//! What the host needs to know about R3000 code and the PS1 address map to
//! debug through the monitor: where an instruction goes next (for host-side
//! single stepping) and which addresses are RAM, ROM, or nothing.

use crate::proto::NUM_REGS;

/// Where execution can go after the instruction at `pc` (and, for a branch
/// or jump, its delay slot) has run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Exactly one successor.
    One(u32),
    /// A coprocessor branch (BCzF / BCzT): the condition flag is not
    /// visible to the host, so it is either `taken` or `fallthrough`.
    Either { taken: u32, fallthrough: u32 },
}

impl Next {
    pub fn addrs(self) -> Vec<u32> {
        match self {
            Next::One(a) => vec![a],
            Next::Either { taken, fallthrough } if taken == fallthrough => vec![taken],
            Next::Either { taken, fallthrough } => vec![taken, fallthrough],
        }
    }
}

fn field(insn: u32, shift: u32, bits: u32) -> u32 {
    (insn >> shift) & ((1u32 << bits).wrapping_sub(1))
}

fn reg(regs: &[u32; NUM_REGS], index: u32) -> u32 {
    usize::try_from(index)
        .ok()
        .and_then(|i| regs.get(i))
        .copied()
        .unwrap_or(0)
}

/// PC-relative branch target: the delay slot's address plus the offset.
fn branch_target(pc: u32, insn: u32) -> u32 {
    let imm = u16::try_from(insn & 0xffff).unwrap_or(0);
    let off = i32::from(imm.cast_signed()).wrapping_mul(4);
    pc.wrapping_add(4).wrapping_add_signed(off)
}

/// The next PC after `insn` at `pc` executes, from the registers as they are
/// before it runs. A branch or jump runs its delay slot at `pc + 4`, then
/// goes to the target or, not taken, to `pc + 8`. The branch condition and a
/// jump register are read before the delay slot runs, as the CPU does.
pub fn next_pc(pc: u32, insn: u32, regs: &[u32; NUM_REGS]) -> Next {
    let op = insn >> 26;
    let rs = reg(regs, field(insn, 21, 5));
    let rt_index = field(insn, 16, 5);
    let rt = reg(regs, rt_index);
    let seq = pc.wrapping_add(4);
    let skip = pc.wrapping_add(8);
    let cond = |taken: bool| Next::One(if taken { branch_target(pc, insn) } else { skip });
    match op {
        0 => match insn & 0x3f {
            // jr, jalr
            0x08 | 0x09 => Next::One(rs),
            _ => Next::One(seq),
        },
        // REGIMM: bltz, bgez, bltzal, bgezal. The R3000 decodes only bit 0
        // (greater-or-equal) and bit 4 (link) of rt, and links whether or not
        // the branch is taken.
        1 => {
            let negative = rs.cast_signed() < 0;
            cond(if rt_index & 1 != 0 {
                !negative
            } else {
                negative
            })
        }
        // j, jal
        2 | 3 => Next::One((seq & 0xf000_0000) | ((insn & 0x03ff_ffff) << 2)),
        4 => cond(rs == rt),
        5 => cond(rs != rt),
        6 => cond(rs.cast_signed() <= 0),
        7 => cond(rs.cast_signed() > 0),
        // COPz with rs = BC: bczf / bczt.
        0x10..=0x13 if field(insn, 21, 5) == 8 => Next::Either {
            taken: branch_target(pc, insn),
            fallthrough: skip,
        },
        _ => Next::One(seq),
    }
}

/// Whether `insn` is a branch or jump, i.e. has a delay slot.
pub fn has_delay_slot(insn: u32) -> bool {
    let op = insn >> 26;
    match op {
        0 => matches!(insn & 0x3f, 0x08 | 0x09),
        1..=7 => true,
        0x10..=0x13 => field(insn, 21, 5) == 8,
        _ => false,
    }
}

/// gdb's names for r0-r31.
pub const REG_NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp",
    "ra",
];

fn rname(index: u32) -> &'static str {
    usize::try_from(index)
        .ok()
        .and_then(|i| REG_NAMES.get(i))
        .copied()
        .unwrap_or("?")
}

fn simm(insn: u32) -> i32 {
    i32::from(u16::try_from(insn & 0xffff).unwrap_or(0).cast_signed())
}

/// The R3000 instruction `insn` at `pc` in objdump's style (`lw v0,4(a0)`),
/// or `.word 0x...` for a word that is not one.
pub fn disasm(pc: u32, insn: u32) -> String {
    let op = insn >> 26;
    let rs = rname(field(insn, 21, 5));
    let rt = rname(field(insn, 16, 5));
    let rd = rname(field(insn, 11, 5));
    let sa = field(insn, 6, 5);
    let imm = simm(insn);
    let uimm = insn & 0xffff;
    let target = branch_target(pc, insn);
    let word = format!(".word 0x{insn:08x}");
    let mem = |name: &str| format!("{name:<7} {rt},{imm}({rs})");
    match op {
        0 => {
            let three = |name: &str| format!("{name:<7} {rd},{rs},{rt}");
            match insn & 0x3f {
                0x00 if insn == 0 => "nop".into(),
                0x00 => format!("sll     {rd},{rt},0x{sa:x}"),
                0x02 => format!("srl     {rd},{rt},0x{sa:x}"),
                0x03 => format!("sra     {rd},{rt},0x{sa:x}"),
                0x04 => format!("sllv    {rd},{rt},{rs}"),
                0x06 => format!("srlv    {rd},{rt},{rs}"),
                0x07 => format!("srav    {rd},{rt},{rs}"),
                0x08 => format!("jr      {rs}"),
                0x09 if field(insn, 11, 5) == 31 => format!("jalr    {rs}"),
                0x09 => format!("jalr    {rd},{rs}"),
                0x0c if field(insn, 6, 20) == 0 => "syscall".into(),
                0x0c => format!("syscall 0x{:x}", field(insn, 6, 20)),
                0x0d => format!(
                    "break   0x{:x},0x{:x}",
                    field(insn, 16, 10),
                    field(insn, 6, 10)
                ),
                0x10 => format!("mfhi    {rd}"),
                0x11 => format!("mthi    {rs}"),
                0x12 => format!("mflo    {rd}"),
                0x13 => format!("mtlo    {rs}"),
                0x18 => format!("mult    {rs},{rt}"),
                0x19 => format!("multu   {rs},{rt}"),
                0x1a => format!("div     {rs},{rt}"),
                0x1b => format!("divu    {rs},{rt}"),
                0x20 => three("add"),
                0x21 if field(insn, 16, 5) == 0 => format!("move    {rd},{rs}"),
                0x21 => three("addu"),
                0x22 => three("sub"),
                0x23 => three("subu"),
                0x24 => three("and"),
                0x25 => three("or"),
                0x26 => three("xor"),
                0x27 => three("nor"),
                0x2a => three("slt"),
                0x2b => three("sltu"),
                _ => word,
            }
        }
        // The R3000 decodes only bits 0 and 4 of rt (see next_pc).
        1 => {
            let name = match field(insn, 16, 5) & 0x11 {
                0x00 => "bltz",
                0x01 => "bgez",
                0x10 => "bltzal",
                _ => "bgezal",
            };
            format!("{name:<7} {rs},0x{target:08x}")
        }
        2 | 3 => {
            let to = (pc.wrapping_add(4) & 0xf000_0000) | ((insn & 0x03ff_ffff) << 2);
            format!("{:<7} 0x{to:08x}", if op == 2 { "j" } else { "jal" })
        }
        4 if field(insn, 16, 5) == 0 && field(insn, 21, 5) == 0 => {
            format!("b       0x{target:08x}")
        }
        4 if field(insn, 16, 5) == 0 => format!("beqz    {rs},0x{target:08x}"),
        4 => format!("beq     {rs},{rt},0x{target:08x}"),
        5 if field(insn, 16, 5) == 0 => format!("bnez    {rs},0x{target:08x}"),
        5 => format!("bne     {rs},{rt},0x{target:08x}"),
        6 => format!("blez    {rs},0x{target:08x}"),
        7 => format!("bgtz    {rs},0x{target:08x}"),
        8 => format!("addi    {rt},{rs},{imm}"),
        9 if field(insn, 21, 5) == 0 => format!("li      {rt},{imm}"),
        9 => format!("addiu   {rt},{rs},{imm}"),
        0x0a => format!("slti    {rt},{rs},{imm}"),
        0x0b => format!("sltiu   {rt},{rs},{imm}"),
        0x0c => format!("andi    {rt},{rs},0x{uimm:x}"),
        0x0d => format!("ori     {rt},{rs},0x{uimm:x}"),
        0x0e => format!("xori    {rt},{rs},0x{uimm:x}"),
        0x0f => format!("lui     {rt},0x{uimm:x}"),
        0x10..=0x13 => {
            let z = op & 3;
            let creg = field(insn, 11, 5);
            match field(insn, 21, 5) {
                0 => format!("mfc{z}    {rt},${creg}"),
                2 => format!("cfc{z}    {rt},${creg}"),
                4 => format!("mtc{z}    {rt},${creg}"),
                6 => format!("ctc{z}    {rt},${creg}"),
                8 => {
                    let tf = if field(insn, 16, 1) == 1 { 't' } else { 'f' };
                    format!("bc{z}{tf}    0x{target:08x}")
                }
                r if r & 0x10 != 0 && z == 0 && insn & 0x3f == 0x10 => "rfe".into(),
                r if r & 0x10 != 0 => format!("cop{z}    0x{:x}", insn & 0x01ff_ffff),
                _ => word,
            }
        }
        0x20 => mem("lb"),
        0x21 => mem("lh"),
        0x22 => mem("lwl"),
        0x23 => mem("lw"),
        0x24 => mem("lbu"),
        0x25 => mem("lhu"),
        0x26 => mem("lwr"),
        0x28 => mem("sb"),
        0x29 => mem("sh"),
        0x2a => mem("swl"),
        0x2b => mem("sw"),
        0x2e => mem("swr"),
        0x30..=0x33 => format!("lwc{}    ${},{imm}({rs})", op & 3, field(insn, 16, 5)),
        0x38..=0x3b => format!("swc{}    ${},{imm}({rs})", op & 3, field(insn, 16, 5)),
        _ => word,
    }
}

/// A load or store: its effective address, width in bytes, and whether it
/// stores. lwl/lwr/swl/swr count as 4-byte accesses at the unaligned address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub addr: u32,
    pub size: u32,
    pub store: bool,
}

/// The memory access `insn` makes with the registers as they were before it
/// ran, if it is a load or store.
pub fn mem_access(insn: u32, regs: &[u32; NUM_REGS]) -> Option<Access> {
    let op = insn >> 26;
    let (size, store) = match op {
        0x20 | 0x24 => (1, false),
        0x21 | 0x25 => (2, false),
        0x22 | 0x23 | 0x26 | 0x30..=0x33 => (4, false),
        0x28 => (1, true),
        0x29 => (2, true),
        0x2a | 0x2b | 0x2e | 0x38..=0x3b => (4, true),
        _ => return None,
    };
    let addr = reg(regs, field(insn, 21, 5)).wrapping_add_signed(simm(insn));
    Some(Access { addr, size, store })
}

/// Kind of memory at an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Main RAM (2 MiB mirrored over 8 MiB), scratchpad, I/O ports.
    Ram,
    /// BIOS ROM or the EXP1 expansion region (where a monitor cart lives).
    Rom,
}

const MIB: u32 = 1 << 20;

/// Physical ranges (start, length, kind, reachable through kseg1).
const MAP: [(u32, u32, Region, bool); 5] = [
    (0x0000_0000, 8 * MIB, Region::Ram, true),
    (0x1f00_0000, 8 * MIB, Region::Rom, true),
    // Scratchpad is not reachable uncached.
    (0x1f80_0000, 0x400, Region::Ram, false),
    (0x1f80_1000, 0x2000, Region::Ram, true),
    (0x1fc0_0000, 512 * 1024, Region::Rom, true),
];

/// Segment bases the map is mirrored at: kuseg, kseg0, kseg1.
const SEGMENTS: [u32; 3] = [0x0000_0000, 0x8000_0000, 0xa000_0000];

/// The region `addr` falls in and the bytes left in it from `addr`, or None
/// if nothing is there (kseg2, unmapped holes).
pub fn region(addr: u32) -> Option<(Region, u32)> {
    if addr >= 0xc000_0000 {
        return None;
    }
    let kseg1 = addr >= 0xa000_0000;
    let phys = addr & 0x1fff_ffff;
    MAP.iter().find_map(|&(start, len, kind, uncached)| {
        let off = phys.checked_sub(start)?;
        (off < len && (uncached || !kseg1)).then(|| (kind, len.saturating_sub(off)))
    })
}

/// Whether the monitor can READ_MEM `len` bytes at `addr` without side
/// effects: memory (RAM, scratchpad, ROM, EXP1), not the I/O ports, and not
/// an unmapped address, where the read would fault inside the monitor.
pub fn safe_to_read(addr: u32, len: u32) -> bool {
    let io = (0x1f80_1000..0x1f80_3000).contains(&(addr & 0x1fff_ffff));
    !io && region(addr).is_some_and(|(_, left)| len <= left)
}

pub fn is_rom(addr: u32) -> bool {
    matches!(region(addr), Some((Region::Rom, _)))
}

/// A gdb memory map (qXfer:memory-map:read) of the regions above. Marking
/// the ROMs read-only makes gdb use a hardware breakpoint (Z1) for `break`
/// there, and makes it refuse accesses outside the map.
pub fn memory_map_xml() -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE memory-map PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\" \"http://sourceware.org/gdb/gdb-memory-map.dtd\">\n<memory-map>\n",
    );
    for seg in SEGMENTS {
        for (start, len, kind, uncached) in MAP {
            if seg == 0xa000_0000 && !uncached {
                continue;
            }
            let ty = match kind {
                Region::Ram => "ram",
                Region::Rom => "rom",
            };
            let addr = seg | start;
            xml.push_str(&format!(
                "  <memory type=\"{ty}\" start=\"0x{addr:08x}\" length=\"0x{len:x}\"/>\n"
            ));
            // gdb holds 32-bit MIPS addresses sign-extended to 64 bits, so
            // kseg0/kseg1 are also given as 0xffffffff8.../0xffffffffa....
            if addr >= 0x8000_0000 {
                xml.push_str(&format!(
                    "  <memory type=\"{ty}\" start=\"0xffffffff{addr:08x}\" length=\"0x{len:x}\"/>\n"
                ));
            }
        }
    }
    xml.push_str("</memory-map>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs(set: &[(usize, u32)]) -> [u32; NUM_REGS] {
        let mut r = [0u32; NUM_REGS];
        for &(i, v) in set {
            r[i] = v;
        }
        r
    }

    const PC: u32 = 0x8001_0010;

    #[test]
    fn sequential_and_jumps() {
        let r = regs(&[(8, 0x8002_0000), (31, 0x8001_0040)]);
        assert_eq!(next_pc(PC, 0x2409_0005, &r), Next::One(PC + 4)); // addiu
        assert_eq!(next_pc(PC, 0x0100_0008, &r), Next::One(0x8002_0000)); // jr t0
        assert_eq!(next_pc(PC, 0x03e0_0008, &r), Next::One(0x8001_0040)); // jr ra
        assert_eq!(next_pc(PC, 0x0100_f809, &r), Next::One(0x8002_0000)); // jalr t0
        // j 0x80010100 / jal 0x80010100
        assert_eq!(next_pc(PC, 0x0800_4040, &r), Next::One(0x8001_0100));
        assert_eq!(next_pc(PC, 0x0c00_4040, &r), Next::One(0x8001_0100));
        assert!(has_delay_slot(0x0c00_4040) && !has_delay_slot(0x2409_0005));
    }

    #[test]
    fn conditional_branches() {
        let r = regs(&[(9, 5), (10, 5), (11, 0xffff_fffe)]);
        let back = PC.wrapping_add(4).wrapping_sub(8);
        let fwd = PC + 4 + 0x10;
        // beq t1, t2, +4 words: taken
        assert_eq!(next_pc(PC, 0x112a_0004, &r), Next::One(fwd));
        // bne t1, t2, +4: not taken
        assert_eq!(next_pc(PC, 0x152a_0004, &r), Next::One(PC + 8));
        // beq t1, zero, -2 words: not taken; bne t1, zero, -2: taken
        assert_eq!(next_pc(PC, 0x1120_fffe, &r), Next::One(PC + 8));
        assert_eq!(next_pc(PC, 0x1520_fffe, &r), Next::One(back));
        // blez / bgtz on t3 = -2 and t1 = 5
        assert_eq!(next_pc(PC, 0x1960_0004, &r), Next::One(fwd));
        assert_eq!(next_pc(PC, 0x1d60_0004, &r), Next::One(PC + 8));
        assert_eq!(next_pc(PC, 0x1d20_0004, &r), Next::One(fwd));
        // bltz / bgez / bltzal / bgezal on t3 = -2
        assert_eq!(next_pc(PC, 0x0560_0004, &r), Next::One(fwd));
        assert_eq!(next_pc(PC, 0x0561_0004, &r), Next::One(PC + 8));
        assert_eq!(next_pc(PC, 0x0570_0004, &r), Next::One(fwd));
        assert_eq!(next_pc(PC, 0x0571_0004, &r), Next::One(PC + 8));
        // bc2t: either way
        assert_eq!(next_pc(PC, 0x4901_0004, &r).addrs(), vec![fwd, PC + 8]);
    }

    /// Expected text from `mipsel-none-elf-objdump -b binary -m mips:3000
    /// -EL -D` (whitespace folded), with branch targets as they are for an
    /// instruction at 0x80020000. Where the text differs, objdump's is noted.
    #[test]
    fn disasm_matches_objdump() {
        let cases: [(u32, &str); 22] = [
            (0x0000_0000, "nop"),
            (0x0004_1080, "sll v0,a0,0x2"),
            (0x0320_f809, "jalr t9"),
            (0x0320_1009, "jalr v0,t9"),
            (0x0000_000c, "syscall"),
            (0x0004_004d, "break 0x4,0x1"),
            (0x0080_1021, "move v0,a0"),
            (0x0085_102b, "sltu v0,a0,a1"),
            (0x0491_fffe, "bgezal a0,0x8001fffc"),
            (0x0c00_4040, "jal 0x80010100"),
            (0x1000_fffe, "b 0x8001fffc"),
            (0x1085_fffe, "beq a0,a1,0x8001fffc"),
            (0x1480_fffe, "bnez a0,0x8001fffc"),
            (0x2402_fff0, "li v0,-16"),
            (0x3082_ff00, "andi v0,a0,0xff00"),
            (0x3c02_dead, "lui v0,0xdead"),
            (0x4200_0010, "rfe"),
            (0x4a18_0001, "cop2 0x180001"), // objdump: c2 0x180001
            (0x4882_4800, "mtc2 v0,$9"),
            (0x8c82_fffc, "lw v0,-4(a0)"),
            (0xb882_fffc, "swr v0,-4(a0)"),
            (0xc882_0004, "lwc2 $2,4(a0)"),
        ];
        for (w, want) in cases {
            let text = disasm(0x8002_0000, w);
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert_eq!(text, want, "word {w:08x}");
        }
        // Not R3000 instructions.
        assert_eq!(disasm(PC, 0xfc00_0000), ".word 0xfc000000");
        assert_eq!(disasm(PC, 0x0000_0001), ".word 0x00000001");
    }

    #[test]
    fn memory_access_of_loads_and_stores() {
        let r = regs(&[(4, 0x8010_0000)]);
        let acc = |w| mem_access(w, &r);
        assert_eq!(
            acc(0x8c88_0001),
            Some(Access {
                addr: 0x8010_0001,
                size: 4,
                store: false
            })
        );
        assert_eq!(
            acc(0xa488_fffe),
            Some(Access {
                addr: 0x800f_fffe,
                size: 2,
                store: true
            })
        );
        assert_eq!(acc(0x2082_0001), None);
        assert!(safe_to_read(0x8001_0000, 8) && safe_to_read(0xbfc0_0000, 4));
        assert!(!safe_to_read(0x1f80_1810, 4) && !safe_to_read(0x1fa0_0000, 4));
        assert!(!safe_to_read(0x807f_fffc, 8));
    }

    #[test]
    fn address_map() {
        assert_eq!(region(0x8001_0000), Some((Region::Ram, 8 * MIB - 0x1_0000)));
        assert_eq!(region(0xbfc0_0180).map(|r| r.0), Some(Region::Rom));
        assert_eq!(region(0x1f00_0000).map(|r| r.0), Some(Region::Rom));
        assert_eq!(region(0x9f80_0000).map(|r| r.0), Some(Region::Ram));
        assert_eq!(region(0xbf80_0000), None);
        assert_eq!(region(0x1fa0_0000), None);
        assert_eq!(region(0xfffe_0130), None);
        assert!(is_rom(0x9fc0_0000) && !is_rom(0x8000_0000));
        assert!(memory_map_xml().contains("start=\"0xbfc00000\" length=\"0x80000\""));
    }
}
