//! Host-side single step (issue #12): run the instruction at PC (and, for a
//! branch or jump, its delay slot) on the host against the halted register
//! file, with loads and stores done through READ_MEM / WRITE_MEM, instead of
//! planting a break, CONTinuing and waiting for the stop.
//!
//! [`step`] either completes the step and updates the registers, or says why
//! it cannot, before touching anything; the caller then steps for real. What
//! is simulated:
//!
//! - ALU, shifts, lui, slt*, mult/multu/div/divu (division by zero and
//!   0x80000000 / -1 give what the R3000A gives: see [`div`]), mfhi/mflo,
//!   mthi/mtlo; add/addi/sub only when they do not overflow.
//! - Branches and jumps with their delay slot, as the real stepper steps
//!   them: the condition and jump register are read before the slot runs,
//!   the link is written before it.
//! - lb/lbu/lh/lhu/lw/lwl/lwr and sb/sh/sw/swl/swr, aligned, to RAM (the
//!   first 2 MiB, any segment), scratchpad (kuseg/kseg0), and loads from
//!   the BIOS ROM.
//!
//! Everything else falls back: coprocessor instructions (cop0, cop2 and
//! their loads/stores), syscall, break, reserved encodings and encodings
//! with nonzero must-be-zero fields, overflowing add/addi/sub, unaligned
//! accesses, any access outside the regions above (I/O, EXP1/2, RAM
//! mirrors past 2 MiB, kseg2, kuseg above 0x20000000), a successor PC
//! outside RAM or BIOS, an access that meets the armed watch, an exec
//! breakpoint on an instruction the step runs, SR with IsC, SwC, RE, KUc or KUp
//! set, a branch in a delay slot, a delay slot that reads or writes the
//! register its branch links, jalr with rd = rs, and bltzal/bgezal on r31.
//!
//! Load delay: a real step ends at the step `break`, an exception, and the
//! load in flight completes before it, so after a real step the loaded
//! register already holds its new value. No instruction runs after a load
//! within one step (a load is never a branch), so a load's result is written
//! at the end of the step here too. Either way, an instruction right after a
//! load sees the new value when stepped and the old one when run freely.

use crate::proto::{NUM_REGS, REG_HI, REG_LO, REG_PC, REG_SR};

pub type Regs = [u32; NUM_REGS];

/// Target memory, as the monitor reaches it. Only called for addresses
/// [`step`] has checked.
pub trait Bus {
    type Error;
    /// Exactly `len` bytes at `addr`.
    fn read(&mut self, addr: u32, len: u32) -> Result<Vec<u8>, Self::Error>;
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), Self::Error>;
}

/// The data watch, in the debug unit's terms: `len` bytes from `addr`
/// (aligned to `len`), compared without the segment bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchRange {
    pub addr: u32,
    pub len: u32,
    pub read: bool,
    pub write: bool,
}

/// Debug-unit state a simulated step must not go past, since the real one
/// would stop on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Guards {
    /// Exec breakpoint: address and compare mask.
    pub exec: Option<(u32, u32)>,
    pub watch: Option<WatchRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Stepped: the registers hold the result, memory was written.
    Done,
    /// Not simulated, nothing changed; the reason, for logs.
    Fallback(&'static str),
}

/// SR bits under which the host cannot mirror what a load or store does.
/// The saved SR is the one after exception entry pushed the mode stack, so
/// the halted context's own mode is KUp (RFE pops it back into KUc).
const SR_KUC: u32 = 1 << 1;
const SR_KUP: u32 = 1 << 3;
const SR_ISC: u32 = 1 << 16;
const SR_SWC: u32 = 1 << 17;
const SR_RE: u32 = 1 << 25;

const RAM_END: u32 = 0x0020_0000;
const SPAD: u32 = 0x1f80_0000;
const SPAD_END: u32 = 0x1f80_0400;
const BIOS: u32 = 0x1fc0_0000;
const BIOS_END: u32 = 0x1fc8_0000;
const PHYS: u32 = 0x1fff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Load {
    Byte,
    ByteU,
    Half,
    HalfU,
    Word,
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Store {
    Byte,
    Half,
    Word,
    Left,
    Right,
}

/// What one instruction does, decided from the registers before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// Register writes (index, value); HI and LO for mult/div.
    Set([Option<(usize, u32)>; 2]),
    /// Where execution goes after the delay slot, and the link written.
    Branch {
        next: u32,
        link: Option<(usize, u32)>,
    },
    Load {
        kind: Load,
        addr: u32,
        rt: usize,
    },
    Store {
        kind: Store,
        addr: u32,
        value: u32,
    },
}

type Plan = Result<Op, &'static str>;

fn set(i: usize, v: u32) -> Op {
    Op::Set([Some((i, v)), None])
}

fn field(insn: u32, shift: u32) -> usize {
    usize::try_from((insn >> shift) & 31).unwrap_or(0)
}

fn reg(regs: &Regs, i: usize) -> u32 {
    regs.get(i).copied().unwrap_or(0)
}

fn sext16(insn: u32) -> u32 {
    let imm = u16::try_from(insn & 0xffff).unwrap_or(0);
    i32::from(imm.cast_signed()).cast_unsigned()
}

/// DIV as the R3000A computes it: LO, HI. Division by zero gives HI = rs
/// and LO = -1 (rs >= 0) or 1 (rs < 0); 0x80000000 / -1 gives LO =
/// 0x80000000, HI = 0. No exception either way (psx-spx, "CPU Arithmetic
/// Instructions"; PCSX-Redux's interpreter does the same).
pub fn div(rs: u32, rt: u32) -> (u32, u32) {
    let (n, d) = (rs.cast_signed(), rt.cast_signed());
    if d == 0 {
        return (if n < 0 { 1 } else { u32::MAX }, rs);
    }
    match (n.checked_div(d), n.checked_rem(d)) {
        (Some(q), Some(r)) => (q.cast_unsigned(), r.cast_unsigned()),
        // i32::MIN / -1
        _ => (rs, 0),
    }
}

/// DIVU: LO, HI; by zero LO = 0xffffffff, HI = rs.
pub fn divu(rs: u32, rt: u32) -> (u32, u32) {
    match (rs.checked_div(rt), rs.checked_rem(rt)) {
        (Some(q), Some(r)) => (q, r),
        _ => (u32::MAX, rs),
    }
}

fn split64(v: u64) -> (u32, u32) {
    let lo = u32::try_from(v & 0xffff_ffff).unwrap_or(0);
    let hi = u32::try_from(v >> 32).unwrap_or(0);
    (lo, hi)
}

fn hilo(lo: u32, hi: u32) -> Op {
    Op::Set([
        Some((usize::from(REG_LO), lo)),
        Some((usize::from(REG_HI), hi)),
    ])
}

fn special(insn: u32, pc: u32, regs: &Regs) -> Plan {
    let (rs_i, rt_i, rd_i) = (field(insn, 21), field(insn, 16), field(insn, 11));
    let sa = (insn >> 6) & 31;
    let (rs, rt) = (reg(regs, rs_i), reg(regs, rt_i));
    let funct = insn & 0x3f;
    let zero = |ok: bool| {
        if ok {
            Ok(())
        } else {
            Err("nonzero reserved field")
        }
    };
    Ok(match funct {
        0x00 | 0x02 | 0x03 => {
            zero(rs_i == 0)?;
            set(
                rd_i,
                match funct {
                    0x00 => rt.wrapping_shl(sa),
                    0x02 => rt.wrapping_shr(sa),
                    _ => rt.cast_signed().wrapping_shr(sa).cast_unsigned(),
                },
            )
        }
        0x04 | 0x06 | 0x07 => {
            zero(sa == 0)?;
            let s = rs & 31;
            set(
                rd_i,
                match funct {
                    0x04 => rt.wrapping_shl(s),
                    0x06 => rt.wrapping_shr(s),
                    _ => rt.cast_signed().wrapping_shr(s).cast_unsigned(),
                },
            )
        }
        0x08 => {
            zero(rt_i == 0 && rd_i == 0 && sa == 0)?;
            Op::Branch {
                next: rs,
                link: None,
            }
        }
        0x09 => {
            zero(rt_i == 0 && sa == 0)?;
            if rd_i == rs_i {
                return Err("jalr with rd = rs");
            }
            Op::Branch {
                next: rs,
                link: (rd_i != 0).then_some((rd_i, pc.wrapping_add(8))),
            }
        }
        0x0c => return Err("syscall"),
        0x0d => return Err("break"),
        0x10 | 0x12 => {
            zero(rs_i == 0 && rt_i == 0 && sa == 0)?;
            let from = if funct == 0x10 { REG_HI } else { REG_LO };
            set(rd_i, reg(regs, usize::from(from)))
        }
        0x11 | 0x13 => {
            zero(rt_i == 0 && rd_i == 0 && sa == 0)?;
            set(usize::from(if funct == 0x11 { REG_HI } else { REG_LO }), rs)
        }
        0x18..=0x1b => {
            zero(rd_i == 0 && sa == 0)?;
            let (lo, hi) = match funct {
                0x18 => {
                    let p = i64::from(rs.cast_signed()).wrapping_mul(i64::from(rt.cast_signed()));
                    split64(p.cast_unsigned())
                }
                0x19 => split64(u64::from(rs).wrapping_mul(u64::from(rt))),
                0x1a => div(rs, rt),
                _ => divu(rs, rt),
            };
            hilo(lo, hi)
        }
        0x20..=0x27 | 0x2a | 0x2b => {
            zero(sa == 0)?;
            let v = match funct {
                0x20 => rs
                    .cast_signed()
                    .checked_add(rt.cast_signed())
                    .ok_or("add overflows")?
                    .cast_unsigned(),
                0x21 => rs.wrapping_add(rt),
                0x22 => rs
                    .cast_signed()
                    .checked_sub(rt.cast_signed())
                    .ok_or("sub overflows")?
                    .cast_unsigned(),
                0x23 => rs.wrapping_sub(rt),
                0x24 => rs & rt,
                0x25 => rs | rt,
                0x26 => rs ^ rt,
                0x27 => !(rs | rt),
                0x2a => u32::from(rs.cast_signed() < rt.cast_signed()),
                _ => u32::from(rs < rt),
            };
            set(rd_i, v)
        }
        _ => return Err("reserved SPECIAL function"),
    })
}

/// Decode `insn` at `pc` against `regs`, with no side effects.
fn plan(insn: u32, pc: u32, regs: &Regs) -> Plan {
    let op = insn >> 26;
    let (rs_i, rt_i) = (field(insn, 21), field(insn, 16));
    let (rs, rt) = (reg(regs, rs_i), reg(regs, rt_i));
    let imm = insn & 0xffff;
    let simm = sext16(insn);
    let skip = pc.wrapping_add(8);
    let target = pc.wrapping_add(4).wrapping_add(simm.wrapping_shl(2));
    let cond = |taken: bool, link: Option<(usize, u32)>| Op::Branch {
        next: if taken { target } else { skip },
        link,
    };
    let addr = rs.wrapping_add(simm);
    let load = |kind| Op::Load {
        kind,
        addr,
        rt: rt_i,
    };
    let store = |kind| Op::Store {
        kind,
        addr,
        value: rt,
    };
    Ok(match op {
        0 => return special(insn, pc, regs),
        1 => {
            // Only the four defined rt values.
            let link = match rt_i {
                0x00 | 0x01 => None,
                0x10 | 0x11 if rs_i == 31 => return Err("bltzal/bgezal on r31"),
                0x10 | 0x11 => Some((31, skip)),
                _ => return Err("undefined REGIMM rt"),
            };
            let neg = rs.cast_signed() < 0;
            cond(if rt_i & 1 != 0 { !neg } else { neg }, link)
        }
        2 | 3 => Op::Branch {
            next: (pc.wrapping_add(4) & 0xf000_0000) | ((insn & 0x03ff_ffff) << 2),
            link: (op == 3).then_some((31, skip)),
        },
        4 => cond(rs == rt, None),
        5 => cond(rs != rt, None),
        6 | 7 if rt_i != 0 => return Err("nonzero reserved field"),
        6 => cond(rs.cast_signed() <= 0, None),
        7 => cond(rs.cast_signed() > 0, None),
        8 => set(
            rt_i,
            rs.cast_signed()
                .checked_add(simm.cast_signed())
                .ok_or("addi overflows")?
                .cast_unsigned(),
        ),
        9 => set(rt_i, rs.wrapping_add(simm)),
        0x0a => set(rt_i, u32::from(rs.cast_signed() < simm.cast_signed())),
        0x0b => set(rt_i, u32::from(rs < simm)),
        0x0c => set(rt_i, rs & imm),
        0x0d => set(rt_i, rs | imm),
        0x0e => set(rt_i, rs ^ imm),
        0x0f if rs_i != 0 => return Err("nonzero reserved field"),
        0x0f => set(rt_i, imm << 16),
        0x10..=0x13 => return Err("coprocessor instruction"),
        0x20 => load(Load::Byte),
        0x21 => load(Load::Half),
        0x22 => load(Load::Left),
        0x23 => load(Load::Word),
        0x24 => load(Load::ByteU),
        0x25 => load(Load::HalfU),
        0x26 => load(Load::Right),
        0x28 => store(Store::Byte),
        0x29 => store(Store::Half),
        0x2a => store(Store::Left),
        0x2b => store(Store::Word),
        0x2e => store(Store::Right),
        0x30..=0x3b => return Err("coprocessor load/store"),
        _ => return Err("reserved opcode"),
    })
}

/// Whether `addr` is in a segment the PS1 decodes: kuseg's first 512 MiB,
/// kseg0, kseg1.
fn segment_ok(addr: u32) -> bool {
    addr < 0x2000_0000 || (0x8000_0000..0xc000_0000).contains(&addr)
}

/// Whether `len` bytes at `addr` are plain memory the monitor can read (or,
/// with `write`, write) with no side effects.
fn data_ok(addr: u32, len: u32, write: bool) -> bool {
    if !segment_ok(addr) {
        return false;
    }
    let kseg1 = addr >= 0xa000_0000;
    let phys = addr & PHYS;
    let Some(end) = phys.checked_add(len) else {
        return false;
    };
    end <= RAM_END
        || (!kseg1 && phys >= SPAD && end <= SPAD_END)
        || (!write && phys >= BIOS && end <= BIOS_END)
}

/// Whether the CPU can fetch an instruction at `pc` from RAM or BIOS.
fn fetch_ok(pc: u32) -> bool {
    if pc & 3 != 0 || !segment_ok(pc) {
        return false;
    }
    let phys = pc & PHYS;
    phys < RAM_END || (BIOS..BIOS_END).contains(&phys)
}

fn exec_hit(g: &Guards, pc: u32) -> bool {
    g.exec.is_some_and(|(a, m)| (a ^ pc) & m == 0)
}

fn watch_hit(g: &Guards, addr: u32, len: u32, write: bool) -> bool {
    g.watch.is_some_and(|w| {
        if !(if write { w.write } else { w.read }) {
            return false;
        }
        let (a, wa) = (u64::from(addr & PHYS), u64::from(w.addr & PHYS));
        a < wa.saturating_add(u64::from(w.len)) && wa < a.saturating_add(u64::from(len))
    })
}

/// The bytes a memory op touches: address, length, whether written.
fn access(op: &Op) -> Option<(u32, u32, bool)> {
    match *op {
        Op::Load { kind, addr, .. } => Some(match kind {
            Load::Byte | Load::ByteU => (addr, 1, false),
            Load::Half | Load::HalfU => (addr, 2, false),
            Load::Word => (addr, 4, false),
            Load::Left | Load::Right => (addr & !3, 4, false),
        }),
        Op::Store { kind, addr, .. } => {
            let s = addr & 3;
            Some(match kind {
                Store::Byte => (addr, 1, true),
                Store::Half => (addr, 2, true),
                Store::Word => (addr, 4, true),
                Store::Left => (addr & !3, s.wrapping_add(1), true),
                Store::Right => (addr, 4u32.wrapping_sub(s), true),
            })
        }
        Op::Set(_) | Op::Branch { .. } => None,
    }
}

fn check_access(op: &Op, g: &Guards) -> Result<(), &'static str> {
    let Some((addr, len, write)) = access(op) else {
        return Ok(());
    };
    let align = match *op {
        Op::Load {
            kind: Load::Half | Load::HalfU,
            ..
        }
        | Op::Store {
            kind: Store::Half, ..
        } => 1,
        Op::Load {
            kind: Load::Word, ..
        }
        | Op::Store {
            kind: Store::Word, ..
        } => 3,
        _ => 0,
    };
    if addr & align != 0 {
        return Err("unaligned access");
    }
    if !data_ok(addr, len, write) {
        return Err("access outside RAM, scratchpad and BIOS");
    }
    if watch_hit(g, addr, len, write) {
        return Err("access meets the watch");
    }
    Ok(())
}

fn writes(op: &Op, i: usize) -> bool {
    match *op {
        Op::Set(w) => w.iter().flatten().any(|&(r, _)| r == i),
        Op::Load { rt, .. } => rt == i,
        Op::Branch { link, .. } => link.is_some_and(|(r, _)| r == i),
        Op::Store { .. } => false,
    }
}

fn put(regs: &mut Regs, i: usize, v: u32) {
    if i != 0
        && let Some(slot) = regs.get_mut(i)
    {
        *slot = v;
    }
}

/// A step that has passed every check: the link to write (for a branch),
/// the one instruction with effects, and the PC after.
struct Ready {
    link: Option<(usize, u32)>,
    op: Op,
    next: u32,
}

fn prepare(regs: &Regs, g: &Guards, words: &[u32]) -> Result<Ready, &'static str> {
    let pc = reg(regs, usize::from(REG_PC));
    let insn = words.first().copied().ok_or("no instruction")?;
    let op = plan(insn, pc, regs)?;
    let Op::Branch { next, link } = op else {
        let next = pc.wrapping_add(4);
        if !fetch_ok(next) {
            return Err("next PC outside RAM and BIOS");
        }
        check_access(&op, g)?;
        return Ok(Ready {
            link: None,
            op,
            next,
        });
    };
    let slot_pc = pc.wrapping_add(4);
    let slot = words.get(1).copied().ok_or("delay slot not fetchable")?;
    if exec_hit(g, slot_pc) {
        return Err("exec breakpoint on the delay slot");
    }
    let mut linked = *regs;
    if let Some((i, v)) = link {
        put(&mut linked, i, v);
    }
    let slot_op = plan(slot, slot_pc, &linked)?;
    if matches!(slot_op, Op::Branch { .. }) {
        return Err("branch in a delay slot");
    }
    if let Some((i, _)) = link.filter(|&(i, _)| i != 0) {
        // The pipeline decides these; leave them to the CPU.
        if writes(&slot_op, i) {
            return Err("delay slot writes the link register");
        }
        // (lwl/lwr merge into rt, but a load into the link register is
        // caught above.)
        if plan(slot, slot_pc, regs)? != slot_op {
            return Err("delay slot reads the link register");
        }
    }
    if !fetch_ok(next) {
        return Err("branch target outside RAM and BIOS");
    }
    check_access(&slot_op, g)?;
    Ok(Ready {
        link,
        op: slot_op,
        next,
    })
}

fn word(b: &[u8]) -> u32 {
    let mut w = [0u8; 4];
    for (d, s) in w.iter_mut().zip(b) {
        *d = *s;
    }
    u32::from_le_bytes(w)
}

fn commit<B: Bus>(r: &Ready, regs: &mut Regs, bus: &mut B) -> Result<(), B::Error> {
    if let Some((i, v)) = r.link {
        put(regs, i, v);
    }
    match r.op {
        Op::Set(w) => {
            for &(i, v) in w.iter().flatten() {
                put(regs, i, v);
            }
        }
        Op::Branch { .. } => {}
        Op::Load { kind, addr, rt } => {
            let old = reg(regs, rt);
            let v = match kind {
                Load::Byte | Load::ByteU => {
                    let b = bus.read(addr, 1)?.first().copied().unwrap_or(0);
                    if kind == Load::Byte {
                        i32::from(b.cast_signed()).cast_unsigned()
                    } else {
                        u32::from(b)
                    }
                }
                Load::Half | Load::HalfU => {
                    let h = u16::try_from(word(&bus.read(addr, 2)?) & 0xffff).unwrap_or(0);
                    if kind == Load::Half {
                        i32::from(h.cast_signed()).cast_unsigned()
                    } else {
                        u32::from(h)
                    }
                }
                Load::Word => word(&bus.read(addr, 4)?),
                Load::Left | Load::Right => {
                    let m = word(&bus.read(addr & !3, 4)?);
                    let sh = (addr & 3).wrapping_mul(8);
                    if kind == Load::Left {
                        // Byte `addr` into bits 31:24, the ones below it after.
                        let keep = 0x00ff_ffffu32.wrapping_shr(sh);
                        (old & keep) | m.wrapping_shl(24u32.wrapping_sub(sh))
                    } else {
                        let keep = if sh == 0 {
                            0
                        } else {
                            0xffff_ff00u32.wrapping_shl(24u32.wrapping_sub(sh))
                        };
                        (old & keep) | m.wrapping_shr(sh)
                    }
                }
            };
            put(regs, rt, v);
        }
        Op::Store { kind, addr, value } => {
            let b = value.to_le_bytes();
            let s = usize::try_from(addr & 3).unwrap_or(0);
            match kind {
                Store::Byte => bus.write(addr, b.get(..1).unwrap_or_default())?,
                Store::Half => bus.write(addr, b.get(..2).unwrap_or_default())?,
                Store::Word => bus.write(addr, &b)?,
                Store::Left => {
                    // The top s + 1 bytes of rt, into the word's bytes 0..=s.
                    let sh = u32::try_from(s).unwrap_or(0).wrapping_mul(8);
                    let v = value.wrapping_shr(24u32.wrapping_sub(sh)).to_le_bytes();
                    bus.write(addr & !3, v.get(..=s).unwrap_or_default())?;
                }
                Store::Right => {
                    // The low 4 - s bytes of rt, into bytes s..=3.
                    bus.write(addr, b.get(..4usize.saturating_sub(s)).unwrap_or_default())?;
                }
            }
        }
    }
    Ok(())
}

/// Step once: the instruction at PC, and its delay slot if it is a branch or
/// jump. Returns [`Outcome::Fallback`] with `regs` and memory untouched when
/// the step must be left to the CPU; errors only from `bus`.
pub fn step<B: Bus>(regs: &mut Regs, g: &Guards, bus: &mut B) -> Result<Outcome, B::Error> {
    let sr = reg(regs, usize::from(REG_SR));
    if sr & (SR_ISC | SR_SWC) != 0 {
        return Ok(Outcome::Fallback("cache isolated or swapped (SR IsC/SwC)"));
    }
    if sr & (SR_KUC | SR_KUP | SR_RE) != 0 {
        return Ok(Outcome::Fallback("user mode or reverse endian"));
    }
    let pc = reg(regs, usize::from(REG_PC));
    if !fetch_ok(pc) {
        return Ok(Outcome::Fallback("PC outside RAM and BIOS"));
    }
    if exec_hit(g, pc) {
        return Ok(Outcome::Fallback("exec breakpoint on PC"));
    }
    let slot = pc.wrapping_add(4);
    let len = if fetch_ok(slot) { 8 } else { 4 };
    let bytes = bus.read(pc, len)?;
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    let ready = match prepare(regs, g, &words) {
        Ok(r) => r,
        Err(why) => return Ok(Outcome::Fallback(why)),
    };
    let mut new = *regs;
    commit(&ready, &mut new, bus)?;
    put(&mut new, usize::from(REG_PC), ready.next);
    if let Some(r0) = new.first_mut() {
        *r0 = 0;
    }
    *regs = new;
    Ok(Outcome::Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn division_edges() {
        assert_eq!(div(7, 0), (u32::MAX, 7));
        assert_eq!(div(0, 0), (u32::MAX, 0));
        assert_eq!(div(0xffff_fff9, 0), (1, 0xffff_fff9));
        assert_eq!(div(0x8000_0000, u32::MAX), (0x8000_0000, 0));
        assert_eq!(div(0xffff_fff9, 2), (0xffff_fffd, u32::MAX)); // -7/2 = -3 r -1
        assert_eq!(divu(7, 0), (u32::MAX, 7));
        assert_eq!(divu(0xffff_fff9, 2), (0x7fff_fffc, 1));
    }

    #[test]
    fn regions() {
        assert!(data_ok(0x8000_0000, 4, true));
        assert!(data_ok(0xa01f_fffc, 4, true));
        assert!(!data_ok(0x801f_fffe, 4, false));
        assert!(!data_ok(0x8020_0000, 4, false), "mirror past 2 MiB");
        assert!(data_ok(0x1f80_03fc, 4, true));
        assert!(data_ok(0x9f80_0000, 4, true));
        assert!(!data_ok(0xbf80_0000, 4, false), "no uncached scratchpad");
        assert!(!data_ok(0x1f80_1070, 4, false), "I/O");
        assert!(data_ok(0xbfc0_0000, 4, false));
        assert!(!data_ok(0xbfc0_0000, 4, true), "no BIOS writes");
        assert!(!data_ok(0x1f00_0000, 4, false), "EXP1");
        assert!(!data_ok(0x2000_0000, 4, false));
        assert!(!data_ok(0xfffe_0130, 4, false));
        assert!(fetch_ok(0x8001_0000) && fetch_ok(0xbfc0_0180));
        assert!(!fetch_ok(0x8001_0002) && !fetch_ok(0x1f00_0000) && !fetch_ok(0x1f80_0000));
    }
}
