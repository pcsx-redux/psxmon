//! `psxmon::stepsim` against the test interpreter (tests/session/sim.rs),
//! step by step: every simulated step must leave the same registers (all
//! 38, HI/LO included) and RAM as the interpreter's step, and every step the
//! simulator leaves to the target must be one it is expected to.
#![cfg(test)]

#[allow(dead_code)]
#[path = "session/sim.rs"]
mod sim;

use std::convert::Infallible;

use psxmon::proto::*;
use psxmon::stepsim::{self, Bus, Guards, Outcome, WatchRange};
use sim::{DebugUnit, Interp, Machine, RAM_SIZE, ROM_BASE, RUN_SR};

// ---- encodings ----

const ZERO: u32 = 0;
const AT: u32 = 1;
const V0: u32 = 2;
const V1: u32 = 3;
const A0: u32 = 4;
const A1: u32 = 5;
const T0: u32 = 8;
const T1: u32 = 9;
const T2: u32 = 10;
const T3: u32 = 11;
const T4: u32 = 12;
const S0: u32 = 16;
const S1: u32 = 17;
const RA: u32 = 31;

fn i(op: u32, rs: u32, rt: u32, imm: i32) -> u32 {
    (op << 26) | (rs << 21) | (rt << 16) | (imm.cast_unsigned() & 0xffff)
}
fn r(funct: u32, rs: u32, rt: u32, rd: u32, sa: u32) -> u32 {
    (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct
}
fn j(op: u32, target: u32) -> u32 {
    (op << 26) | ((target >> 2) & 0x03ff_ffff)
}
fn regimm(rt: u32, rs: u32, words: i32) -> u32 {
    i(1, rs, rt, words)
}
fn addiu(rt: u32, rs: u32, imm: i32) -> u32 {
    i(9, rs, rt, imm)
}
fn lui(rt: u32, imm: u32) -> u32 {
    i(0xf, 0, rt, i32::try_from(imm).expect("16 bits"))
}
fn ori(rt: u32, rs: u32, imm: u32) -> u32 {
    i(0xd, rs, rt, i32::try_from(imm).expect("16 bits"))
}
fn mem(op: u32, rt: u32, off: i32, base: u32) -> u32 {
    i(op, base, rt, off)
}
const NOP: u32 = 0;
const LB: u32 = 0x20;
const LH: u32 = 0x21;
const LWL: u32 = 0x22;
const LW: u32 = 0x23;
const LBU: u32 = 0x24;
const LHU: u32 = 0x25;
const LWR: u32 = 0x26;
const SB: u32 = 0x28;
const SH: u32 = 0x29;
const SWL: u32 = 0x2a;
const SW: u32 = 0x2b;
const SWR: u32 = 0x2e;

const BASE: u32 = 0x8001_0000;
const DATA: u32 = 0x8002_0000;

// ---- harness ----

struct MachineBus<'a>(&'a mut Machine);

impl Bus for MachineBus<'_> {
    type Error = Infallible;
    fn read(&mut self, addr: u32, len: u32) -> Result<Vec<u8>, Infallible> {
        Ok(self.0.read(addr, usize::try_from(len).expect("len")))
    }
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), Infallible> {
        self.0.write(addr, data);
        Ok(())
    }
}

fn machine(words: &[u32], regs: &[(u32, u32)], data: &[u8]) -> Machine {
    let mut rom = vec![0u8; 0x200];
    rom[0x100..0x104].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    rom[0x104..0x108].copy_from_slice(&0x03e0_0008u32.to_le_bytes()); // jr ra
    let mut m = Machine {
        ram: vec![0; RAM_SIZE],
        rom,
        regs: [0; NUM_REGS],
        dbg: DebugUnit::default(),
        tty: Vec::new(),
        ram_size_reg: sim::RAM_SIZE_BIOS,
    };
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    m.write(BASE, &code);
    m.write(DATA, data);
    m.set(REG_SR, RUN_SR);
    m.set(REG_PC, BASE);
    for &(i, v) in regs {
        m.set(u16::try_from(i).expect("reg"), v);
    }
    m
}

/// What a case expects of each step.
#[derive(Clone, Copy)]
enum Want {
    /// Simulated, with the interpreter's result.
    Sim,
    /// Left to the target, for a reason containing this text.
    Real(&'static str),
}

#[derive(Default)]
struct Case<'a> {
    words: &'a [u32],
    regs: &'a [(u32, u32)],
    data: &'a [u8],
    guards: Guards,
    sr: Option<u32>,
    steps: &'a [Want],
}

/// Run `case` on the interpreter and the simulator side by side; returns
/// the interpreter's machine at the end.
fn check(name: &str, case: &Case) -> Machine {
    let mut oracle = machine(case.words, case.regs, case.data);
    if let Some(sr) = case.sr {
        oracle.set(REG_SR, sr);
    }
    let mut target = machine(case.words, case.regs, case.data);
    if let Some(sr) = case.sr {
        target.set(REG_SR, sr);
    }
    for (n, want) in case.steps.iter().enumerate() {
        let pc = oracle.reg(REG_PC);
        let mut regs = target.regs;
        let ram_before = target.ram.clone();
        let got = stepsim::step(&mut regs, &case.guards, &mut MachineBus(&mut target))
            .expect("infallible");
        let truth = Interp::host_step(&mut oracle);
        match (*want, got) {
            (Want::Sim, Outcome::Done) => {
                assert!(
                    truth.is_ok(),
                    "{name} step {n} at 0x{pc:08x}: simulated, interpreter says {truth:?}"
                );
                for (k, (a, b)) in regs.iter().zip(oracle.regs.iter()).enumerate() {
                    assert_eq!(
                        a, b,
                        "{name} step {n} at 0x{pc:08x}: reg {k}: sim 0x{a:08x} interp 0x{b:08x}"
                    );
                }
                assert!(
                    target.ram == oracle.ram,
                    "{name} step {n} at 0x{pc:08x}: RAM differs"
                );
                target.regs = regs;
            }
            (Want::Real(why), Outcome::Fallback(got)) => {
                assert!(
                    got.contains(why),
                    "{name} step {n} at 0x{pc:08x}: fell back for {got:?}, want {why:?}"
                );
                assert_eq!(regs, target.regs, "{name} step {n}: fallback changed regs");
                assert!(target.ram == ram_before, "{name}: fallback wrote");
                // The target would run it; carry on from the interpreter's
                // state when it could, else the case is over.
                if truth.is_err() {
                    return oracle;
                }
                target.regs = oracle.regs;
                target.ram.clone_from(&oracle.ram);
            }
            (Want::Sim, Outcome::Fallback(why)) => {
                panic!("{name} step {n} at 0x{pc:08x}: fell back ({why}), want simulated")
            }
            (Want::Real(why), Outcome::Done) => {
                panic!("{name} step {n} at 0x{pc:08x}: simulated, want fallback ({why})")
            }
        }
    }
    oracle
}

fn reg(m: &Machine, r: u32) -> u32 {
    m.reg(u16::try_from(r).expect("reg"))
}

fn sims(n: usize) -> Vec<Want> {
    vec![Want::Sim; n]
}

// ---- cases ----

#[test]
fn alu_and_shifts() {
    let words = [
        lui(T0, 0x8765),          // 00
        ori(T0, T0, 0x4321),      // 04
        addiu(T1, ZERO, -7),      // 08
        r(0x21, T0, T1, T2, 0),   // addu
        r(0x23, T1, T0, T3, 0),   // subu
        r(0x24, T0, T1, T4, 0),   // and
        r(0x25, T0, T1, S0, 0),   // or
        r(0x26, T0, T1, S1, 0),   // xor
        r(0x27, T0, T1, A0, 0),   // nor
        r(0x2a, T1, T0, A1, 0),   // slt (-7 < 0x87654321 signed: no)
        r(0x2b, T1, T0, V0, 0),   // sltu
        r(0x2a, T0, T1, V1, 0),   // slt (negative < -7: yes)
        i(0x0a, T1, AT, -8),      // slti -7 < -8: no
        i(0x0b, T0, AT, -1),      // sltiu 0x87654321 < 0xffffffff: yes
        i(0x0c, T0, T2, 0x8f0f),  // andi (zero-extended)
        i(0x0e, T1, T3, 0xffff),  // xori
        r(0x00, 0, T0, T4, 4),    // sll
        r(0x02, 0, T0, S0, 31),   // srl
        r(0x03, 0, T0, S1, 8),    // sra
        addiu(A0, ZERO, 36),      // shift amount 36 -> 4
        r(0x04, A0, T0, A1, 0),   // sllv
        r(0x06, A0, T0, V0, 0),   // srlv
        r(0x07, A0, T0, V1, 0),   // srav
        r(0x20, T1, T1, T2, 0),   // add, no overflow
        r(0x22, T1, T0, T3, 0),   // sub, no overflow
        i(8, T1, T4, -0x8000),    // addi, no overflow
        addiu(ZERO, T0, 5),       // r0 stays 0
        r(0x21, T0, T0, ZERO, 0), // r0 stays 0
        NOP,
    ];
    check(
        "alu",
        &Case {
            words: &words,
            steps: &sims(words.len()),
            ..Default::default()
        },
    );
}

#[test]
fn mult_div_hi_lo() {
    let words = [
        r(0x18, T0, T1, 0, 0), // mult -3 * 0x7fffffff
        r(0x10, 0, 0, A0, 0),  // mfhi
        r(0x12, 0, 0, A1, 0),  // mflo
        r(0x19, T0, T1, 0, 0), // multu
        r(0x10, 0, 0, V0, 0),
        r(0x1a, T0, T2, 0, 0),   // div -3 / 2
        r(0x1a, T1, ZERO, 0, 0), // div by zero, positive
        r(0x1a, T0, ZERO, 0, 0), // div by zero, negative
        r(0x1a, T3, T0, 0, 0),   // 0x80000000 / -3
        r(0x1a, T3, T4, 0, 0),   // 0x80000000 / -1
        r(0x1b, T0, T2, 0, 0),   // divu
        r(0x1b, T0, ZERO, 0, 0), // divu by zero
        r(0x11, T2, 0, 0, 0),    // mthi
        r(0x13, T1, 0, 0, 0),    // mtlo
        r(0x12, 0, 0, V1, 0),
    ];
    check(
        "muldiv",
        &Case {
            words: &words,
            regs: &[
                (T0, (-3i32).cast_unsigned()),
                (T1, 0x7fff_ffff),
                (T2, 2),
                (T3, 0x8000_0000),
                (T4, u32::MAX),
                (REG_HI.into(), 0x1111),
                (REG_LO.into(), 0x2222),
            ],
            steps: &sims(words.len()),
            ..Default::default()
        },
    );
}

#[test]
fn branches_and_delay_slots() {
    let words = [
        i(4, T0, T1, 3),       // 00 beq, not taken
        addiu(A0, A0, 1),      // 04 slot
        i(5, T0, T1, 2),       // 08 bne, taken -> 0x14
        addiu(A0, A0, 2),      // 0c slot
        addiu(A0, A0, 100),    // 10 skipped
        i(6, T0, 0, 2),        // 14 blez t0 (-1): taken -> 0x20
        addiu(A1, A1, 1),      // 18 slot
        NOP,                   // 1c skipped
        i(7, T0, 0, 5),        // 20 bgtz: not taken
        NOP,                   // 24
        regimm(0x10, T0, 2),   // 28 bltzal: taken -> 0x34, ra = 0x30
        addiu(A1, A1, 2),      // 2c slot
        NOP,                   // 30
        regimm(0x11, T0, 5),   // 34 bgezal: not taken, links anyway
        NOP,                   // 38
        regimm(0x01, T1, 1),   // 3c bgez t1 (5): taken -> 0x44
        NOP,                   // 40
        j(2, BASE + 0x50),     // 44 j -> 0x50
        addiu(V0, ZERO, 9),    // 48 slot
        NOP,                   // 4c
        j(3, BASE + 0x60),     // 50 jal -> 0x60
        addiu(V1, ZERO, 8),    // 54 slot
        NOP,                   // 58
        NOP,                   // 5c
        lui(S0, BASE >> 16),   // 60
        ori(S0, S0, 0x74),     // 64
        r(0x09, S0, 0, S1, 0), // 68 jalr s1, s0 -> 0x74
        addiu(A0, A0, 4),      // 6c slot
        NOP,                   // 70
        addiu(T2, ZERO, 3),    // 74
        addiu(T2, T2, -1),     // 78 loop: 3 times
        i(5, T2, ZERO, -2),    // 7c bne t2, zero, 0x78
        addiu(T3, T3, 1),      // 80 slot
        r(0x08, RA, 0, 0, 0),  // 84 jr ra (0x58)
        NOP,                   // 88
    ];
    let steps = sims(20);
    let m = check(
        "branches",
        &Case {
            words: &words,
            regs: &[(T0, u32::MAX), (T1, 5)],
            steps: &steps,
            ..Default::default()
        },
    );
    assert_eq!(m.reg(REG_PC), BASE + 0x58, "ended back at jal's return");
    assert_eq!(reg(&m, T2), 0);
    assert_eq!(reg(&m, T3), 3);
}

#[test]
fn loads_and_stores() {
    let data: Vec<u8> = (0u8..32).map(|b| b.wrapping_mul(37) | 0x80).collect();
    let words = [
        lui(S0, DATA >> 16), // 00
        mem(LB, T0, 1, S0),  // sign-extended byte
        mem(LBU, T1, 1, S0), // zero-extended
        mem(LH, T2, 2, S0),  // sign-extended half
        mem(LHU, T3, 2, S0),
        mem(LW, T4, 4, S0),
        addiu(A0, ZERO, -1),
        mem(LWL, A0, 8, S0), // offsets 0..3
        mem(LWR, A0, 8, S0),
        mem(LWL, A1, 9, S0),
        mem(LWR, A1, 12, S0),
        mem(LWL, V0, 14, S0),
        mem(LWR, V0, 11, S0),
        mem(LWL, V1, 19, S0),
        mem(LWR, V1, 17, S0),
        // Each offset merging into a register that is not 0.
        mem(LWL, AT, 20, S0),
        mem(LWL, AT, 21, S0),
        mem(LWL, AT, 22, S0),
        mem(LWL, AT, 23, S0),
        mem(LWR, AT, 20, S0),
        mem(LWR, AT, 21, S0),
        mem(LWR, AT, 22, S0),
        mem(LWR, AT, 23, S0),
        lui(T0, 0xa1b2),
        ori(T0, T0, 0xc3d4),
        mem(SB, T0, 16, S0),
        mem(SH, T0, 18, S0),
        mem(SW, T0, 20, S0),
        mem(SWL, T0, 24, S0), // offsets 0..3
        mem(SWR, T0, 25, S0),
        mem(SWL, T0, 26, S0),
        mem(SWR, T0, 27, S0),
        mem(SWR, T0, 28, S0),
        mem(SWL, T0, 31, S0),
        mem(LW, ZERO, 0, S0), // load into r0
        lui(S1, 0xbfc0),
        mem(LW, T1, 0x100, S1), // BIOS ROM
        lui(S1, 0xa002),        // kseg1 view of DATA
        mem(LW, T2, 20, S1),
        mem(SB, T2, 1, S1),
        NOP,
    ];
    check(
        "loads",
        &Case {
            words: &words,
            regs: &[(AT, 0x1122_3344), (A1, 0xa1a1_a1a1), (V1, 0xc3c3_c3c3)],
            data: &data,
            steps: &sims(words.len()),
            ..Default::default()
        },
    );
}

#[test]
fn load_in_delay_slot_is_seen_at_the_target() {
    // The step boundary is an exception: the load has landed when the
    // target instruction runs.
    let words = [
        lui(S0, DATA >> 16),
        i(4, ZERO, ZERO, 2), // b 0x10
        mem(LW, T0, 0, S0),  // slot
        NOP,
        r(0x21, T0, ZERO, T1, 0), // 0x10: t1 = t0
        NOP,
    ];
    let m = check(
        "delay load",
        &Case {
            words: &words,
            data: &0xdead_beefu32.to_le_bytes(),
            steps: &sims(4),
            ..Default::default()
        },
    );
    assert_eq!(reg(&m, T1), 0xdead_beef);
}

#[test]
fn faults_fall_back() {
    let one = |name: &str, insn: u32, regs: &[(u32, u32)], why: &'static str| {
        check(
            name,
            &Case {
                words: &[insn, NOP],
                regs,
                steps: &[Want::Real(why)],
                ..Default::default()
            },
        );
    };
    let big = [(T0, 0x7fff_ffff), (T1, 1), (T2, 0x8000_0000)];
    one("add ov", r(0x20, T0, T1, T3, 0), &big, "add overflows");
    one("sub ov", r(0x22, T2, T1, T3, 0), &big, "sub overflows");
    one("addi ov", i(8, T0, T3, 1), &big, "addi overflows");
    one("lw unaligned", mem(LW, T3, 2, T2), &big, "unaligned");
    one("lh unaligned", mem(LH, T3, 1, T2), &big, "unaligned");
    one("sh unaligned", mem(SH, T3, 1, T2), &big, "unaligned");
    one("sw unaligned", mem(SW, T3, 2, T2), &big, "unaligned");
    one("syscall", 0x0000_000c, &[], "syscall");
    one("break", 0x0000_000d, &[], "break");
    one("mfc0", 0x4008_6000, &[], "coprocessor");
    one("cop2", 0x4a00_0001, &[], "coprocessor");
    one("lwc2", 0xc800_0000, &[], "coprocessor load/store");
    one("reserved", 0xfc00_0000, &[], "reserved");
    one("reserved funct", r(0x01, 0, 0, 0, 0), &[], "reserved");
    one("lui rs", i(0xf, 1, T0, 1), &[], "reserved field");
    one(
        "jr ra into nothing",
        r(0x08, RA, 0, 0, 0),
        &[(RA, 0x1f00_0000)],
        "outside",
    );
    one(
        "jalr rd = rs",
        r(0x09, T0, 0, T0, 0),
        &[(T0, BASE)],
        "rd = rs",
    );
    one("bltzal r31", regimm(0x10, RA, 1), &[], "r31");
    one("undefined regimm", regimm(0x02, T0, 1), &[], "REGIMM");
}

#[test]
fn memory_outside_ram_falls_back() {
    let one = |name: &str, insn: u32, base: u32, why: &'static str| {
        check(
            name,
            &Case {
                words: &[insn, NOP],
                regs: &[(S0, base)],
                steps: &[Want::Real(why)],
                ..Default::default()
            },
        );
    };
    one("I/O read", mem(LW, T0, 0x70, S0), 0x1f80_1000, "outside");
    one("I/O write", mem(SW, T0, 0x70, S0), 0x1f80_1000, "outside");
    one("EXP1", mem(LW, T0, 0, S0), 0x1f00_0000, "outside");
    one("BIOS write", mem(SW, T0, 0, S0), 0xbfc0_0000, "outside");
    one("mirror", mem(LW, T0, 0, S0), 0x8020_0000, "outside");
    one("kseg2", mem(LW, T0, 0, S0), 0xfffe_0130, "outside");
}

#[test]
fn delay_slot_hazards_fall_back() {
    let seq = |name: &str, words: &[u32], regs: &[(u32, u32)], why: &'static str| {
        check(
            name,
            &Case {
                words,
                regs,
                steps: &[Want::Real(why)],
                ..Default::default()
            },
        );
    };
    let tgt = BASE + 0x10;
    seq(
        "slot reads link",
        &[j(3, tgt), addiu(A0, RA, 0), NOP, NOP, NOP],
        &[],
        "reads the link",
    );
    seq(
        "slot writes link",
        &[j(3, tgt), addiu(RA, ZERO, 1), NOP, NOP, NOP],
        &[],
        "writes the link",
    );
    seq(
        "slot loads link",
        &[r(0x09, T0, 0, RA, 0), mem(LWL, RA, 0, T0), NOP, NOP, NOP],
        &[(T0, tgt)],
        "writes the link",
    );
    seq(
        "branch in slot",
        &[j(2, tgt), j(2, tgt), NOP, NOP, NOP],
        &[],
        "branch in a delay slot",
    );
    seq(
        "slot faults",
        &[j(2, tgt), r(0x20, T0, T0, T1, 0), NOP, NOP, NOP],
        &[(T0, 0x7fff_ffff)],
        "overflows",
    );
    seq(
        "slot is a break",
        &[j(2, tgt), 0x0000_000d, NOP, NOP, NOP],
        &[],
        "break",
    );
}

#[test]
fn debug_unit_and_sr_fall_back() {
    let words = [
        lui(S0, DATA >> 16),
        mem(SW, T0, 4, S0),
        mem(LW, T0, 4, S0),
        j(2, BASE + 0x14),
        NOP,
        NOP,
    ];
    let watch = |read, write| Guards {
        exec: None,
        watch: Some(WatchRange {
            addr: DATA & 0x1fff_ffff,
            len: 8,
            read,
            write,
        }),
    };
    check(
        "write watch",
        &Case {
            words: &words,
            guards: watch(false, true),
            steps: &[Want::Sim, Want::Real("watch"), Want::Sim, Want::Sim],
            ..Default::default()
        },
    );
    check(
        "read watch",
        &Case {
            words: &words,
            guards: watch(true, false),
            steps: &[Want::Sim, Want::Sim, Want::Real("watch"), Want::Sim],
            ..Default::default()
        },
    );
    check(
        "exec bp on the slot",
        &Case {
            words: &words,
            guards: Guards {
                exec: Some((BASE + 0x10, 0x1fff_ffff)),
                watch: None,
            },
            steps: &[Want::Sim, Want::Sim, Want::Sim, Want::Real("delay slot")],
            ..Default::default()
        },
    );
    for (sr, why) in [
        (RUN_SR | 1 << 16, "IsC"),
        (RUN_SR | 1 << 17, "SwC"),
        (RUN_SR | 2, "user mode"),
        (RUN_SR | 1 << 3, "user mode"),
    ] {
        check(
            why,
            &Case {
                words: &words,
                sr: Some(sr),
                steps: &[Want::Real(why)],
                ..Default::default()
            },
        );
    }
}

#[test]
fn rom_code_steps() {
    // Code in the BIOS ROM is fetched and stepped like RAM code.
    let words = [
        lui(T0, 0xbfc0),
        ori(T0, T0, 0x104),
        r(0x09, T0, 0, RA, 0),
        NOP,
        NOP,
    ];
    let m = check(
        "rom",
        &Case {
            words: &words,
            steps: &sims(4),
            ..Default::default()
        },
    );
    assert_eq!(m.reg(REG_PC), BASE + 0x10);
    assert_eq!(ROM_BASE, 0x1fc0_0000);
}
