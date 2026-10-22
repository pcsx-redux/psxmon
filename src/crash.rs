//! A crash report for a FAULT stop: what the exception means, where it
//! happened and in which instruction, the registers, and the top of the
//! stack, with symbols when an ELF is at hand.

use std::fmt::Write as _;

use crate::exe::Symbol;
use crate::mips::{self, REG_NAMES};
use crate::proto::{NUM_REGS, REG_BADVADDR, REG_CAUSE};
use crate::session::{Session, Stop};
use crate::transport::Transport;

/// Names of REGS slots 32-37.
const REGS_TAIL: [&str; 6] = ["sr", "lo", "hi", "bad", "cause", "epc"];

/// Words of stack dumped from sp.
pub const STACK_WORDS: u32 = 8;

const SP: usize = 29;
const RA: usize = 31;
/// Cause.BD: the exception was in a branch delay slot.
const CAUSE_BD: u32 = 1 << 31;
/// How far past an unsized symbol (an assembler label) an address may lie
/// and still be named after it.
const LABEL_REACH: u32 = 0x1000;

/// The R3000A's name for ExcCode `code` and what it means.
pub fn exc_code(code: u32) -> (&'static str, &'static str) {
    match code {
        0 => ("Int", "interrupt"),
        1 => ("Mod", "TLB modification (the PS1 has no TLB)"),
        2 => ("TLBL", "TLB miss on a load (the PS1 has no TLB)"),
        3 => ("TLBS", "TLB miss on a store (the PS1 has no TLB)"),
        4 => (
            "AdEL",
            "address error on a load or an instruction fetch: a misaligned address, \
             or a kernel address from user mode",
        ),
        5 => (
            "AdES",
            "address error on a store: a misaligned address, or a kernel address from user mode",
        ),
        6 => (
            "IBE",
            "bus error on an instruction fetch: nothing answered at the PC",
        ),
        7 => (
            "DBE",
            "bus error on a load or store: nothing answered at the address",
        ),
        8 => ("Sys", "syscall"),
        9 => ("Bp", "breakpoint"),
        10 => (
            "RI",
            "reserved instruction: the word at the PC is not an R3000 instruction",
        ),
        11 => (
            "CpU",
            "coprocessor unusable: a coprocessor instruction with its SR.CU bit clear",
        ),
        12 => (
            "Ov",
            "arithmetic overflow in add, addi or sub (addu, addiu and subu wrap instead)",
        ),
        _ => ("?", "unknown exception code"),
    }
}

/// Symbols to name addresses with.
#[derive(Debug, Default, Clone)]
pub struct Symbols(Vec<Symbol>);

impl Symbols {
    pub fn new(mut syms: Vec<Symbol>) -> Self {
        syms.sort_by_key(|s| s.addr);
        Symbols(syms)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `name+0xoff` for `addr`: the innermost sized symbol holding it, or an
    /// unsized label at most [`LABEL_REACH`] below it. Addresses compare by
    /// physical address, so kseg0, kseg1 and kuseg forms all match.
    pub fn name(&self, addr: u32) -> Option<String> {
        let a = addr & 0x1fff_ffff;
        let best = self
            .0
            .iter()
            .filter(|s| {
                let start = s.addr & 0x1fff_ffff;
                a.checked_sub(start).is_some_and(|off| {
                    if s.size == 0 {
                        off < LABEL_REACH
                    } else {
                        off < s.size
                    }
                })
            })
            .max_by_key(|s| (s.addr & 0x1fff_ffff, s.size != 0))?;
        let off = a.wrapping_sub(best.addr & 0x1fff_ffff);
        Some(if off == 0 {
            best.name.clone()
        } else {
            format!("{}+0x{off:x}", best.name)
        })
    }

    fn tag(&self, addr: u32) -> String {
        self.name(addr)
            .map(|n| format!(" <{n}>"))
            .unwrap_or_default()
    }
}

/// What the host read from a halted target for its report.
#[derive(Debug, Clone)]
pub struct Crash {
    pub stop: Stop,
    /// GET_REGS, or why it failed.
    pub regs: Result<[u32; NUM_REGS], String>,
    /// The word at EPC, and at EPC + 4 when the fault was in a delay slot.
    pub code: Vec<(u32, u32)>,
    /// [`STACK_WORDS`] words from sp, when sp points at memory.
    pub stack: Vec<u32>,
}

async fn read_words<T: Transport>(s: &mut Session<T>, addr: u32, n: u32) -> Option<Vec<u32>> {
    let len = n.checked_mul(4)?;
    if addr & 3 != 0 || !mips::safe_to_read(addr, len) {
        return None;
    }
    let bytes = s.read_mem(addr, len).await.ok()?;
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w))
        .collect();
    (words.len() == usize::try_from(n).ok()?).then_some(words)
}

/// Read what the report needs from the halted target. Never fails: a part
/// the monitor cannot give is left out of the report.
pub async fn gather<T: Transport>(s: &mut Session<T>, stop: Stop) -> Crash {
    let regs = s.get_regs().await.map_err(|e| e.to_string());
    let mut crash = Crash {
        stop,
        regs,
        code: Vec::new(),
        stack: Vec::new(),
    };
    let Ok(regs) = crash.regs else {
        return crash;
    };
    let bd = regs[usize::from(REG_CAUSE)] & CAUSE_BD != 0;
    let n = if bd { 2 } else { 1 };
    if let Some(words) = read_words(s, stop.epc, n).await {
        crash.code = (0u32..)
            .map(|i| stop.epc.wrapping_add(i.wrapping_mul(4)))
            .zip(words)
            .collect();
    }
    if let Some(words) = read_words(s, regs[SP], STACK_WORDS).await {
        crash.stack = words;
    }
    crash
}

impl Crash {
    /// The report, one line per item, each ending in a newline.
    pub fn report(&self, syms: &Symbols) -> String {
        let mut out = String::new();
        let stop = self.stop;
        let code = stop.a;
        let (name, meaning) = exc_code(code);
        let _ = writeln!(out, "  cause:   {name} (ExcCode {code}): {meaning}");
        let regs = match &self.regs {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(out, "  registers unavailable: {e}");
                return out;
            }
        };
        let bd = regs[usize::from(REG_CAUSE)] & CAUSE_BD != 0;
        let pc = if bd {
            stop.epc.wrapping_add(4)
        } else {
            stop.epc
        };
        let insn = self.code.iter().find(|&&(a, _)| a == pc).map(|&(_, w)| w);
        let bad = regs[usize::from(REG_BADVADDR)];
        if code == 4 || code == 5 {
            let fetch = if code == 4 && bad == pc {
                " (instruction fetch)"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "  address: 0x{bad:08x}{} (BadVaddr){fetch}",
                syms.tag(bad)
            );
        }
        match insn {
            Some(w) => {
                let _ = writeln!(
                    out,
                    "  pc:      0x{pc:08x}{}  {}",
                    syms.tag(pc),
                    mips::disasm(pc, w)
                );
            }
            None => {
                let _ = writeln!(out, "  pc:      0x{pc:08x}{}  (not readable)", syms.tag(pc));
            }
        }
        if let Some(acc) = insn.and_then(|w| mips::mem_access(w, regs)) {
            let _ = writeln!(
                out,
                "  access:  {}-byte {} 0x{:08x}{}",
                acc.size,
                if acc.store { "store to" } else { "load from" },
                acc.addr,
                syms.tag(acc.addr)
            );
        }
        if code == 12
            && let Some(w) = insn
        {
            let rs = (w >> 21) & 31;
            let rt = (w >> 16) & 31;
            let val = |i: u32| {
                usize::try_from(i)
                    .ok()
                    .and_then(|i| regs.get(i))
                    .copied()
                    .unwrap_or(0)
            };
            let name = |i: u32| {
                usize::try_from(i)
                    .ok()
                    .and_then(|i| REG_NAMES.get(i))
                    .copied()
                    .unwrap_or("?")
            };
            let second = if w >> 26 == 0 {
                format!(" {}=0x{:08x}", name(rt), val(rt))
            } else {
                String::new()
            };
            let _ = writeln!(out, "  operands: {}=0x{:08x}{second}", name(rs), val(rs));
        }
        if bd {
            let branch = self
                .code
                .iter()
                .find(|&&(a, _)| a == stop.epc)
                .map(|&(a, w)| format!("  {}", mips::disasm(a, w)))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  in the delay slot of the branch at 0x{:08x}{}{branch}",
                stop.epc,
                syms.tag(stop.epc)
            );
        }
        let _ = writeln!(
            out,
            "  ra:      0x{:08x}{}   sp: 0x{:08x}",
            regs[RA],
            syms.tag(regs[RA]),
            regs[SP]
        );
        // Every REGS slot in REGS order (PROTOCOL.md section 9): r0-r31 by
        // ABI name, then SR, LO, HI, BadVaddr, Cause and the resume PC.
        let all: Vec<String> = REG_NAMES
            .iter()
            .chain(&REGS_TAIL)
            .zip(regs.iter())
            .map(|(n, v)| format!("{n:>5} {v:08x}"))
            .collect();
        let _ = writeln!(out, "  registers:");
        for row in all.chunks(4) {
            let _ = writeln!(out, " {}", row.join("  "));
        }
        if !self.stack.is_empty() {
            let _ = writeln!(out, "  stack at 0x{:08x}:", regs[SP]);
            for (i, w) in (0u32..).zip(&self.stack) {
                let at = regs[SP].wrapping_add(i.wrapping_mul(4));
                let _ = writeln!(out, "    0x{at:08x}: {w:08x}{}", syms.tag(*w));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(name: &str, addr: u32, size: u32) -> Symbol {
        Symbol {
            name: name.into(),
            addr,
            size,
        }
    }

    #[test]
    fn symbol_names() {
        let s = Symbols::new(vec![
            sym("main", 0x8001_0000, 0x100),
            sym("inner", 0x8001_0040, 0x10),
            sym("label", 0x8002_0000, 0),
            sym("table", 0x8003_0000, 8),
        ]);
        assert_eq!(s.name(0x8001_0000).as_deref(), Some("main"));
        assert_eq!(s.name(0x8001_0044).as_deref(), Some("inner+0x4"));
        assert_eq!(s.name(0x8001_0050).as_deref(), Some("main+0x50"));
        // Any segment of the same physical address.
        assert_eq!(s.name(0xa001_0004).as_deref(), Some("main+0x4"));
        assert_eq!(s.name(0x8002_0ffc).as_deref(), Some("label+0xffc"));
        assert_eq!(s.name(0x8002_1000), None);
        assert_eq!(s.name(0x8003_0008), None);
        assert_eq!(s.name(0x8000_fffc), None);
        assert!(Symbols::default().name(0x8001_0000).is_none());
    }

    #[test]
    fn every_fault_code_the_monitor_sends_has_a_name() {
        for code in [4, 5, 6, 7, 10, 11, 12] {
            assert_ne!(exc_code(code).0, "?", "ExcCode {code}");
        }
        assert_eq!(exc_code(13).0, "?");
    }
}
