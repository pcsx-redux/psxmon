//! `psxmon gdb` against the simulated monitor, spoken to in raw RSP, and
//! (with PSXMON_GDB_E2E=1) through a real gdb-multiarch.
#![cfg(test)]

#[allow(dead_code)]
#[path = "../session/sim.rs"]
mod sim;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use gdbstub::stub::DisconnectReason;
use psxmon::MemTransport;
use psxmon::exe::{Image, Segment};
use psxmon::gdb::MonTarget;
use psxmon::pcdrv::{PcdrvServer, Quota};
use psxmon::proto::*;
use psxmon::session::{LoadOptions, Session};
use sim::{Interp, SimConfig, SimStats};

// ---- a few R3000 encodings ----

const ZERO: u32 = 0;
const V0: u32 = 2;
const A0: u32 = 4;
const T0: u32 = 8;
const T1: u32 = 9;
const T2: u32 = 10;
const T3: u32 = 11;
const T4: u32 = 12;
const T5: u32 = 13;

fn itype(op: u32, rs: u32, rt: u32, imm: i32) -> u32 {
    (op << 26) | (rs << 21) | (rt << 16) | (imm.cast_unsigned() & 0xffff)
}
fn addiu(rt: u32, rs: u32, imm: i32) -> u32 {
    itype(9, rs, rt, imm)
}
fn lui(rt: u32, imm: u32) -> u32 {
    itype(0xf, 0, rt, i32::try_from(imm).expect("16 bits"))
}
fn ori(rt: u32, rs: u32, imm: u32) -> u32 {
    itype(0xd, rs, rt, i32::try_from(imm).expect("16 bits"))
}
fn sw(rt: u32, off: i32, base: u32) -> u32 {
    itype(0x2b, base, rt, off)
}
fn sb(rt: u32, off: i32, base: u32) -> u32 {
    itype(0x28, base, rt, off)
}
fn beq(rs: u32, rt: u32, words: i32) -> u32 {
    itype(4, rs, rt, words)
}
fn bne(rs: u32, rt: u32, words: i32) -> u32 {
    itype(5, rs, rt, words)
}
fn jalr(rs: u32) -> u32 {
    (rs << 21) | (31 << 11) | 9
}
fn brk(code1: u32, code2: u32) -> u32 {
    BreakCode { code1, code2 }.encode()
}
const NOP: u32 = 0;
const JR_RA: u32 = 0x03e0_0008;

const BASE: u32 = 0x8001_0000;
const DATA: u32 = 0x8002_0000;
const ROM_FN: u32 = 0xbfc0_0100;

/// The main test program; comments give each word's offset.
fn main_program() -> Vec<u32> {
    vec![
        lui(T0, DATA >> 16),          // 00
        addiu(T1, ZERO, 5),           // 04
        sw(T1, 0, T0),                // 08 watch hit 1
        beq(T1, ZERO, 10),            // 0c not taken
        addiu(T2, ZERO, 1),           // 10 delay slot
        bne(T1, ZERO, 2),             // 14 taken, to 0x20
        addiu(T3, ZERO, 2),           // 18 delay slot
        addiu(T4, ZERO, 3),           // 1c skipped
        brk(0, PC_INIT),              // 20 PCDRV, served unseen
        lui(T5, ROM_FN >> 16),        // 24
        ori(T5, T5, ROM_FN & 0xffff), // 28
        jalr(T5),                     // 2c into ROM: hbreak there
        NOP,                          // 30
        sw(T1, 0, T0),                // 34 watch hit 2
        addiu(A0, ZERO, 42),          // 38
        brk(4, 0),                    // 3c exit 42
    ]
}

/// Prints `text` through the sim's tty port, then exits 42.
fn print_program(text: &[u8]) -> Vec<u32> {
    let mut w = vec![lui(T0, sim::TTY_PORT >> 16)];
    let off = i32::try_from(sim::TTY_PORT & 0xffff).expect("16 bits");
    for &b in text {
        w.push(addiu(T1, ZERO, i32::from(b)));
        w.push(sb(T1, off, T0));
    }
    w.push(addiu(A0, ZERO, 42));
    w.push(brk(4, 0));
    w
}

fn rom() -> Vec<u8> {
    let mut r = vec![0u8; 0x200];
    r[0x100..0x104].copy_from_slice(&JR_RA.to_le_bytes());
    r
}

fn image(words: &[u32]) -> Image {
    Image {
        segments: vec![Segment {
            addr: BASE,
            data: words.iter().flat_map(|w| w.to_le_bytes()).collect(),
        }],
        pc: BASE,
        gp: 0x8009_0000,
        sp: 0x801f_ff00,
    }
}

struct Rig {
    port: u16,
    stats: Arc<Mutex<SimStats>>,
    server: JoinHandle<(DisconnectReason, Option<u32>)>,
    _dir: tempfile::TempDir,
}

/// A sim running `words`, a MonTarget over it halted at the entry, and a
/// server thread waiting for one gdb connection. Steps are simulated on the
/// host where possible.
fn rig(words: &[u32]) -> Rig {
    rig_opts(words, sim::RAM_SIZE, true)
}

/// [`rig`] with `ram` bytes of RAM installed.
fn rig_with(words: &[u32], ram: usize) -> Rig {
    rig_opts(words, ram, true)
}

/// [`rig`], with host step simulation on or off.
fn rig_sim(words: &[u32], step_sim: bool) -> Rig {
    rig_opts(words, sim::RAM_SIZE, step_sim)
}

/// [`rig`] with `ram` bytes of RAM and host step simulation on or off.
fn rig_opts(words: &[u32], ram: usize, step_sim: bool) -> Rig {
    let cfg = SimConfig {
        rom: rom(),
        ram_size: ram,
        ..Default::default()
    };
    // The sim gets a thread and runtime of its own; the server's runtime is
    // only driven while a target operation runs.
    let (host, dev, rate) = MemTransport::pair(115200);
    let (sim, stats) = sim::Sim::new(dev, rate, cfg, Box::new(Interp::default()));
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("sim runtime")
            .block_on(sim.run());
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("gdb runtime");
    let mut s = Session::new(host);
    assert!(
        rt.block_on(s.ping(Duration::from_secs(2), &[]))
            .expect("ping")
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let pcdrv = PcdrvServer::new(dir.path(), Quota::default()).expect("pcdrv");
    let mut t = MonTarget::new(rt, s, Some(pcdrv));
    t.verbose = std::env::var_os("PSXMON_GDB_VERBOSE").is_some();
    t.step_sim = step_sim;
    t.start_program(&image(words), &LoadOptions::default())
        .expect("start at entry");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (conn, _) = listener.accept().expect("accept");
        let reason = t.serve(conn).expect("serve");
        (reason, t.exit_code)
    });
    Rig {
        port,
        stats,
        server,
        _dir: dir,
    }
}

/// A minimal RSP client (ack mode).
struct Rsp {
    s: TcpStream,
}

impl Rsp {
    fn connect(port: u16) -> Rsp {
        let s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        Rsp { s }
    }

    fn byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.s.read_exact(&mut b).expect("read from server");
        b[0]
    }

    fn cmd(&mut self, body: &str) -> String {
        self.send(body);
        self.reply()
    }

    /// Send `body` and wait for the server's ack.
    fn send(&mut self, body: &str) {
        let sum = body.bytes().fold(0u8, u8::wrapping_add);
        let pkt = format!("${body}#{sum:02x}");
        self.s.write_all(pkt.as_bytes()).expect("send");
        loop {
            match self.byte() {
                b'+' => break,
                b'-' => self.s.write_all(pkt.as_bytes()).expect("resend"),
                other => panic!("expected ack, got {other:#x}"),
            }
        }
    }

    /// The next packet's body, acked.
    fn reply(&mut self) -> String {
        let r = self.recv();
        self.ack();
        r
    }

    fn ack(&mut self) {
        self.s.write_all(b"+").expect("ack");
    }

    /// The next packet's body, not yet acked.
    fn recv(&mut self) -> String {
        while self.byte() != b'$' {}
        let mut raw = Vec::new();
        loop {
            let b = self.byte();
            if b == b'#' {
                break;
            }
            raw.push(b);
        }
        let _ = (self.byte(), self.byte());
        // Undo run-length encoding: `X*n` repeats X n - 29 more times.
        let mut out: Vec<u8> = Vec::new();
        let mut it = raw.into_iter();
        while let Some(b) = it.next() {
            if b == b'*' {
                let n = it.next().expect("run length").saturating_sub(29);
                let last = *out.last().expect("a byte to repeat");
                out.extend(std::iter::repeat_n(last, usize::from(n)));
            } else {
                out.push(b);
            }
        }
        String::from_utf8(out).expect("ascii")
    }

    fn reg(&mut self, n: usize) -> u32 {
        let r = self.cmd(&format!("p{n:x}"));
        let bytes: Vec<u8> = r
            .as_bytes()
            .chunks(2)
            .take(4)
            .map(|h| u8::from_str_radix(std::str::from_utf8(h).expect("ascii"), 16).expect("hex"))
            .collect();
        u32::from_le_bytes(bytes.try_into().expect("4 bytes"))
    }

    fn pc(&mut self) -> u32 {
        self.reg(usize::from(REG_PC))
    }
}

fn is_trap(r: &str) -> bool {
    r.starts_with("S05") || r.starts_with("T05")
}

/// Every CONT since command `from` is preceded, since the one before it,
/// by SET_BP for each kind in `kinds`.
fn assert_rearmed(stats: &Arc<Mutex<SimStats>>, from: usize, kinds: &[u16]) {
    let st = stats.lock().expect("stats");
    let cmds = &st.cmds[from..];
    let conts = cmds.iter().filter(|&&c| c == CONT).count();
    assert!(conts > 0, "no CONT in {cmds:x?}");
    let mut last = 0;
    for (i, &c) in cmds.iter().enumerate() {
        if c == CONT {
            let window = &cmds[last..i];
            let set = window.iter().filter(|&&c| c == SET_BP).count();
            assert_eq!(set, kinds.len(), "SET_BPs before CONT: {window:x?}");
            last = i.saturating_add(1);
        }
    }
}

fn cmd_count(stats: &Arc<Mutex<SimStats>>) -> usize {
    stats.lock().expect("stats").cmds.len()
}

#[test]
fn rsp_registers_memory_breakpoints_steps_pcdrv_exit() {
    let rig = rig(&main_program());
    let mut g = Rsp::connect(rig.port);
    let sup = g.cmd("qSupported:swbreak+;hwbreak+;xmlRegisters=mips");
    assert!(sup.contains("qXfer:memory-map:read+"), "{sup}");
    assert!(is_trap(&g.cmd("?")));

    // g: 72 registers, gdb order; PC at the entry, sp as RUN set it.
    let regs = g.cmd("g");
    assert_eq!(regs.len(), 72 * 8, "{regs}");
    assert_eq!(&regs[37 * 8..38 * 8], "00000180");
    assert_eq!(&regs[29 * 8..30 * 8], "00ff1f80");
    assert_eq!(g.pc(), BASE);

    // m / M.
    let words = main_program();
    let want: String = words[..2]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(g.cmd(&format!("m{BASE:x},8")), want);
    assert_eq!(g.cmd("M80020100,4:efbeadde"), "OK");
    assert_eq!(g.cmd("m80020100,4"), "efbeadde");
    // A write to ROM that does not take is an error.
    assert!(g.cmd("Mbfc00100,4:0d000500").starts_with('E'));
    assert_eq!(g.cmd("mbfc00100,4"), "0800e003");
    // Unmapped memory is an error, not a monitor access.
    assert!(g.cmd("mfffe0130,4").starts_with('E'));

    // Z0 is not offered at all; Z1 only in ROM; Z2 on the data unit.
    assert_eq!(g.cmd("Z0,80010020,4"), "");
    assert!(g.cmd("Z1,80010020,4").starts_with('E'));
    assert_eq!(g.cmd(&format!("Z1,{ROM_FN:x},4")), "OK");
    assert!(g.cmd("Z1,bfc00200,4").starts_with('E'), "second ROM bp");
    assert!(g.cmd("Z2,80020001,4").starts_with('E'), "unaligned watch");
    assert!(g.cmd("Z2,80020000,c").starts_with('E'), "length 12");
    assert_eq!(g.cmd("Z2,80020000,4"), "OK");

    // Continue: the store at 0x08 trips the watch.
    let mark = cmd_count(&rig.stats);
    let r = g.cmd("c");
    assert!(r.starts_with("T05") && r.contains("watch:80020000"), "{r}");
    assert_eq!(g.pc(), BASE + 0x08);
    assert_rearmed(&rig.stats, mark, &[0, 2]);
    {
        let st = rig.stats.lock().expect("stats");
        assert!(
            st.set_bps.contains(&(0, ROM_FN, 0x1fff_ffff)),
            "{:x?}",
            st.set_bps
        );
        // 2 MiB installed: the mask leaves out bits 21-22, the mirrors.
        assert!(
            st.set_bps.contains(&(2, DATA, 0x1f9f_fffc)),
            "{:x?}",
            st.set_bps
        );
    }

    // Step off the store with the watch out of the way, as gdb does.
    assert_eq!(g.cmd("z2,80020000,4"), "OK");
    assert!(is_trap(&g.cmd("s")));
    assert_eq!(g.pc(), BASE + 0x0c);
    assert_eq!(g.cmd("Z2,80020000,4"), "OK");
    // The planted step break is gone again.
    assert_eq!(g.cmd("m80010010,4"), "01000a24");

    // Not-taken beq: lands at 0x14 with its delay slot run.
    assert!(is_trap(&g.cmd("s")));
    assert_eq!(g.pc(), BASE + 0x14);
    assert_eq!(g.reg(T2 as usize), 1);
    // Taken bne: lands on 0x20, delay slot run, 0x1c skipped.
    assert!(is_trap(&g.cmd("s")));
    assert_eq!(g.pc(), BASE + 0x20);
    assert_eq!(g.reg(T3 as usize), 2);
    assert_eq!(g.reg(T4 as usize), 0);

    // PCinit at 0x20 is served without gdb seeing it (v0 7 -> 0), then
    // the ROM hbreak fires.
    assert_eq!(g.cmd("P2=07000000"), "OK");
    assert_eq!(g.reg(V0 as usize), 7);
    let mark = cmd_count(&rig.stats);
    let r = g.cmd("c");
    assert!(r.starts_with("T05") && r.contains("hwbreak"), "{r}");
    assert_eq!(g.pc(), ROM_FN);
    assert_eq!(g.reg(V0 as usize), 0, "PCinit result");
    // Two CONTs (the first, and the one after PCDRV), each re-armed.
    assert_rearmed(&rig.stats, mark, &[0, 2]);

    // Step `jr ra` in ROM back into RAM.
    assert_eq!(g.cmd(&format!("z1,{ROM_FN:x},4")), "OK");
    assert!(is_trap(&g.cmd("s")));
    assert_eq!(g.pc(), BASE + 0x34);

    // The watch was re-armed after the hardware stop, so it fires again.
    let mark = cmd_count(&rig.stats);
    let r = g.cmd("c");
    assert!(r.contains("watch:80020000"), "{r}");
    assert_eq!(g.pc(), BASE + 0x34);
    assert_rearmed(&rig.stats, mark, &[2]);

    // Exit: W with the code.
    assert_eq!(g.cmd("z2,80020000,4"), "OK");
    assert_eq!(g.cmd("c"), "W2a");
    let (reason, code) = rig.server.join().expect("server thread");
    assert!(matches!(reason, DisconnectReason::TargetExited(42)));
    assert_eq!(code, Some(42));
    let st = rig.stats.lock().expect("stats");
    assert!(st.errors_sent.is_empty(), "{:x?}", st.errors_sent);
}

/// Real stepping: the exec breakpoint is lent to a successor in ROM.
#[test]
fn rsp_step_into_rom_uses_exec_breakpoint() {
    let words = vec![
        lui(T5, ROM_FN >> 16),
        ori(T5, T5, ROM_FN & 0xffff),
        jalr(T5), // 08
        NOP,
        addiu(A0, ZERO, 0), // 10
        brk(4, 0),
    ];
    let rig = rig_sim(&words, false);
    let mut g = Rsp::connect(rig.port);
    g.cmd("qSupported:swbreak+;hwbreak+");
    for _ in 0..3 {
        assert!(is_trap(&g.cmd("s")));
    }
    assert_eq!(g.pc(), ROM_FN);
    assert!(
        rig.stats
            .lock()
            .expect("stats")
            .set_bps
            .contains(&(0, ROM_FN, 0x1fff_ffff))
    );
    assert!(is_trap(&g.cmd("s")));
    assert_eq!(g.pc(), BASE + 0x10);
    assert_eq!(g.cmd("c"), "W00");
    let (_, code) = rig.server.join().expect("server thread");
    assert_eq!(code, Some(0));
}

#[test]
fn rsp_detach_leaves_target_halted() {
    for sim in [false, true] {
        let rig = rig_sim(&main_program(), sim);
        let mut g = Rsp::connect(rig.port);
        g.cmd("qSupported:swbreak+");
        let mark = cmd_count(&rig.stats);
        assert!(is_trap(&g.cmd("s")));
        assert_eq!(g.cmd("D"), "OK");
        let (reason, code) = rig.server.join().expect("server thread");
        assert!(matches!(reason, DisconnectReason::Disconnect));
        assert_eq!(code, None);
        let st = rig.stats.lock().expect("stats");
        let cmds = &st.cmds[mark..];
        if sim {
            // The step (lui t0) ran on the host; detach wrote t0 back.
            assert!(!cmds.contains(&CONT), "simulated step: {cmds:x?}");
            assert_eq!(st.cmds.last(), Some(&SET_REG), "t0 written back: {cmds:x?}");
        } else {
            assert_eq!(cmds.iter().filter(|&&c| c == CONT).count(), 1, "{cmds:x?}");
            assert_eq!(st.cmds.last(), Some(&WRITE_MEM), "no CONT after detach");
        }
    }
}

/// A mixed sequence for stepping: ALU, mult/div (by zero too), stores and
/// loads (byte, lwl/lwr), an I/O load the host leaves to the target, a
/// taken branch with a load in its delay slot, jal/jr with ALU delay slots.
fn step_program() -> Vec<u32> {
    let r = |funct: u32, rs: u32, rt: u32, rd: u32, sa: u32| {
        (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct
    };
    let mem = |op: u32, rt: u32, off: i32, base: u32| itype(op, base, rt, off);
    const AT: u32 = 1;
    const V1: u32 = 3;
    const A1: u32 = 5;
    const A2: u32 = 6;
    const A3: u32 = 7;
    vec![
        lui(T0, DATA >> 16),                            // 00
        addiu(T1, ZERO, -5),                            // 04
        addiu(T2, ZERO, 7),                             // 08
        r(0x18, T1, T2, 0, 0),                          // 0c mult
        r(0x12, 0, 0, T3, 0),                           // 10 mflo
        r(0x10, 0, 0, T4, 0),                           // 14 mfhi
        r(0x1a, T2, ZERO, 0, 0),                        // 18 div by zero
        r(0x12, 0, 0, A0, 0),                           // 1c mflo
        sw(T1, 0, T0),                                  // 20
        mem(0x20, T5, 0, T0),                           // 24 lb
        mem(0x22, A1, 3, T0),                           // 28 lwl
        mem(0x26, A1, 0, T0),                           // 2c lwr
        lui(AT, 0x1f80),                                // 30
        mem(0x23, V0, 0x1070, AT),                      // 34 lw from I/O: on the target
        beq(ZERO, ZERO, 2),                             // 38 -> 0x44
        mem(0x23, V1, 0, T0),                           // 3c delay slot load
        addiu(A0, A0, 100),                             // 40 skipped
        (3 << 26) | ((BASE + 0x54) >> 2 & 0x03ff_ffff), // 44 jal 0x54
        r(0x21, V1, T1, A2, 0),                         // 48 addu (slot)
        r(0x2b, T1, T2, A3, 0),                         // 4c sltu
        brk(4, 0),                                      // 50 exit
        r(0x00, 0, A2, A2, 3),                          // 54 sll
        JR_RA,                                          // 58
        r(0x02, 0, A2, A3, 1),                          // 5c srl (slot)
    ]
}

/// PC after each `s` and the full `g` register dump, and the CONTs sent.
fn step_trace(sim: bool, steps: usize) -> (Vec<(u32, String)>, usize, usize) {
    let rig = rig_sim(&step_program(), sim);
    let mut g = Rsp::connect(rig.port);
    g.cmd("qSupported:swbreak+");
    let mark = cmd_count(&rig.stats);
    let mut trace = Vec::new();
    for _ in 0..steps {
        assert!(is_trap(&g.cmd("s")));
        trace.push((g.pc(), g.cmd("g")));
    }
    let (conts, cmds) = {
        let st = rig.stats.lock().expect("stats");
        let cmds = &st.cmds[mark..];
        let mut kinds: Vec<(u16, usize)> = Vec::new();
        for &c in cmds {
            match kinds.iter_mut().find(|k| k.0 == c) {
                Some(k) => k.1 = k.1.saturating_add(1),
                None => kinds.push((c, 1)),
            }
        }
        eprintln!("sim={sim}: (command type, count) {kinds:?}");
        (cmds.iter().filter(|&&c| c == CONT).count(), cmds.len())
    };
    // a0 holds div-by-zero's LO: exit code 0xffffffff.
    assert_eq!(g.cmd("c"), "Wff");
    let (_, code) = rig.server.join().expect("server thread");
    assert_eq!(code, Some(u32::MAX));
    (trace, conts, cmds)
}

#[test]
fn rsp_step_simulated_matches_real_step() {
    const STEPS: usize = 19;
    let (real, real_conts, real_cmds) = step_trace(false, STEPS);
    let (sim, sim_conts, sim_cmds) = step_trace(true, STEPS);
    for (n, (a, b)) in real.iter().zip(sim.iter()).enumerate() {
        assert_eq!(a, b, "step {n}: real vs simulated");
    }
    assert_eq!(
        real.last().map(|t| t.0),
        Some(BASE + 0x50),
        "ends on the exit"
    );
    eprintln!(
        "{STEPS} steps: real {real_conts} CONT / {real_cmds} commands, \
         simulated {sim_conts} CONT / {sim_cmds} commands"
    );
    assert_eq!(real_conts, STEPS);
    // Only the I/O load runs on the target.
    assert_eq!(sim_conts, 1);
    assert!(sim_cmds * 2 < real_cmds, "{sim_cmds} vs {real_cmds}");
}

/// Stores a word at 0x80200100, 2 MiB above 0x80000100, then exits 42.
fn mirror_store_program() -> Vec<u32> {
    vec![
        lui(T0, 0x8020),
        addiu(T1, ZERO, 7),
        sw(T1, 0x100, T0), // 08
        addiu(A0, ZERO, 42),
        brk(4, 0),
    ]
}

/// A watch on 0x80000100 fires on a store through its mirror 0x80200100
/// when 2 MiB is installed, and not when 8 MiB is (no mirror there).
#[test]
fn rsp_watch_matches_ram_mirrors() {
    let rig = rig_with(&mirror_store_program(), 2 << 20);
    let mut g = Rsp::connect(rig.port);
    g.cmd("qSupported:swbreak+");
    assert_eq!(g.cmd("Z2,80000100,4"), "OK");
    let r = g.cmd("c");
    assert!(r.starts_with("T05") && r.contains("watch:80000100"), "{r}");
    assert_eq!(g.pc(), BASE + 0x08);
    {
        let st = rig.stats.lock().expect("stats");
        assert!(
            st.set_bps.contains(&(2, 0x8000_0100, 0x1f9f_fffc)),
            "{:x?}",
            st.set_bps
        );
    }
    // The sentinel the probe flipped is back.
    assert_eq!(g.cmd("ma0000000,4"), "00000000");
    assert_eq!(g.cmd("D"), "OK");
    rig.server.join().expect("server thread");

    let rig = rig_with(&mirror_store_program(), 8 << 20);
    let mut g = Rsp::connect(rig.port);
    g.cmd("qSupported:swbreak+");
    assert_eq!(g.cmd("Z2,80000100,4"), "OK");
    assert_eq!(g.cmd("c"), "W2a");
    let (_, code) = rig.server.join().expect("server thread");
    assert_eq!(code, Some(42));
    let st = rig.stats.lock().expect("stats");
    assert!(
        st.set_bps.contains(&(2, 0x8000_0100, 0x1fff_fffc)),
        "{:x?}",
        st.set_bps
    );
}

/// Console text printed while the target runs reaches gdb as `O` packets
/// before the stop reply.
#[test]
fn rsp_console_text_as_o_packets() {
    let rig = rig(&print_program(b"hi\n"));
    let mut g = Rsp::connect(rig.port);
    g.cmd("qSupported:swbreak+");
    let mut got = String::new();
    let mut r = g.cmd("c");
    while let Some(hex) = r.strip_prefix('O') {
        got.push_str(hex);
        r = g.reply();
    }
    assert_eq!(got, "68690a", "O packets before the stop");
    assert_eq!(r, "W2a");
    let (_, code) = rig.server.join().expect("server thread");
    assert_eq!(code, Some(42));
}

/// A gdb slow to ack the `O` packets (a stalled process on a loaded
/// machine) still gets to ack the stop reply. The stub waits for the acks
/// it is owed before closing; closing on a timer instead would meet the
/// late ack with RST, and the ack after it would fail with EPIPE.
#[test]
fn rsp_late_acks_after_exit() {
    let rig = rig(&print_program(
        b"hi
",
    ));
    let mut g = Rsp::connect(rig.port);
    g.cmd("qSupported:swbreak+");
    g.send("c");
    let mut r = g.recv();
    assert!(r.starts_with('O'), "{r}");
    // Longer than any timer the stub could reasonably close on.
    std::thread::sleep(Duration::from_millis(1000));
    g.ack();
    let mut got = String::new();
    while let Some(hex) = r.strip_prefix('O') {
        got.push_str(hex);
        r = g.reply();
    }
    assert_eq!(got, "68690a", "O packets before the stop");
    assert_eq!(r, "W2a");
    let (_, code) = rig.server.join().expect("server thread");
    assert_eq!(code, Some(42));
}

/// gdb-multiarch shows the target's console text. Opt in: PSXMON_GDB_E2E=1.
#[test]
fn gdb_multiarch_shows_console_text() {
    if std::env::var_os("PSXMON_GDB_E2E").is_none() {
        eprintln!("skipped: set PSXMON_GDB_E2E=1 to run gdb-multiarch");
        return;
    }
    let rig = rig(&print_program(b"target: hello\n"));
    let target = format!("target remote 127.0.0.1:{}", rig.port);
    let out = std::process::Command::new("gdb-multiarch")
        .args(["--batch", "-nx"])
        .args(["-ex", "set architecture mips:3000"])
        .args(["-ex", "set endian little"])
        .args(["-ex", &target])
        .args(["-ex", "continue"])
        .output()
        .expect("run gdb-multiarch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // gdb --batch writes the target's output to its stderr.
    assert!(
        format!("{stdout}{stderr}").contains("target: hello"),
        "{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("exited with code 052"),
        "{stdout}\n{stderr}"
    );
    let (_, code) = rig.server.join().expect("server thread");
    assert_eq!(code, Some(42));
}

/// gdb-multiarch against the sim-backed server. Opt in: PSXMON_GDB_E2E=1.
#[test]
fn gdb_multiarch_end_to_end() {
    if std::env::var_os("PSXMON_GDB_E2E").is_none() {
        eprintln!("skipped: set PSXMON_GDB_E2E=1 to run gdb-multiarch");
        return;
    }
    let rig = rig(&main_program());
    let target = format!("target remote 127.0.0.1:{}", rig.port);
    let out = std::process::Command::new("gdb-multiarch")
        .args(["--batch", "-nx"])
        .args(["-ex", "set architecture mips:3000"])
        .args(["-ex", "set endian little"])
        .args(["-ex", "set debug remote 1"])
        .args(["-ex", &target])
        .args(["-ex", "info registers pc"])
        .args(["-ex", "x/4x 0x80010000"])
        .args(["-ex", "break *0x80010014"])
        .args(["-ex", "continue"])
        .args(["-ex", "info registers pc"])
        .args(["-ex", "stepi"])
        .args(["-ex", "info registers pc t3 t4"])
        .args(["-ex", "break *0xbfc00100"])
        .args(["-ex", "continue"])
        .args(["-ex", "info registers pc v0"])
        .args(["-ex", "detach"])
        .output()
        .expect("run gdb-multiarch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if let Ok(path) = std::env::var("PSXMON_GDB_E2E_LOG") {
        std::fs::write(path, format!("{stdout}\n----\n{stderr}")).expect("log");
    }
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("0x80010000"), "{stdout}");
    assert!(stdout.contains("0x3c088002"), "x/4x: {stdout}");
    assert!(stdout.contains("0x80010014"), "breakpoint: {stdout}");
    assert!(stdout.contains("0x80010020"), "stepi over bne: {stdout}");
    assert!(
        stdout.contains("pc: 0xbfc00100"),
        "ROM breakpoint: {stdout}"
    );
    assert!(
        stderr.contains("$Z1,bfc00100,4"),
        "break in ROM became Z1: {stderr}"
    );
    let (reason, _) = rig.server.join().expect("server thread");
    assert!(matches!(reason, DisconnectReason::Disconnect));
}

#[test]
fn rsp_ctrl_c_is_accepted_and_ignored() {
    // `b .` forever: the sim's interpreter runs out its budget and hangs.
    let rig = rig(&[beq(ZERO, ZERO, -1), NOP]);
    let mut g = Rsp::connect(rig.port);
    g.cmd("qSupported:swbreak+");
    g.s.write_all(b"$c#63").expect("send c");
    assert_eq!(g.byte(), b'+');
    g.s.write_all(&[0x03]).expect("send ^C");
    // No stop reply: the monitor cannot be interrupted.
    g.s.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let mut b = [0u8; 1];
    let r = g.s.read(&mut b);
    assert!(
        matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut),
        "got {r:?} {b:?}"
    );
    assert!(!rig.server.is_finished(), "server still waiting for a stop");
}
