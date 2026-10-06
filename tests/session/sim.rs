//! A fake monitor for tests: speaks the SIO1 byte-stream protocol the way
//! monitor.c and transport.c do, over the in-memory transport, with 2 MiB of
//! RAM (or 4 or 8) repeating over the 8 MiB RAM window, a register file, SET_BAUD with its two windows, and a scripted
//! target program that prints, makes PCDRV breaks and exits, or an R3000
//! subset interpreter with the cop0 debug unit (SET_BP / CLR_BP) and a ROM.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use psxmon::frame::{bytes_to_words, encode_frame, fletcher, u32_words, word_u32, words_to_bytes};
use psxmon::lz4;
use psxmon::proto::*;
use psxmon::session::deadline_after;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::{Instant, timeout_at};

/// Installed RAM by default.
pub const RAM_SIZE: usize = 2 << 20;
/// The physical RAM window the BIOS maps: installed RAM repeats over it.
pub const RAM_WINDOW: usize = 8 << 20;
/// Memory control RAM_SIZE register, and the value the BIOS leaves in it
/// (the 8 MiB window).
pub const RAM_SIZE_REG: u32 = 0x1f80_1060;
pub const RAM_SIZE_BIOS: u32 = 0x0000_0b88;
pub const RUN_SR: u32 = 0x4000_0404;
const EXIT_BREAK: u32 = 0x0004_000d;

// Register indices, as in REGS.
pub const V0: u16 = 2;
pub const V1: u16 = 3;
pub const A0: u16 = 4;
pub const A1: u16 = 5;
pub const A2: u16 = 6;
pub const A3: u16 = 7;
pub const GP: u16 = 28;
pub const SP: u16 = 29;
pub const FP: u16 = 30;

/// Physical base of the BIOS ROM.
pub const ROM_BASE: u32 = 0x1fc0_0000;
/// PCSX-Redux's debug console port: a byte stored here is console text.
pub const TTY_PORT: u32 = 0x1f80_2080;

/// The cop0 debug unit as the monitor drives it (PROTOCOL.md section 11).
#[derive(Default, Debug, Clone, Copy)]
pub struct DebugUnit {
    /// PCE.
    pub exec: bool,
    /// DR (bit 0) and DW (bit 1), with DAE.
    pub data: u16,
    pub bpc: u32,
    pub bpcm: u32,
    pub bda: u32,
    pub bdam: u32,
    pub watch_addr: u32,
}

pub struct Machine {
    pub ram: Vec<u8>,
    /// BIOS ROM contents at [`ROM_BASE`]; writes do not reach it.
    pub rom: Vec<u8>,
    pub regs: [u32; NUM_REGS],
    pub dbg: DebugUnit,
    /// Bytes stored to [`TTY_PORT`], sent as console text before the next
    /// step's outcome.
    pub tty: Vec<u8>,
    /// The memory control RAM_SIZE register.
    pub ram_size_reg: u32,
}

impl Machine {
    /// Offset in `ram` of a RAM address: any address in the 8 MiB window,
    /// wrapped to the installed size.
    fn phys(&self, addr: u32) -> Option<usize> {
        usize::try_from(addr & 0x1fff_ffff)
            .ok()
            .filter(|&p| p < RAM_WINDOW)
            .and_then(|p| p.checked_rem(self.ram.len()))
    }

    /// Byte `i` of the RAM_SIZE register, for an address on it.
    fn reg_off(addr: u32) -> Option<usize> {
        (addr & 0x1fff_ffff)
            .checked_sub(RAM_SIZE_REG)
            .and_then(|o| usize::try_from(o).ok())
            .filter(|&o| o < 4)
    }

    fn rom_off(addr: u32) -> Option<usize> {
        (addr & 0x1fff_ffff)
            .checked_sub(ROM_BASE)
            .and_then(|o| usize::try_from(o).ok())
    }

    fn byte(&self, at: u32) -> u8 {
        if let Some(i) = Self::reg_off(at) {
            return self.ram_size_reg.to_le_bytes()[i];
        }
        self.phys(at)
            .and_then(|p| self.ram.get(p))
            .or_else(|| Self::rom_off(at).and_then(|o| self.rom.get(o)))
            .copied()
            .unwrap_or(0)
    }

    // Byte addresses advance in the 32-bit address space, which wraps.
    pub fn read(&self, addr: u32, len: usize) -> Vec<u8> {
        let mut at = addr;
        (0..len)
            .map(|_| {
                let b = self.byte(at);
                at = at.wrapping_add(1);
                b
            })
            .collect()
    }

    pub fn read32(&self, addr: u32) -> u32 {
        let b = self.read(addr, 4);
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    pub fn write(&mut self, addr: u32, data: &[u8]) {
        let mut at = addr;
        for &b in data {
            if let Some(i) = Self::reg_off(at) {
                let mut r = self.ram_size_reg.to_le_bytes();
                r[i] = b;
                self.ram_size_reg = u32::from_le_bytes(r);
            } else if let Some(slot) = self.phys(at).and_then(|p| self.ram.get_mut(p)) {
                *slot = b;
            }
            at = at.wrapping_add(1);
        }
    }

    pub fn reg(&self, index: u16) -> u32 {
        self.regs.get(usize::from(index)).copied().unwrap_or(0)
    }

    /// r0 stays 0.
    pub fn set(&mut self, index: u16, value: u32) {
        if index == 0 {
            return;
        }
        if let Some(r) = self.regs.get_mut(usize::from(index)) {
            *r = value;
        }
    }
}

/// What the target does next.
pub enum Step {
    /// Console text through the tty device (0x00 bytes are dropped).
    Tty(Vec<u8>),
    /// A software `break` at the address in the PC register.
    Break(u32),
    /// A debug-unit stop at the PC register: the exec breakpoint (or a
    /// `break` in a delay slot) when `data` is false, else the data watch.
    Hw { data: bool },
    /// An exception the monitor reports as FAULT, ExcCode given, at PC.
    Fault(u32),
    /// Spin forever.
    Hang,
}

pub trait Program: Send {
    /// Called on RUN (fresh start, regs as RUN left them) and on every
    /// resume past a break.
    fn step(&mut self, m: &mut Machine) -> Step;

    /// Whether CONT resumes at the PC register as it stands (a real CPU);
    /// scripted programs instead replay the break they stopped on when CONT
    /// finds the PC still on it.
    fn resumes_in_place(&self) -> bool {
        false
    }
}

#[derive(Clone)]
pub struct SimConfig {
    pub caps: u16,
    pub bios: u32,
    /// Report `break 4, 0` as STOPPED EXIT with the code in `a`, as monitors
    /// before break-driven exit did.
    pub legacy_exit: bool,
    /// SET_BAUD window length.
    pub window: Duration,
    /// Switch to a rate the host can never match (to exercise the fallback).
    pub unreachable_rate: bool,
    /// The rate the sim listens at from the start (default: the host's).
    pub start_rate: Option<u32>,
    /// BIOS ROM contents.
    pub rom: Vec<u8>,
    /// Installed RAM in bytes, a divisor of the 8 MiB window.
    pub ram_size: usize,
    /// The RAM_SIZE register's value at start.
    pub ram_size_reg: u32,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            caps: CAP_LZ4,
            bios: 0xbf38df5e,
            legacy_exit: false,
            window: Duration::from_millis(400),
            unreachable_rate: false,
            start_rate: None,
            rom: Vec::new(),
            ram_size: RAM_SIZE,
            ram_size_reg: RAM_SIZE_BIOS,
        }
    }
}

/// What the sim saw, for assertions.
#[derive(Default, Debug, Clone)]
pub struct SimStats {
    pub lz4_frames: usize,
    pub plain_load_frames: usize,
    pub max_match: usize,
    pub errors_sent: Vec<u16>,
    pub rate: u32,
    /// Every command frame received (TYPE without the LZ4 flag), in order.
    pub cmds: Vec<u16>,
    /// SET_BP payloads: (kind, addr, mask).
    pub set_bps: Vec<(u16, u32, u32)>,
}

#[derive(Default)]
struct Lz4State {
    active: bool,
    dest: u32,
    consumed: u32,
    comp: Vec<u8>,
}

pub struct Sim {
    io: DuplexStream,
    rx: VecDeque<u8>,
    rate: u32,
    host_rate: Arc<AtomicU32>,
    cfg: SimConfig,
    m: Machine,
    ctx: bool,
    epc: u32,
    last_break: u32,
    program: Box<dyn Program>,
    lz: Lz4State,
    stats: Arc<Mutex<SimStats>>,
}

impl Sim {
    pub fn new(
        io: DuplexStream,
        host_rate: Arc<AtomicU32>,
        cfg: SimConfig,
        program: Box<dyn Program>,
    ) -> (Sim, Arc<Mutex<SimStats>>) {
        let rate = cfg
            .start_rate
            .unwrap_or_else(|| host_rate.load(Ordering::SeqCst));
        let stats = Arc::new(Mutex::new(SimStats {
            rate,
            ..Default::default()
        }));
        let rom = cfg.rom.clone();
        let (ram_size, ram_size_reg) = (cfg.ram_size, cfg.ram_size_reg);
        let sim = Sim {
            io,
            rx: VecDeque::new(),
            rate,
            host_rate,
            cfg,
            m: Machine {
                ram: vec![0; ram_size],
                rom,
                regs: [0; NUM_REGS],
                dbg: DebugUnit::default(),
                tty: Vec::new(),
                ram_size_reg,
            },
            ctx: false,
            epc: 0,
            last_break: 0,
            program,
            lz: Lz4State::default(),
            stats: stats.clone(),
        };
        (sim, stats)
    }

    fn stats(&self) -> std::sync::MutexGuard<'_, SimStats> {
        self.stats.lock().expect("sim stats lock")
    }

    fn count(&self, field: impl FnOnce(&mut SimStats) -> &mut usize) {
        let mut st = self.stats();
        let n = field(&mut st);
        *n = n.saturating_add(1);
    }

    fn in_sync(&self) -> bool {
        self.host_rate.load(Ordering::SeqCst) == self.rate
    }

    /// Next byte from the host, or None at `deadline` / end of link. Bytes
    /// sent at a rate the sim is not on are lost.
    async fn byte_until(&mut self, deadline: Option<Instant>) -> Option<u8> {
        loop {
            if let Some(b) = self.rx.pop_front() {
                if self.in_sync() {
                    return Some(b);
                }
                continue;
            }
            let mut buf = [0u8; 4096];
            let n = match deadline {
                Some(d) => timeout_at(d, self.io.read(&mut buf)).await.ok()?.ok()?,
                None => self.io.read(&mut buf).await.ok()?,
            };
            if n == 0 {
                return None;
            }
            self.rx.extend(buf.get(..n)?);
        }
    }

    async fn byte(&mut self) -> Option<u8> {
        self.byte_until(None).await
    }

    async fn word(&mut self) -> Option<u16> {
        let lo = self.byte().await?;
        let hi = self.byte().await?;
        Some(u16::from_le_bytes([lo, hi]))
    }

    async fn put(&mut self, bytes: &[u8]) {
        if self.in_sync() {
            // A closed link just ends the test's conversation.
            self.io.write_all(bytes).await.ok();
        }
    }

    async fn send_frame(&mut self, ty: u16, payload: &[u16]) {
        let wire = encode_frame(ty, payload).expect("sim frames fit");
        self.put(&wire).await;
    }

    async fn send_status(&mut self, code: u16) {
        if code == 0 {
            self.send_frame(ACK, &[]).await;
        } else {
            self.stats().errors_sent.push(code);
            self.send_frame(ERROR, &[code]).await;
        }
    }

    /// transportRecvBegin + the payload + CKSUM. None at end of link.
    async fn recv_frame(&mut self) -> Option<(u16, Vec<u16>, bool)> {
        let (ty, len) = loop {
            if self.byte().await? != 0 {
                continue;
            }
            let mut lo;
            loop {
                lo = self.byte().await?;
                if lo != 0 {
                    break;
                }
            }
            let hi = self.byte().await?;
            if u16::from_le_bytes([lo, hi]) != SYNC {
                continue;
            }
            let t = self.word().await?;
            let l = self.word().await?;
            if l <= STREAM_MAX_LEN {
                break (t, l);
            }
        };
        let mut words = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            words.push(self.word().await?);
        }
        let lo = self.word().await?;
        let hi = self.word().await?;
        let ck = u32::from(lo) | (u32::from(hi) << 16);
        // Mandatory on a byte link: 0 never matches.
        let ok = ck == fletcher([ty, len].into_iter().chain(words.iter().copied()));
        Some((ty, words, ok))
    }

    /// awaitFrame: the exact bytes of `f` within one window.
    async fn await_exact(&mut self, f: &[u8]) -> bool {
        let deadline = deadline_after(self.cfg.window);
        let mut matched = 0usize;
        while let Some(b) = self.byte_until(Some(deadline)).await {
            if f.get(matched) == Some(&b) {
                matched = matched.saturating_add(1);
                if matched == f.len() {
                    return true;
                }
            } else {
                matched = usize::from(f.first() == Some(&b));
            }
        }
        false
    }

    pub async fn run(mut self) {
        // The monitor waits in the command loop from boot (HELLO is lost on SIO1).
        while let Some((ty, words, ok)) = self.recv_frame().await {
            if !self.command(ty, &words, ok).await {
                // A hung target: the link stays open and silent.
                std::future::pending::<()>().await;
            }
        }
    }

    /// One command; false when the target hangs for good.
    async fn command(&mut self, ty: u16, w: &[u16], ok: bool) -> bool {
        let base = ty & !LZ4_FLAG;
        self.stats().cmds.push(base);
        if base == WRITE_MEM || base == LOAD {
            let reply = if ty & LZ4_FLAG == 0 {
                self.count(|st| &mut st.plain_load_frames);
                let addr = word_u32(w, 0);
                let n = usize::try_from(word_u32(w, 2)).expect("len fits usize");
                let avail = w.len().saturating_sub(4).saturating_mul(2);
                let bytes = words_to_bytes(w, 4, n.min(avail));
                self.m.write(addr, &bytes); // before the checksum is known
                if ok { 0 } else { E_CKSUM }
            } else if self.cfg.caps & CAP_LZ4 != 0 {
                self.lz4_slice(w, ok)
            } else {
                E_BADCMD
            };
            self.send_status(reply).await;
            return true;
        }
        if !ok {
            self.send_status(E_CKSUM).await;
            return true;
        }
        if w.len() > CMD_MAX_WORDS {
            self.send_status(E_BADLEN).await;
            return true;
        }
        match ty {
            PING => {
                let mut p = vec![PROTO_VER, self.cfg.caps];
                p.extend(u32_words(&[self.cfg.bios]));
                self.send_frame(PONG, &p).await;
            }
            READ_MEM => self.read_mem(word_u32(w, 0), word_u32(w, 2)).await,
            GET_REGS => {
                let regs: Vec<u32> = (0..NUM_REGS)
                    .map(|i| {
                        if self.ctx || i == usize::from(REG_BADVADDR) {
                            self.regs_at(i)
                        } else {
                            0
                        }
                    })
                    .collect();
                self.send_frame(REGS, &u32_words(&regs)).await;
            }
            SET_REG => {
                let idx = w.first().copied().unwrap_or(0);
                let code = if usize::from(idx) >= NUM_REGS {
                    E_BADREG
                } else if !self.ctx {
                    E_BADSTATE
                } else {
                    if idx != 0 {
                        self.m.set(idx, word_u32(w, 1));
                    }
                    0
                };
                self.send_status(code).await;
            }
            RUN => {
                self.m.regs = [0; NUM_REGS];
                self.m.set(GP, word_u32(w, 2));
                self.m.set(SP, word_u32(w, 4));
                self.m.set(FP, word_u32(w, 4));
                self.m.set(REG_PC, word_u32(w, 0));
                self.m.set(REG_SR, RUN_SR);
                self.ctx = false;
                self.send_status(0).await;
                return self.execute(false).await;
            }
            CONT => {
                if !self.ctx {
                    self.send_status(E_BADSTATE).await;
                } else {
                    self.send_status(0).await;
                    // PC left on the break re-executes it.
                    let again = !self.program.resumes_in_place() && self.m.reg(REG_PC) == self.epc;
                    return self.execute(again).await;
                }
            }
            SET_BAUD => {
                let reload = w.first().copied().unwrap_or(0);
                if reload == 0 {
                    self.send_status(E_BADLEN).await;
                } else {
                    self.send_status(0).await;
                    self.try_rate(reload).await;
                }
            }
            SET_BP => {
                let kind = w.first().copied().unwrap_or(0);
                let (addr, mask) = (word_u32(w, 1), word_u32(w, 3));
                self.stats().set_bps.push((kind, addr, mask));
                let d = &mut self.m.dbg;
                let code = match kind {
                    0 => {
                        d.bpc = addr;
                        d.bpcm = mask;
                        d.exec = true;
                        0
                    }
                    1..=3 => {
                        d.bda = addr;
                        d.bdam = mask;
                        d.watch_addr = addr;
                        d.data |= kind;
                        0
                    }
                    _ => E_BADCMD,
                };
                self.send_status(code).await;
            }
            CLR_BP => {
                if w.first().copied().unwrap_or(0) == 0 {
                    self.m.dbg.exec = false;
                } else {
                    self.m.dbg.data = 0;
                }
                self.send_status(0).await;
            }
            STOP => self.send_status(0).await,
            _ => self.send_status(E_BADCMD).await,
        }
        true
    }

    fn regs_at(&self, i: usize) -> u32 {
        self.m.regs.get(i).copied().unwrap_or(0)
    }

    async fn read_mem(&mut self, addr: u32, len: u32) {
        let len = usize::try_from(len).expect("len fits usize");
        let mut off = 0usize;
        loop {
            let chunk = len.saturating_sub(off).min(CHUNK_BYTES);
            let at = addr.wrapping_add(u32::try_from(off).expect("offset fits u32"));
            let mut p = u32_words(&[u32::try_from(chunk).expect("chunk fits u32")]);
            p.extend(bytes_to_words(&self.m.read(at, chunk)));
            self.send_frame(DATA, &p).await;
            off = off.saturating_add(chunk);
            if off >= len {
                break;
            }
        }
    }

    fn lz4_slice(&mut self, w: &[u16], ok: bool) -> u16 {
        self.count(|st| &mut st.lz4_frames);
        if w.len() < 10 {
            self.lz.active = false;
            return E_BADLEN;
        }
        let [dest, raw_len, clen, off, nbytes] = [0, 2, 4, 6, 8].map(|i| word_u32(w, i));
        let mut bad = 0;
        if off == 0 {
            self.lz = Lz4State {
                active: true,
                dest,
                consumed: 0,
                comp: Vec::new(),
            };
        } else if !self.lz.active || off != self.lz.consumed {
            bad = E_BADSTATE;
        }
        let room = w.len().saturating_sub(10).saturating_mul(2);
        let n = usize::try_from(nbytes).expect("nbytes fits usize");
        if bad == 0 && (n > room || off.checked_add(nbytes).is_none_or(|end| end > clen)) {
            bad = E_BADLEN;
        }
        if bad == 0 {
            self.lz.comp.extend(words_to_bytes(w, 10, n));
        }
        if bad == 0 && !ok {
            bad = E_CKSUM;
        }
        if bad == 0 {
            self.lz.consumed = self.lz.consumed.saturating_add(nbytes);
            if self.lz.consumed == clen {
                let seqs = lz4::sequences(&self.lz.comp).unwrap_or_default();
                let mm = seqs.iter().map(|s| s.match_len).max().unwrap_or(0);
                {
                    let mut st = self.stats();
                    st.max_match = st.max_match.max(mm);
                }
                let want = usize::try_from(raw_len).expect("rawlen fits usize");
                match lz4::decompress(&self.lz.comp, RAM_SIZE) {
                    Ok(out) if out.len() == want => {
                        let dest = self.lz.dest;
                        self.m.write(dest, &out);
                    }
                    _ => bad = E_DECODE,
                }
                self.lz.active = false;
            }
        }
        if bad != 0 {
            self.lz.active = false;
        }
        bad
    }

    async fn try_rate(&mut self, reload: u16) {
        const PING_BYTES: [u8; 11] = [
            0x00, 0xaa, 0x55, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
        ];
        const CONFIRM_BYTES: [u8; 13] = [
            0x00, 0xaa, 0x55, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x06, 0x00,
        ];
        let old = self.rate;
        self.rate = if self.cfg.unreachable_rate {
            1
        } else {
            sio1_rate(reload)
        };
        if self.await_exact(&PING_BYTES).await {
            self.send_frame(PONG, &[PROTO_VER]).await;
            if self.await_exact(&CONFIRM_BYTES).await {
                self.send_frame(PONG, &[PROTO_VER]).await;
                let rate = self.rate;
                self.stats().rate = rate;
                return;
            }
        }
        self.rate = old;
    }

    /// Run the target until it stops (true) or hangs (false).
    async fn execute(&mut self, reexecute: bool) -> bool {
        let mut step = if reexecute {
            Step::Break(self.last_break)
        } else {
            self.program.step(&mut self.m)
        };
        loop {
            if !self.m.tty.is_empty() {
                let text = std::mem::take(&mut self.m.tty);
                self.put(&text).await;
            }
            match step {
                Step::Tty(bytes) => {
                    let bytes: Vec<u8> = bytes.into_iter().filter(|&b| b != 0).collect();
                    self.put(&bytes).await;
                }
                Step::Hang => return false,
                Step::Hw { data } => {
                    // The monitor writes DCIC 0 whichever unit fired.
                    let watch = self.m.dbg.watch_addr;
                    self.m.dbg.exec = false;
                    self.m.dbg.data = 0;
                    let (reason, a) = if data {
                        (STOP_DATA_WATCH, watch)
                    } else {
                        (STOP_BREAKPOINT, 0)
                    };
                    return self.stopped(reason, a, 0).await;
                }
                Step::Fault(code) => return self.stopped(STOP_FAULT, code, 0).await,
                Step::Break(insn) => {
                    self.last_break = insn;
                    let (reason, a) = if self.cfg.legacy_exit && insn == EXIT_BREAK {
                        (STOP_EXIT, self.m.reg(A0))
                    } else {
                        (STOP_BREAKPOINT, insn)
                    };
                    return self.stopped(reason, a, 0).await;
                }
            }
            step = self.program.step(&mut self.m);
        }
    }

    /// Enter HALTED at the PC register and send STOPPED.
    async fn stopped(&mut self, reason: u16, a: u32, b: u32) -> bool {
        self.ctx = true;
        self.epc = self.m.reg(REG_PC);
        self.m.set(REG_BADVADDR, 0);
        let mut p = vec![reason];
        p.extend(u32_words(&[self.epc, a, b]));
        self.send_frame(STOPPED, &p).await;
        true
    }
}

// ---- an R3000 subset, for debugger tests ----

/// What one instruction did besides its register and memory effects.
enum Effect {
    Seq,
    /// A branch or jump (it has a delay slot); Some(target) when taken.
    Branch(Option<u32>),
    Break,
    Watch,
    Fault(u32),
}

/// Runs the program in RAM (and ROM) from the PC register: enough of the
/// R3000 for the debugger tests, with delay slots, the debug unit, and
/// `break` in a delay slot reported the monitor's way (PROTOCOL.md 13).
pub struct Interp {
    /// Instructions to run per resume before the target counts as hung.
    pub budget: u32,
}

impl Default for Interp {
    fn default() -> Self {
        Interp { budget: 100_000 }
    }
}

/// mult, multu, div, divu (funct 0x18..0x1b) as PCSX-Redux computes them:
/// (LO, HI).
fn muldiv(funct: u32, rs: u32, rt: u32) -> (u32, u32) {
    match funct {
        0x18 => {
            let p = i64::from(rs.cast_signed())
                .wrapping_mul(i64::from(rt.cast_signed()))
                .cast_unsigned();
            halves(p)
        }
        0x19 => halves(u64::from(rs).wrapping_mul(u64::from(rt))),
        0x1a => {
            if rt == 0 {
                (
                    if rs & 0x8000_0000 != 0 {
                        1
                    } else {
                        0xffff_ffff
                    },
                    rs,
                )
            } else if rs == 0x8000_0000 && rt == 0xffff_ffff {
                (0x8000_0000, 0)
            } else {
                let (n, d) = (rs.cast_signed(), rt.cast_signed());
                (
                    n.checked_div(d).expect("no overflow").cast_unsigned(),
                    n.checked_rem(d).expect("no overflow").cast_unsigned(),
                )
            }
        }
        _ => {
            if rt == 0 {
                (0xffff_ffff, rs)
            } else {
                (
                    rs.checked_div(rt).expect("rt != 0"),
                    rs.checked_rem(rt).expect("rt != 0"),
                )
            }
        }
    }
}

/// (low, high) words of a 64-bit product.
fn halves(p: u64) -> (u32, u32) {
    (
        u32::try_from(p & 0xffff_ffff).expect("32 bits"),
        u32::try_from(p >> 32).expect("32 bits"),
    )
}

fn sext(imm: u32) -> u32 {
    i32::from(u16::try_from(imm & 0xffff).expect("16 bits").cast_signed()).cast_unsigned()
}

impl Interp {
    fn exec(m: &mut Machine, pc: u32, insn: u32) -> Effect {
        let op = insn >> 26;
        let rs_i = u16::try_from((insn >> 21) & 31).expect("5 bits");
        let rt_i = u16::try_from((insn >> 16) & 31).expect("5 bits");
        let rd_i = u16::try_from((insn >> 11) & 31).expect("5 bits");
        let (rs, rt) = (m.reg(rs_i), m.reg(rt_i));
        let imm = insn & 0xffff;
        let simm = sext(imm);
        let link = pc.wrapping_add(8);
        let target = pc.wrapping_add(4).wrapping_add(simm << 2);
        let cond = |t: bool| Effect::Branch(t.then_some(target));
        let watch = |m: &Machine, addr: u32, need: u16| {
            m.dbg.data & need != 0 && (addr ^ m.dbg.bda) & m.dbg.bdam == 0
        };
        match op {
            0 => {
                let sh = (insn >> 6) & 31;
                let v = match insn & 0x3f {
                    0x00 => rt.wrapping_shl(sh),
                    0x02 => rt.wrapping_shr(sh),
                    0x03 => rt.cast_signed().wrapping_shr(sh).cast_unsigned(),
                    0x04 => rt.wrapping_shl(rs & 31),
                    0x06 => rt.wrapping_shr(rs & 31),
                    0x07 => rt.cast_signed().wrapping_shr(rs & 31).cast_unsigned(),
                    0x08 => return Effect::Branch(Some(rs)),
                    0x09 => {
                        m.set(rd_i, link);
                        return Effect::Branch(Some(rs));
                    }
                    0x0d => return Effect::Break,
                    0x10 => m.reg(REG_HI),
                    0x12 => m.reg(REG_LO),
                    0x11 | 0x13 => {
                        m.set(if insn & 0x3f == 0x11 { REG_HI } else { REG_LO }, rs);
                        return Effect::Seq;
                    }
                    0x18..=0x1b => {
                        let (lo, hi) = muldiv(insn & 0x3f, rs, rt);
                        m.set(REG_LO, lo);
                        m.set(REG_HI, hi);
                        return Effect::Seq;
                    }
                    // Ov: the destination is left alone.
                    0x20 if (rs ^ rt) & 0x8000_0000 == 0
                        && (rs ^ rs.wrapping_add(rt)) & 0x8000_0000 != 0 =>
                    {
                        return Effect::Fault(12);
                    }
                    0x22 if (rs ^ rt) & 0x8000_0000 != 0
                        && (rs ^ rs.wrapping_sub(rt)) & 0x8000_0000 != 0 =>
                    {
                        return Effect::Fault(12);
                    }
                    0x20 | 0x21 => rs.wrapping_add(rt),
                    0x22 | 0x23 => rs.wrapping_sub(rt),
                    0x24 => rs & rt,
                    0x25 => rs | rt,
                    0x26 => rs ^ rt,
                    0x27 => !(rs | rt),
                    0x2a => u32::from(rs.cast_signed() < rt.cast_signed()),
                    0x2b => u32::from(rs < rt),
                    _ => return Effect::Fault(10),
                };
                m.set(rd_i, v);
                Effect::Seq
            }
            1 => {
                if rt_i & 0x1e == 0x10 {
                    m.set(31, link);
                }
                let neg = rs.cast_signed() < 0;
                cond(if rt_i & 1 != 0 { !neg } else { neg })
            }
            2 | 3 => {
                if op == 3 {
                    m.set(31, link);
                }
                Effect::Branch(Some(
                    (pc.wrapping_add(4) & 0xf000_0000) | ((insn & 0x03ff_ffff) << 2),
                ))
            }
            4 => cond(rs == rt),
            5 => cond(rs != rt),
            6 => cond(rs.cast_signed() <= 0),
            7 => cond(rs.cast_signed() > 0),
            8 if (rs ^ simm) & 0x8000_0000 == 0
                && (rs ^ rs.wrapping_add(simm)) & 0x8000_0000 != 0 =>
            {
                Effect::Fault(12)
            }
            8 | 9 => {
                m.set(rt_i, rs.wrapping_add(simm));
                Effect::Seq
            }
            0x0a => {
                m.set(rt_i, u32::from(rs.cast_signed() < simm.cast_signed()));
                Effect::Seq
            }
            0x0b => {
                m.set(rt_i, u32::from(rs < simm));
                Effect::Seq
            }
            0x0c => {
                m.set(rt_i, rs & imm);
                Effect::Seq
            }
            0x0d => {
                m.set(rt_i, rs | imm);
                Effect::Seq
            }
            0x0e => {
                m.set(rt_i, rs ^ imm);
                Effect::Seq
            }
            0x0f => {
                m.set(rt_i, imm << 16);
                Effect::Seq
            }
            0x22 | 0x26 => {
                // lwl / lwr, as PCSX-Redux's tables have them.
                const LWL_MASK: [u32; 4] = [0x00ff_ffff, 0x0000_ffff, 0x0000_00ff, 0];
                const LWL_SHIFT: [u32; 4] = [24, 16, 8, 0];
                const LWR_MASK: [u32; 4] = [0, 0xff00_0000, 0xffff_0000, 0xffff_ff00];
                const LWR_SHIFT: [u32; 4] = [0, 8, 16, 24];
                let addr = rs.wrapping_add(simm);
                if watch(m, addr, 1) {
                    return Effect::Watch;
                }
                let sh = usize::try_from(addr & 3).expect("2 bits");
                let mem = m.read32(addr & !3);
                let v = if op == 0x22 {
                    (rt & LWL_MASK[sh]) | (mem << LWL_SHIFT[sh])
                } else {
                    (rt & LWR_MASK[sh]) | (mem >> LWR_SHIFT[sh])
                };
                m.set(rt_i, v);
                Effect::Seq
            }
            0x2a | 0x2e => {
                // swl / swr: read-modify-write of the aligned word.
                const SWL_MASK: [u32; 4] = [0xffff_ff00, 0xffff_0000, 0xff00_0000, 0];
                const SWL_SHIFT: [u32; 4] = [24, 16, 8, 0];
                const SWR_MASK: [u32; 4] = [0, 0x0000_00ff, 0x0000_ffff, 0x00ff_ffff];
                const SWR_SHIFT: [u32; 4] = [0, 8, 16, 24];
                let addr = rs.wrapping_add(simm);
                if watch(m, addr, 2) {
                    return Effect::Watch;
                }
                let sh = usize::try_from(addr & 3).expect("2 bits");
                let mem = m.read32(addr & !3);
                let v = if op == 0x2a {
                    (rt >> SWL_SHIFT[sh]) | (mem & SWL_MASK[sh])
                } else {
                    (rt << SWR_SHIFT[sh]) | (mem & SWR_MASK[sh])
                };
                m.write(addr & !3, &v.to_le_bytes());
                Effect::Seq
            }
            0x20 | 0x21 | 0x23 | 0x24 | 0x25 => {
                let addr = rs.wrapping_add(simm);
                if watch(m, addr, 1) {
                    return Effect::Watch;
                }
                if (op == 0x21 || op == 0x25) && addr & 1 != 0 || op == 0x23 && addr & 3 != 0 {
                    return Effect::Fault(4); // AdEL
                }
                let v = match op {
                    0x20 => i32::from(m.read(addr, 1)[0].cast_signed()).cast_unsigned(),
                    0x24 => u32::from(m.read(addr, 1)[0]),
                    0x21 | 0x25 => {
                        let b = m.read(addr, 2);
                        let h = u32::from(u16::from_le_bytes([b[0], b[1]]));
                        if op == 0x21 { sext(h) } else { h }
                    }
                    _ => m.read32(addr),
                };
                m.set(rt_i, v);
                Effect::Seq
            }
            0x28 | 0x29 | 0x2b => {
                let addr = rs.wrapping_add(simm);
                if watch(m, addr, 2) {
                    return Effect::Watch;
                }
                if op == 0x29 && addr & 1 != 0 || op == 0x2b && addr & 3 != 0 {
                    return Effect::Fault(5); // AdES
                }
                let n = match op {
                    0x28 => 1,
                    0x29 => 2,
                    _ => 4,
                };
                if op == 0x28 && addr & 0x1fff_ffff == TTY_PORT {
                    m.tty.push(rt.to_le_bytes()[0]);
                }
                m.write(addr, &rt.to_le_bytes()[..n]);
                Effect::Seq
            }
            _ => Effect::Fault(10),
        }
    }
}

impl Interp {
    /// One step as psxmon's stepper takes it: the instruction at PC and, for
    /// a branch or jump, its delay slot. Err with what stopped it instead
    /// (the registers may then be half updated).
    pub fn host_step(m: &mut Machine) -> Result<(), String> {
        let pc = m.reg(REG_PC);
        let insn = m.read32(pc);
        let next = match Self::exec(m, pc, insn) {
            Effect::Seq => pc.wrapping_add(4),
            Effect::Branch(t) => {
                let slot = pc.wrapping_add(4);
                match Self::exec(m, slot, m.read32(slot)) {
                    Effect::Seq => {}
                    Effect::Branch(_) => return Err("branch in delay slot".into()),
                    Effect::Break => return Err("break".into()),
                    Effect::Watch => return Err("watch".into()),
                    Effect::Fault(c) => return Err(format!("fault {c}")),
                }
                t.unwrap_or(pc.wrapping_add(8))
            }
            Effect::Break => return Err("break".into()),
            Effect::Watch => return Err("watch".into()),
            Effect::Fault(c) => return Err(format!("fault {c}")),
        };
        m.set(REG_PC, next);
        Ok(())
    }
}

impl Program for Interp {
    fn resumes_in_place(&self) -> bool {
        true
    }

    fn step(&mut self, m: &mut Machine) -> Step {
        let mut pc = m.reg(REG_PC);
        let mut npc = pc.wrapping_add(4);
        // The branch whose delay slot `pc` is, if it is one.
        let mut branch: Option<u32> = None;
        for _ in 0..self.budget {
            // An exception in a delay slot resumes at the branch (Cause.BD).
            let epc = branch.unwrap_or(pc);
            if m.dbg.exec && (pc ^ m.dbg.bpc) & m.dbg.bpcm == 0 {
                m.set(REG_PC, epc);
                return Step::Hw { data: false };
            }
            let insn = m.read32(pc);
            let mut next = npc.wrapping_add(4);
            let mut is_branch = false;
            match Self::exec(m, pc, insn) {
                Effect::Seq => {}
                Effect::Branch(t) => {
                    is_branch = true;
                    if let Some(t) = t {
                        next = t;
                    }
                }
                Effect::Break => {
                    m.set(REG_PC, epc);
                    // The monitor reads the word at EPC, which for a delay
                    // slot is the branch: not a `break`, so a hardware stop.
                    return if branch.is_some() {
                        Step::Hw { data: false }
                    } else {
                        Step::Break(insn)
                    };
                }
                Effect::Watch => {
                    m.set(REG_PC, epc);
                    return Step::Hw { data: true };
                }
                Effect::Fault(code) => {
                    m.set(REG_PC, epc);
                    return Step::Fault(code);
                }
            }
            m.set(0, 0);
            branch = is_branch.then_some(pc);
            pc = npc;
            npc = next;
        }
        Step::Hang
    }
}

/// Start a sim on a fresh in-memory link; returns the host end, at 115200.
pub fn start(
    cfg: SimConfig,
    program: Box<dyn Program>,
) -> (psxmon::MemTransport, Arc<Mutex<SimStats>>) {
    let (host, dev, rate) = psxmon::MemTransport::pair(115200);
    let (sim, stats) = Sim::new(dev, rate, cfg, program);
    tokio::spawn(sim.run());
    (host, stats)
}

// ---- target programs ----

fn brk(m: &mut Machine, at: u32, code1: u32, code2: u32) -> Step {
    m.set(REG_PC, at);
    Step::Break(BreakCode { code1, code2 }.encode())
}

fn exit(m: &mut Machine, at: u32, code: u32) -> Step {
    m.set(A0, code);
    brk(m, at, 4, 0)
}

/// PCDRV result the way the pcdrv.h wrappers read it: v1 when v0 is 0.
fn pcret(m: &Machine) -> i32 {
    if m.reg(V0) == 0 {
        m.reg(V1).cast_signed()
    } else {
        -1
    }
}

/// Checks that RUN set pc/gp/sp and that `expect` is in memory at `addr`,
/// prints, then exits with `code` (0xdead if anything was off) from a break
/// at `exit_at`.
pub struct CheckAndExit {
    pub addr: u32,
    pub expect: Vec<u8>,
    pub pc: u32,
    pub gp: u32,
    pub sp: u32,
    pub code: u32,
    pub exit_at: u32,
    pub started: bool,
}

impl Program for CheckAndExit {
    fn step(&mut self, m: &mut Machine) -> Step {
        if !self.started {
            self.started = true;
            return Step::Tty(b"target: hello\n".to_vec());
        }
        let good = m.read(self.addr, self.expect.len()) == self.expect
            && m.reg(REG_PC) == self.pc
            && m.reg(GP) == self.gp
            && m.reg(SP) == self.sp
            && m.reg(FP) == self.sp
            && m.reg(REG_SR) == RUN_SR;
        let code = if good { self.code } else { 0xdead };
        exit(m, self.exit_at, code)
    }
}

/// The farmjob test program, in Rust: read IN.TXT via PCDRV, write it back
/// upper-cased to OUT.TXT, exit with the byte count (0xbad on failure).
pub struct Farmjob {
    phase: u32,
    fd: i32,
    n: i32,
}

impl Farmjob {
    pub const NAME: u32 = 0x800f_0000;
    pub const BUF: u32 = 0x8010_0000;
    pub const BUF_SIZE: u32 = 32768;

    pub fn new() -> Self {
        Farmjob {
            phase: 0,
            fd: -1,
            n: 0,
        }
    }

    fn bytes(&self) -> usize {
        usize::try_from(self.n).expect("byte count checked non-negative")
    }
}

impl Program for Farmjob {
    fn step(&mut self, m: &mut Machine) -> Step {
        let phase = self.phase;
        self.phase = phase.saturating_add(1);
        // A distinct fake PC per break.
        let at = phase
            .checked_mul(8)
            .and_then(|o| 0x8001_0100u32.checked_add(o))
            .expect("few phases");
        let bad = |m: &mut Machine| exit(m, 0x8001_0ff0, 0xbad);
        match phase {
            0 => Step::Tty(b"farmjob: start\n".to_vec()),
            1 => brk(m, at, 0, PC_INIT),
            2 => {
                if m.reg(V0) != 0 {
                    return bad(m);
                }
                m.write(Self::NAME, b"IN.TXT\0");
                m.set(A0, Self::NAME);
                m.set(A2, 0);
                brk(m, at, 0, PC_OPEN)
            }
            3 => {
                self.fd = pcret(m);
                if self.fd < 0 {
                    return bad(m);
                }
                m.set(A1, self.fd.cast_unsigned());
                m.set(A2, Self::BUF_SIZE);
                m.set(A3, Self::BUF);
                brk(m, at, 0, PC_READ)
            }
            4 => {
                self.n = pcret(m);
                m.set(A0, self.fd.cast_unsigned());
                brk(m, at, 0, PC_CLOSE)
            }
            5 => {
                if m.reg(V0) != 0 || self.n < 0 {
                    return bad(m);
                }
                let data = m.read(Self::BUF, self.bytes()).to_ascii_uppercase();
                m.write(Self::BUF, &data);
                m.write(Self::NAME, b"OUT.TXT\0");
                m.set(A0, Self::NAME);
                m.set(A2, 0);
                brk(m, at, 0, PC_CREAT)
            }
            6 => {
                self.fd = pcret(m);
                if self.fd < 0 {
                    return bad(m);
                }
                m.set(A1, self.fd.cast_unsigned());
                m.set(A2, self.n.cast_unsigned());
                m.set(A3, Self::BUF);
                brk(m, at, 0, PC_WRITE)
            }
            7 => {
                if pcret(m) != self.n {
                    return bad(m);
                }
                m.set(A0, self.fd.cast_unsigned());
                brk(m, at, 0, PC_CLOSE)
            }
            8 => {
                if m.reg(V0) != 0 {
                    return bad(m);
                }
                Step::Tty(format!("farmjob: {} bytes\n", self.n).into_bytes())
            }
            _ => exit(m, at, self.n.cast_unsigned()),
        }
    }
}

/// Tries to PCcreat a name outside the jail, then exits with the result.
pub struct JailProbe {
    pub name: &'static [u8],
    pub done: bool,
}

impl Program for JailProbe {
    fn step(&mut self, m: &mut Machine) -> Step {
        if !self.done {
            self.done = true;
            let mut name = self.name.to_vec();
            name.push(0);
            m.write(Farmjob::NAME, &name);
            m.set(A0, Farmjob::NAME);
            return brk(m, 0x8001_0000, 0, PC_CREAT);
        }
        let r = pcret(m).cast_unsigned();
        exit(m, 0x8001_0010, r)
    }
}

pub struct Hang;

impl Program for Hang {
    fn step(&mut self, _m: &mut Machine) -> Step {
        Step::Hang
    }
}
