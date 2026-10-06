//! `psxmon gdb`: a GDB remote (RSP) server that drives the monitor.
//!
//! gdb talks RSP to [`MonTarget`] through `gdbstub`; each target operation
//! is one or more monitor commands, run to completion on a private tokio
//! runtime (`block_on`), since gdbstub's event loop is blocking.
//!
//! How gdb's requests map onto the monitor (PROTOCOL.md sections 8 and 11):
//!
//! - Software breakpoints are gdb's own: Z0 is not offered, so gdb writes
//!   its `break 5` into RAM through `M`/`X`. The monitor stops on it with
//!   the PC on the break, which is where gdb expects a MIPS breakpoint.
//! - The one cop0 exec breakpoint serves Z1 in ROM (BIOS, EXP1). The memory
//!   map marks those regions read-only, so gdb's `break` there becomes Z1.
//! - The one data breakpoint serves Z2/Z3/Z4 (kinds 2/1/3).
//! - A hardware stop disarms the debug unit, so the session re-arms both
//!   with SET_BP before every CONT (see `Session::cont`).
//! - Single step is done here. Most steps are simulated on the host
//!   ([`crate::stepsim`]): the registers are kept here, loads and stores go
//!   through READ_MEM / WRITE_MEM, and nothing runs. Registers changed that
//!   way are written back (SET_REG) before the target next runs and when
//!   gdb goes away. A step the host cannot simulate is done on the target:
//!   decode the instruction at PC, plant a `break` at the successor in RAM
//!   (or use the exec breakpoint for a successor in ROM), CONT, and put
//!   everything back at the stop. [`STEP_SIM_ENV`] set to `0` (or
//!   `psxmon gdb --real-step`) makes every step a real one.
//! - PCDRV calls and `break 4, 0` exits are served while the target runs,
//!   exactly as `psxmon run` does; gdb never sees them, except that an exit
//!   is reported as the process exiting.
//! - gdb's Ctrl-C sends STOP while the target runs, when the monitor has
//!   `CAP_STOP`. The monitor halts the target at its next interrupt and
//!   reports STOPPED INTERRUPT, which goes to gdb as SIGINT. STOP is sent
//!   again every [`STOP_RESEND`] until a stop comes, since one that crosses
//!   a stop on the wire is dropped by the halted monitor. A target that
//!   takes no interrupts cannot be stopped this way, and neither can one
//!   under a monitor without `CAP_STOP`: there the interrupt is ignored.
//! - Console text the target prints while it runs goes to gdb as `O`
//!   packets (gdb shows it as the program's output), and still to whatever
//!   sink the session had (stdout for `psxmon gdb`). gdbstub 0.7 only
//!   writes `O` inside a `monitor` command, so the event loop writes them
//!   itself while it waits for a stop, the one time RSP allows them. Text
//!   that arrives while the target is halted is held for the next resume.

use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use gdbstub::common::Signal;
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError};
use gdbstub::stub::{DisconnectReason, GdbStub, SingleThreadStopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::single_register_access::{
    SingleRegisterAccess, SingleRegisterAccessOps,
};
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, HwWatchpoint, HwWatchpointOps,
    WatchKind,
};
use gdbstub::target::ext::memory_map::{MemoryMap, MemoryMapOps};
use gdbstub::target::ext::target_description_xml_override::{
    TargetDescriptionXmlOverride, TargetDescriptionXmlOverrideOps,
};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::mips::reg::MipsCoreRegs;
use gdbstub_arch::mips::reg::id::MipsRegId;
use gdbstub_arch::mips::{Mips, MipsBreakpointKind};
use tokio::runtime::Runtime;

use crate::exe::Image;
use crate::mips::{self, Region};
use crate::pcdrv::PcdrvServer;
use crate::proto::*;
use crate::session::{
    HwBreak, LoadOptions, LoadStats, Session, SessionError, Stop, deadline_after,
};
use crate::stepsim::{self, Bus, Guards, Outcome, WatchRange};
use crate::transport::Transport;

/// How long each wait for a stop lasts before the gdb link is checked.
const POLL: Duration = Duration::from_millis(50);
/// How long a freshly loaded program gets to reach its entry break.
const START_WAIT: Duration = Duration::from_secs(5);
/// How long after a STOP with no stop it is sent again.
const STOP_RESEND: Duration = Duration::from_secs(1);
/// Console bytes per `O` packet (twice that in hex on the wire).
const O_CHUNK: usize = 512;
/// Most console text held for gdb; past it, newer text is dropped.
const O_HELD_MAX: usize = 64 << 10;
/// Longest wait for gdb's acks of the last packets when closing the link.
const CLOSE_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Environment variable that turns host-simulated stepping off when `0`.
pub const STEP_SIM_ENV: &str = "PSXMON_STEP_SIM";

/// Whether [`STEP_SIM_ENV`] leaves step simulation on (the default).
pub fn step_sim_from_env() -> bool {
    std::env::var(STEP_SIM_ENV).map_or(true, |v| v.trim() != "0")
}

/// `break 0x3ff, 0`: the word psxmon plants for a single step and at a
/// program's entry. Any other `break` is the program's or gdb's.
pub const STEP_BREAK: u32 = 0x03ff_000d;

/// Compare mask for the exec and data breakpoints: every address bit
/// except the segment (bits 29-31), so a breakpoint matches its address in
/// kuseg, kseg0 and kseg1 alike.
const SEGMENT_MASK: u32 = 0x1fff_ffff;

type Res<T> = std::result::Result<T, SessionError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Watch {
    addr: u32,
    len: u32,
    kind: WatchKind,
}

impl Watch {
    fn hw(&self) -> HwBreak {
        HwBreak {
            kind: match self.kind {
                WatchKind::Read => 1,
                WatchKind::Write => 2,
                WatchKind::ReadWrite => 3,
            },
            addr: self.addr,
            // len is a power of two.
            mask: !self.len.wrapping_sub(1) & SEGMENT_MASK,
        }
    }
}

/// A step in flight: the words planted in RAM, and the ROM address the
/// exec breakpoint was lent to.
#[derive(Debug, Default)]
struct StepState {
    planted: Vec<(u32, Vec<u8>)>,
    rom: Option<u32>,
}

#[derive(Debug)]
enum Pending {
    Halted,
    Running,
    Stepping(StepState),
    /// A stop to report without running (a step that cannot move).
    Report(SingleThreadStopReason<u32>),
}

/// The gdb-facing target: a monitor session and the debug state gdb set up.
pub struct MonTarget<T: Transport> {
    rt: Runtime,
    sess: Session<T>,
    pcdrv: Option<PcdrvServer>,
    /// Registers of the halted context as gdb sees them: read once per
    /// stop, then changed by simulated steps.
    regs: Option<[u32; NUM_REGS]>,
    /// What the monitor holds for the halted context; where it differs
    /// from `regs`, SET_REG is owed before the target runs.
    target_regs: [u32; NUM_REGS],
    /// gdb's hardware breakpoint (ROM only).
    rom_bp: Option<u32>,
    watch: Option<Watch>,
    pending: Pending,
    /// When STOP was last sent for gdb's interrupt, until the next stop.
    stop_sent: Option<Instant>,
    /// The target's exit code, once it has executed `break 4, 0`.
    pub exit_code: Option<u32>,
    /// Log stops, steps and breakpoint changes to stderr.
    pub verbose: bool,
    /// Console text not yet sent to gdb.
    gdb_text: Arc<Mutex<Vec<u8>>>,
    /// `O` packets sent since the last resume whose `+` gdbstub has not read.
    acks_owed: usize,
    /// Simulate steps on the host where possible (see [`crate::stepsim`]).
    pub step_sim: bool,
    /// Steps simulated and steps run on the target, for logs and tests.
    pub steps_simulated: u64,
    pub steps_real: u64,
}

/// The monitor's memory, for [`stepsim`].
struct MonBus<'a, T: Transport> {
    rt: &'a Runtime,
    sess: &'a mut Session<T>,
}

impl<T: Transport> Bus for MonBus<'_, T> {
    type Error = SessionError;

    fn read(&mut self, addr: u32, len: u32) -> Res<Vec<u8>> {
        let b = self.rt.block_on(self.sess.read_mem(addr, len))?;
        let n = usize::try_from(len).map_err(|_| SessionError::TooLarge("read"))?;
        match b.get(..n) {
            Some(s) => Ok(s.to_vec()),
            None => Err(SessionError::Other("short READ_MEM".into())),
        }
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Res<()> {
        self.rt.block_on(self.sess.write_mem(addr, data))
    }
}

impl<T: Transport> MonTarget<T> {
    /// A target over an attached session. `rt` runs the session's I/O and
    /// must not be the runtime the caller is inside of. The session's
    /// console sink keeps getting the target's text; gdb gets a copy.
    pub fn new(rt: Runtime, mut sess: Session<T>, pcdrv: Option<PcdrvServer>) -> Self {
        let gdb_text = Arc::new(Mutex::new(Vec::new()));
        let held = gdb_text.clone();
        let mut sink = sess.take_console();
        sess.set_console(Some(Box::new(move |bytes: &[u8]| {
            if let Some(sink) = sink.as_mut() {
                sink(bytes);
            }
            let mut held = held.lock().unwrap_or_else(PoisonError::into_inner);
            let room = O_HELD_MAX.saturating_sub(held.len());
            held.extend_from_slice(bytes.get(..room.min(bytes.len())).unwrap_or_default());
        })));
        MonTarget {
            rt,
            sess,
            pcdrv,
            regs: None,
            target_regs: [0; NUM_REGS],
            rom_bp: None,
            watch: None,
            pending: Pending::Halted,
            stop_sent: None,
            exit_code: None,
            verbose: false,
            gdb_text,
            acks_owed: 0,
            step_sim: step_sim_from_env(),
            steps_simulated: 0,
            steps_real: 0,
        }
    }

    /// Console text held for gdb, taken.
    fn take_gdb_text(&self) -> Vec<u8> {
        std::mem::take(&mut *self.gdb_text.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub fn session(&mut self) -> &mut Session<T> {
        &mut self.sess
    }

    pub fn runtime(&self) -> &Runtime {
        &self.rt
    }

    pub fn pcdrv_mut(&mut self) -> Option<&mut PcdrvServer> {
        self.pcdrv.as_mut()
    }

    fn log(&self, msg: impl FnOnce() -> String) {
        if self.verbose {
            eprintln!("psxmon gdb: {}", msg());
        }
    }

    /// Load `image` and leave it halted on its first instruction, with the
    /// registers RUN gives it. SET_REG needs a halted context, which a fresh
    /// monitor does not have, so psxmon plants [`STEP_BREAK`] at the entry,
    /// RUNs, and puts the original word back once it has stopped there.
    pub fn start_program(&mut self, image: &Image, opts: &LoadOptions) -> Res<Vec<LoadStats>> {
        let mut stats = Vec::new();
        for seg in &image.segments {
            stats.push(
                self.rt
                    .block_on(self.sess.load(seg.addr, &seg.data, opts))?,
            );
        }
        let pc = image.pc;
        let orig = self.rt.block_on(self.sess.read_mem(pc, 4))?;
        self.write(pc, &STEP_BREAK.to_le_bytes())?;
        self.rt.block_on(self.sess.run(pc, image.gp, image.sp))?;
        let r = self.rt.block_on(
            self.sess
                .run_until_stop(deadline_after(START_WAIT), self.pcdrv.as_mut()),
        )?;
        self.write(pc, &orig)?;
        match r.stop {
            Some(s) if s.reason == STOP_BREAKPOINT && s.a == STEP_BREAK && s.epc == pc => {}
            Some(s) => {
                return Err(SessionError::Other(format!(
                    "program did not stop at its entry 0x{pc:08x}: {} at 0x{:08x}",
                    s.reason_name(),
                    s.epc
                )));
            }
            None => {
                return Err(SessionError::Other(format!(
                    "program did not reach its entry 0x{pc:08x}"
                )));
            }
        }
        self.regs = None;
        Ok(stats)
    }

    /// Whether the monitor holds a halted context (GET_REGS is all zeros
    /// but BadVaddr without one).
    pub fn has_context(&mut self) -> Res<bool> {
        let regs = self.regs()?;
        Ok(regs
            .iter()
            .enumerate()
            .any(|(i, &v)| i != usize::from(REG_BADVADDR) && v != 0))
    }

    /// Serve one gdb connection until gdb detaches, kills, or the target
    /// exits. The target is left halted in every case.
    pub fn serve(&mut self, conn: TcpStream) -> Res<DisconnectReason> {
        let linger = conn.try_clone().ok();
        let gdb = GdbStub::new(conn);
        let r = gdb.run_blocking::<EventLoop<T>>(self);
        if let Some(sock) = linger {
            // gdbstub answers everything but `k` with a packet gdb acks.
            let last = usize::from(!matches!(r, Ok(DisconnectReason::Kill)));
            close_gently(&sock, self.acks_owed.saturating_add(last));
        }
        // Registers a simulated step changed go back to the monitor, so the
        // halted context is the one gdb last saw.
        let flushed = if self.exit_code.is_none() {
            self.flush_regs()
        } else {
            Ok(())
        };
        self.log(|| {
            format!(
                "steps: {} simulated, {} on the target",
                self.steps_simulated, self.steps_real
            )
        });
        match r {
            Ok(reason) => flushed.map(|()| reason),
            Err(e) => {
                if let Some(code) = self.exit_code {
                    // gdb may drop the link right after W.
                    let [low, ..] = code.to_le_bytes();
                    return Ok(DisconnectReason::TargetExited(low));
                }
                Err(SessionError::Other(format!("gdb session: {e}")))
            }
        }
    }

    fn regs(&mut self) -> Res<[u32; NUM_REGS]> {
        if let Some(r) = self.regs {
            return Ok(r);
        }
        let r = self.rt.block_on(self.sess.get_regs())?;
        self.regs = Some(r);
        self.target_regs = r;
        Ok(r)
    }

    /// SET_REG every register a simulated step changed.
    fn flush_regs(&mut self) -> Res<()> {
        let Some(regs) = self.regs else {
            return Ok(());
        };
        for (i, &v) in regs.iter().enumerate().skip(1) {
            if self.target_regs.get(i) != Some(&v) {
                let idx = u16::try_from(i).map_err(|_| SessionError::TooLarge("register index"))?;
                self.rt.block_on(self.sess.set_reg(idx, v))?;
                if let Some(slot) = self.target_regs.get_mut(i) {
                    *slot = v;
                }
            }
        }
        Ok(())
    }

    fn set_reg(&mut self, index: usize, value: u32) -> Res<()> {
        let idx = u16::try_from(index).map_err(|_| SessionError::TooLarge("register index"))?;
        self.rt.block_on(self.sess.set_reg(idx, value))?;
        let value = if index == 0 { 0 } else { value };
        if let Some(slot) = self.regs.as_mut().and_then(|r| r.get_mut(index)) {
            *slot = value;
        }
        if let Some(slot) = self.target_regs.get_mut(index) {
            *slot = value;
        }
        Ok(())
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Res<()> {
        self.rt.block_on(self.sess.write_mem(addr, data))
    }

    fn read_word(&mut self, addr: u32) -> Res<u32> {
        let b = self.rt.block_on(self.sess.read_mem(addr, 4))?;
        let w: [u8; 4] = b
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| SessionError::Other("short READ_MEM".into()))?;
        Ok(u32::from_le_bytes(w))
    }

    /// Point the session's debug-unit set at gdb's breakpoint and watch.
    fn sync_hw(&mut self) {
        self.sess.hw.exec = self.rom_bp.map(|addr| HwBreak {
            kind: 0,
            addr,
            mask: SEGMENT_MASK,
        });
        self.sess.hw.data = self.watch.map(|w| w.hw());
    }

    fn do_continue(&mut self) -> Res<()> {
        self.acks_owed = 0;
        self.flush_regs()?;
        self.sync_hw();
        self.regs = None;
        self.rt.block_on(self.sess.cont())?;
        self.pending = Pending::Running;
        Ok(())
    }

    /// What a simulated step must not run past: gdb's ROM breakpoint and
    /// its watch.
    fn guards(&self) -> Guards {
        Guards {
            exec: self.rom_bp.map(|a| (a, SEGMENT_MASK)),
            watch: self.watch.map(|w| WatchRange {
                addr: w.addr,
                len: w.len,
                read: matches!(w.kind, WatchKind::Read | WatchKind::ReadWrite),
                write: matches!(w.kind, WatchKind::Write | WatchKind::ReadWrite),
            }),
        }
    }

    /// Step on the host; false (nothing changed) when it has to be real.
    fn sim_step(&mut self, regs: [u32; NUM_REGS]) -> Res<bool> {
        let pc = regs.get(usize::from(REG_PC)).copied().unwrap_or(0);
        // With no halted context there is nothing to step (and nothing
        // SET_REG could write back).
        let ctx = regs
            .iter()
            .enumerate()
            .any(|(i, &v)| i != usize::from(REG_BADVADDR) && v != 0);
        if !ctx {
            return Ok(false);
        }
        let guards = self.guards();
        let mut new = regs;
        let mut bus = MonBus {
            rt: &self.rt,
            sess: &mut self.sess,
        };
        match stepsim::step(&mut new, &guards, &mut bus)? {
            Outcome::Done => {
                self.regs = Some(new);
                self.steps_simulated = self.steps_simulated.saturating_add(1);
                self.log(|| {
                    let to = new.get(usize::from(REG_PC)).copied().unwrap_or(0);
                    format!("step at 0x{pc:08x}: simulated -> 0x{to:08x}")
                });
                Ok(true)
            }
            Outcome::Fallback(why) => {
                self.log(|| format!("step at 0x{pc:08x}: on the target ({why})"));
                Ok(false)
            }
        }
    }

    fn do_step(&mut self) -> Res<()> {
        self.acks_owed = 0;
        let regs = self.regs()?;
        if self.step_sim && self.sim_step(regs)? {
            self.pending = Pending::Report(SingleThreadStopReason::DoneStep);
            return Ok(());
        }
        self.flush_regs()?;
        self.steps_real = self.steps_real.saturating_add(1);
        let pc = regs.get(usize::from(REG_PC)).copied().unwrap_or(0);
        let insn = self.read_word(pc)?;
        let next = mips::next_pc(pc, insn, &regs).addrs();
        if next.contains(&pc) {
            // A branch to itself: a break planted there would stop before
            // the branch ran, so report the step done without running it.
            self.log(|| format!("step at 0x{pc:08x}: branch to itself, not run"));
            self.pending = Pending::Report(SingleThreadStopReason::DoneStep);
            return Ok(());
        }
        self.sync_hw();
        let mut st = StepState::default();
        for &a in &next {
            match mips::region(a) {
                Some((Region::Rom, _)) if st.rom.is_none() => {
                    // Nothing else can run during one step, so gdb's own ROM
                    // breakpoint can give up the exec unit for it.
                    st.rom = Some(a);
                    self.sess.hw.exec = Some(HwBreak {
                        kind: 0,
                        addr: a,
                        mask: SEGMENT_MASK,
                    });
                }
                Some((Region::Ram, left)) if left >= 4 => {
                    let orig = self.rt.block_on(self.sess.read_mem(a, 4))?;
                    self.write(a, &STEP_BREAK.to_le_bytes())?;
                    st.planted.push((a, orig));
                }
                _ => self.log(|| format!("step at 0x{pc:08x}: cannot stop at 0x{a:08x}")),
            }
        }
        self.log(|| format!("step at 0x{pc:08x} (0x{insn:08x}) -> {next:08x?}"));
        self.regs = None;
        self.pending = Pending::Stepping(st);
        self.rt.block_on(self.sess.cont())
    }

    /// Put back what a step planted.
    fn end_step(&mut self, st: &StepState) -> Res<()> {
        for (a, orig) in &st.planted {
            self.write(*a, orig)?;
        }
        self.sync_hw();
        Ok(())
    }

    /// Wait up to [`POLL`] for the running target to stop, serving PCDRV.
    fn poll(&mut self) -> Res<Option<SingleThreadStopReason<u32>>> {
        let step = match std::mem::replace(&mut self.pending, Pending::Halted) {
            Pending::Halted => return Ok(None),
            Pending::Report(r) => return Ok(Some(r)),
            Pending::Running => None,
            Pending::Stepping(st) => Some(st),
        };
        let r = self.rt.block_on(
            self.sess
                .run_until_stop(deadline_after(POLL), self.pcdrv.as_mut()),
        );
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                if let Some(st) = &step {
                    // Best effort: the link may be gone.
                    let _ = self.end_step(st);
                }
                return Err(e);
            }
        };
        let Some(stop) = r.stop else {
            self.pending = match step {
                Some(st) => Pending::Stepping(st),
                None => Pending::Running,
            };
            if self.stop_sent.is_some_and(|t| t.elapsed() >= STOP_RESEND) {
                self.send_stop()?;
            }
            return Ok(None);
        };
        self.stop_sent = None;
        if let Some(st) = &step {
            self.end_step(st)?;
        }
        self.regs = None;
        if let Some(code) = r.exit_code {
            self.exit_code = Some(code);
            self.log(|| format!("exit code {code}"));
            let [low, ..] = code.to_le_bytes();
            return Ok(Some(SingleThreadStopReason::Exited(low)));
        }
        let reason = self.classify(&stop, step.as_ref());
        self.log(|| {
            format!(
                "stopped: {} at 0x{:08x} a=0x{:08x} b=0x{:08x} -> {reason:?}",
                stop.reason_name(),
                stop.epc,
                stop.a,
                stop.b
            )
        });
        Ok(Some(reason))
    }

    /// gdb's interrupt while the target runs: STOP, if the monitor reads it.
    fn interrupt(&mut self) -> Res<()> {
        if !matches!(self.pending, Pending::Running | Pending::Stepping(_)) {
            return Ok(());
        }
        if self.sess.caps & CAP_STOP == 0 {
            eprintln!(
                "psxmon gdb: interrupt ignored: this monitor cannot stop a running target; \
                 waiting for a breakpoint, watch, fault or exit"
            );
            return Ok(());
        }
        self.log(|| "interrupt: STOP, the target halts at its next interrupt".into());
        self.send_stop()
    }

    fn send_stop(&mut self) -> Res<()> {
        self.stop_sent = Some(Instant::now());
        self.rt.block_on(self.sess.send(STOP, &[]))
    }

    fn classify(&self, stop: &Stop, step: Option<&StepState>) -> SingleThreadStopReason<u32> {
        let sig = SingleThreadStopReason::Signal;
        match stop.reason {
            STOP_BREAKPOINT if !stop.is_hardware() => {
                let planted = step.is_some_and(|st| st.planted.iter().any(|p| p.0 == stop.epc));
                if stop.a == STEP_BREAK && planted {
                    SingleThreadStopReason::DoneStep
                } else {
                    // gdb's own `break`, or one in the program: PC is on it.
                    sig(Signal::SIGTRAP)
                }
            }
            STOP_BREAKPOINT => {
                let same = |a: Option<u32>| a.is_some_and(|a| (a ^ stop.epc) & SEGMENT_MASK == 0);
                if step.is_some_and(|st| same(st.rom)) {
                    SingleThreadStopReason::DoneStep
                } else if same(self.rom_bp) {
                    SingleThreadStopReason::HwBreak(())
                } else {
                    // A `break` in a branch delay slot (PROTOCOL.md 13):
                    // reported with the PC on the branch.
                    sig(Signal::SIGTRAP)
                }
            }
            STOP_DATA_WATCH => match self.watch {
                Some(w) => SingleThreadStopReason::Watch {
                    tid: (),
                    kind: w.kind,
                    addr: w.addr,
                },
                None => sig(Signal::SIGTRAP),
            },
            STOP_FAULT => sig(match stop.a {
                // AdEL, AdES, IBE, DBE
                4..=7 => Signal::SIGBUS,
                // RI, CpU
                10 | 11 => Signal::SIGILL,
                // Ov
                12 => Signal::SIGFPE,
                _ => Signal::SIGSEGV,
            }),
            STOP_INTERRUPT => sig(Signal::SIGINT),
            _ => sig(Signal::SIGTRAP),
        }
    }
}

fn fatal(e: SessionError) -> TargetError<SessionError> {
    TargetError::Fatal(e)
}

/// Bytes of `len` from `addr` that lie in mapped memory, stopping at the
/// first unmapped byte.
fn mapped_len(addr: u32, len: usize) -> usize {
    let mut at = addr;
    let mut n = 0usize;
    while n < len {
        let Some((_, left)) = mips::region(at) else {
            break;
        };
        let take = usize::try_from(left)
            .unwrap_or(usize::MAX)
            .min(len.saturating_sub(n));
        n = n.saturating_add(take);
        at = at.wrapping_add(u32::try_from(take).unwrap_or(u32::MAX));
    }
    n
}

impl<T: Transport> Target for MonTarget<T> {
    type Arch = Mips;
    type Error = SessionError;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }

    fn support_memory_map(&mut self) -> Option<MemoryMapOps<'_, Self>> {
        Some(self)
    }

    fn support_target_description_xml_override(
        &mut self,
    ) -> Option<TargetDescriptionXmlOverrideOps<'_, Self>> {
        Some(self)
    }

    /// No Z0: gdb inserts its own `break` instructions through memory
    /// writes, and the stop comes back as SIGTRAP with the PC on them.
    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }

    /// gdb probes `X` with the address sign-extended to 64 bits
    /// (`Xffffffff80010014,0:`), which a 32-bit target cannot parse; its
    /// `m`/`M` addresses are masked to 32 bits. Without `X`, gdb uses `M`.
    fn use_x_upcase_packet(&self) -> bool {
        false
    }
}

impl<T: Transport> SingleThreadBase for MonTarget<T> {
    fn read_registers(&mut self, regs: &mut MipsCoreRegs<u32>) -> TargetResult<(), Self> {
        let r = self.regs().map_err(fatal)?;
        let at = |i: u16| r.get(usize::from(i)).copied().unwrap_or(0);
        for (dst, src) in regs.r.iter_mut().zip(r.iter()) {
            *dst = *src;
        }
        regs.cp0.status = at(REG_SR);
        regs.lo = at(REG_LO);
        regs.hi = at(REG_HI);
        regs.cp0.badvaddr = at(REG_BADVADDR);
        regs.cp0.cause = at(REG_CAUSE);
        regs.pc = at(REG_PC);
        // The R3000A has no FPU: gdb's FP slots read as 0.
        regs.fpu = Default::default();
        Ok(())
    }

    fn write_registers(&mut self, regs: &MipsCoreRegs<u32>) -> TargetResult<(), Self> {
        let old = self.regs().map_err(fatal)?;
        let mut new = [0u32; NUM_REGS];
        for (dst, src) in new.iter_mut().zip(regs.r.iter()) {
            *dst = *src;
        }
        for (i, v) in [
            (REG_SR, regs.cp0.status),
            (REG_LO, regs.lo),
            (REG_HI, regs.hi),
            (REG_BADVADDR, regs.cp0.badvaddr),
            (REG_CAUSE, regs.cp0.cause),
            (REG_PC, regs.pc),
        ] {
            if let Some(slot) = new.get_mut(usize::from(i)) {
                *slot = v;
            }
        }
        for (i, (&o, &n)) in old.iter().zip(new.iter()).enumerate() {
            if o != n && i != 0 {
                self.set_reg(i, n).map_err(fatal)?;
            }
        }
        Ok(())
    }

    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, (), Self>> {
        Some(self)
    }

    fn read_addrs(&mut self, start: u32, data: &mut [u8]) -> TargetResult<usize, Self> {
        let n = mapped_len(start, data.len());
        if n == 0 {
            return Err(TargetError::Errno(14)); // EFAULT
        }
        let len = u32::try_from(n).map_err(|_| TargetError::Errno(22))?;
        let bytes = self
            .rt
            .block_on(self.sess.read_mem(start, len))
            .map_err(fatal)?;
        let got = bytes.len().min(n);
        for (d, s) in data.iter_mut().zip(bytes.iter()) {
            *d = *s;
        }
        Ok(got)
    }

    fn write_addrs(&mut self, start: u32, data: &[u8]) -> TargetResult<(), Self> {
        if mapped_len(start, data.len()) < data.len() {
            return Err(TargetError::Errno(14));
        }
        self.write(start, data).map_err(fatal)?;
        // A write into ROM does nothing: read it back, so gdb gets an error
        // (and says so) rather than a breakpoint that never fires.
        if (0..data.len())
            .any(|off| u32::try_from(off).is_ok_and(|o| mips::is_rom(start.wrapping_add(o))))
        {
            let len = u32::try_from(data.len()).map_err(|_| TargetError::Errno(22))?;
            let back = self
                .rt
                .block_on(self.sess.read_mem(start, len))
                .map_err(fatal)?;
            if back != data {
                self.log(|| format!("write to ROM at 0x{start:08x} did not take"));
                return Err(TargetError::Errno(30)); // EROFS
            }
        }
        Ok(())
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

/// REGS index of a gdb register, or None for the FP registers (always 0).
fn reg_index(id: MipsRegId<u32>) -> Result<Option<usize>, TargetError<SessionError>> {
    Ok(Some(match id {
        MipsRegId::Gpr(n) => usize::from(n),
        MipsRegId::Status => usize::from(REG_SR),
        MipsRegId::Lo => usize::from(REG_LO),
        MipsRegId::Hi => usize::from(REG_HI),
        MipsRegId::Badvaddr => usize::from(REG_BADVADDR),
        MipsRegId::Cause => usize::from(REG_CAUSE),
        MipsRegId::Pc => usize::from(REG_PC),
        MipsRegId::Fpr(_) | MipsRegId::Fcsr | MipsRegId::Fir => return Ok(None),
        _ => return Err(TargetError::NonFatal),
    }))
}

impl<T: Transport> SingleRegisterAccess<()> for MonTarget<T> {
    fn read_register(
        &mut self,
        _tid: (),
        id: MipsRegId<u32>,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let value = match reg_index(id)? {
            Some(i) => self
                .regs()
                .map_err(fatal)?
                .get(i)
                .copied()
                .ok_or(TargetError::NonFatal)?,
            None => 0,
        };
        let bytes = value.to_le_bytes();
        for (d, s) in buf.iter_mut().zip(bytes.iter()) {
            *d = *s;
        }
        Ok(bytes.len().min(buf.len()))
    }

    fn write_register(
        &mut self,
        _tid: (),
        id: MipsRegId<u32>,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        let w: [u8; 4] = val
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or(TargetError::NonFatal)?;
        match reg_index(id)? {
            Some(0) | None => Ok(()),
            Some(i) => self.set_reg(i, u32::from_le_bytes(w)).map_err(fatal),
        }
    }
}

impl<T: Transport> SingleThreadResume for MonTarget<T> {
    /// A signal gdb asks to deliver is dropped: the monitor cannot inject
    /// one. A fault continued this way re-executes the faulting instruction.
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        self.do_continue()
    }

    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl<T: Transport> SingleThreadSingleStep for MonTarget<T> {
    fn step(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        self.do_step()
    }
}

impl<T: Transport> Breakpoints for MonTarget<T> {
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl<T: Transport> HwBreakpoint for MonTarget<T> {
    /// The exec breakpoint is kept for ROM, where gdb cannot write a
    /// `break`; one at a time.
    fn add_hw_breakpoint(
        &mut self,
        addr: u32,
        _kind: MipsBreakpointKind,
    ) -> TargetResult<bool, Self> {
        let ok = mips::is_rom(addr) && self.rom_bp.is_none_or(|a| a == addr);
        if ok {
            self.rom_bp = Some(addr);
        }
        self.log(|| format!("Z1 0x{addr:08x}: {}", if ok { "armed" } else { "refused" }));
        Ok(ok)
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: u32,
        _kind: MipsBreakpointKind,
    ) -> TargetResult<bool, Self> {
        let ok = self.rom_bp == Some(addr);
        if ok {
            self.rom_bp = None;
        }
        Ok(ok)
    }
}

impl<T: Transport> HwWatchpoint for MonTarget<T> {
    /// The data breakpoint, for a power-of-two length at an address aligned
    /// to it (the unit matches an address under a mask).
    fn add_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let w = Watch { addr, len, kind };
        let ok = len.is_power_of_two()
            && addr & len.wrapping_sub(1) == 0
            && mips::region(addr).is_some()
            && self.watch.is_none_or(|old| old == w);
        if ok {
            self.watch = Some(w);
        }
        self.log(|| {
            format!(
                "watch {kind:?} 0x{addr:08x} len {len}: {}",
                if ok { "armed" } else { "refused" }
            )
        });
        Ok(ok)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let ok = self.watch == Some(Watch { addr, len, kind });
        if ok {
            self.watch = None;
        }
        Ok(ok)
    }
}

/// Copy `offset..offset + length` of `bytes` into `buf`, for the qXfer reads.
fn xfer(bytes: &[u8], offset: u64, length: usize, buf: &mut [u8]) -> usize {
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let src = bytes.get(start..).unwrap_or_default();
    let n = src.len().min(length).min(buf.len());
    for (d, s) in buf.iter_mut().zip(src.iter().take(n)) {
        *d = *s;
    }
    n
}

/// gdbstub_arch's MIPS description names no OS ABI, and gdb-multiarch then
/// picks GNU/Linux, whose MIPS support single-steps in software: it plants
/// its own `break` and sends `vCont;c`. With `none`, gdb sends `vCont;s`.
const TARGET_XML: &str =
    r#"<target version="1.0"><architecture>mips:3000</architecture><osabi>none</osabi></target>"#;

impl<T: Transport> TargetDescriptionXmlOverride for MonTarget<T> {
    fn target_description_xml(
        &self,
        annex: &[u8],
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        if annex != b"target.xml" {
            return Err(TargetError::NonFatal);
        }
        Ok(xfer(TARGET_XML.as_bytes(), offset, length, buf))
    }
}

impl<T: Transport> MemoryMap for MonTarget<T> {
    fn memory_map_xml(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        Ok(xfer(mips::memory_map_xml().as_bytes(), offset, length, buf))
    }
}

/// Close the gdb link without a reset. A socket closed with unread input
/// sends RST, and gdb then loses what it has not read yet, the stop reply
/// included; input arriving after the close is met with RST too. What is
/// still to come is known: gdb's `+` for each of the `owed` packets (none
/// in no-ack mode, which the tests do not offer). Send FIN, then read
/// until they are all in, gdb closes, or [`CLOSE_ACK_TIMEOUT`] passes
/// with nothing read. A timer alone would be a race against a slow gdb.
fn close_gently(sock: &TcpStream, mut owed: usize) {
    use std::io::Read;
    let _ = sock.shutdown(std::net::Shutdown::Write);
    // gdbstub's `peek` leaves the socket non-blocking; a read would then
    // fail at once with WouldBlock and the acks would never be waited for.
    let _ = sock.set_nonblocking(false);
    let _ = sock.set_read_timeout(Some(CLOSE_ACK_TIMEOUT));
    let mut buf = [0u8; 256];
    let mut r: &TcpStream = sock;
    while owed > 0 {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let acks = buf.get(..n).unwrap_or_default();
                owed = owed.saturating_sub(acks.iter().filter(|&&b| b == b'+').count());
            }
        }
    }
}

/// `text` as RSP `O` packets (`$O<hex>#<sum>`), [`O_CHUNK`] bytes each.
fn console_packets(text: &[u8]) -> Vec<Vec<u8>> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    text.chunks(O_CHUNK)
        .map(|chunk| {
            let mut body = Vec::with_capacity(chunk.len().saturating_mul(2).saturating_add(1));
            body.push(b'O');
            for &b in chunk {
                body.push(HEX[usize::from(b >> 4)]);
                body.push(HEX[usize::from(b & 15)]);
            }
            let sum = body.iter().fold(0u8, |a, &b| a.wrapping_add(b));
            let mut pkt = Vec::with_capacity(body.len().saturating_add(4));
            pkt.push(b'$');
            pkt.extend_from_slice(&body);
            pkt.push(b'#');
            pkt.push(HEX[usize::from(sum >> 4)]);
            pkt.push(HEX[usize::from(sum & 15)]);
            pkt
        })
        .collect()
}

/// Send gdb the console text held so far. Only while the target runs: an
/// `O` packet is legal between a resume and its stop reply. gdb acks each
/// with `+`, which gdbstub reads and ignores; each is counted as owed
/// until read, so the link can be closed once they are all in.
fn send_console<T: Transport>(
    target: &mut MonTarget<T>,
    conn: &mut TcpStream,
) -> std::io::Result<()> {
    let text = target.take_gdb_text();
    if text.is_empty() {
        return Ok(());
    }
    for pkt in console_packets(&text) {
        conn.write_all(&pkt)?;
        target.acks_owed = target.acks_owed.saturating_add(1);
    }
    Connection::flush(conn)
}

enum EventLoop<T> {
    #[allow(dead_code)]
    Never(std::marker::PhantomData<T>),
}

impl<T: Transport> BlockingEventLoop for EventLoop<T> {
    type Target = MonTarget<T>;
    type Connection = TcpStream;
    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut MonTarget<T>,
        conn: &mut TcpStream,
    ) -> Result<
        Event<Self::StopReason>,
        WaitForStopReasonError<SessionError, <TcpStream as Connection>::Error>,
    > {
        loop {
            if conn
                .peek()
                .map_err(WaitForStopReasonError::Connection)?
                .is_some()
            {
                let byte = conn.read().map_err(WaitForStopReasonError::Connection)?;
                // While the target runs gdb only sends `+` and ^C: a `+`
                // here is the ack of an `O` packet, read before the stop.
                if byte == b'+' {
                    target.acks_owed = target.acks_owed.saturating_sub(1);
                }
                return Ok(Event::IncomingData(byte));
            }
            let stopped = target.poll().map_err(WaitForStopReasonError::Target)?;
            // Text printed before the stop goes out before the stop reply.
            send_console(target, conn).map_err(WaitForStopReasonError::Connection)?;
            if let Some(reason) = stopped {
                return Ok(Event::TargetStopped(reason));
            }
        }
    }

    /// Send STOP (see [`MonTarget::interrupt`]) and keep waiting: the stop
    /// comes back through `wait_for_stop_reason` as SIGINT.
    fn on_interrupt(target: &mut MonTarget<T>) -> Result<Option<Self::StopReason>, SessionError> {
        target.interrupt()?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{O_CHUNK, console_packets};

    #[test]
    fn console_text_becomes_o_packets() {
        let pkts = console_packets(b"hi\n");
        // 'O' + "68690a", checksum mod 256.
        let body = b"O68690a";
        let sum = body.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(pkts, vec![format!("$O68690a#{sum:02x}").into_bytes()]);
        assert!(console_packets(b"").is_empty());
        let long = vec![b'x'; O_CHUNK + 1];
        let pkts = console_packets(&long);
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[1].len(), "$O78#00".len());
    }
}
