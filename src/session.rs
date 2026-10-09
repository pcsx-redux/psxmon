//! A monitor session over any byte link: attach with PING, load and run a
//! program, read and write memory and registers, and wait for the program to
//! stop while collecting its console text and serving its PCDRV calls.
//! Mirrors runner-agent `monitor/session.ts` and `monitor/loader.ts`.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, sleep, timeout_at};

use crate::frame::{
    Event, Frame, FrameError, Parser, bytes_to_words, encode_frame, u32_words, word_u32,
    words_to_bytes,
};
use crate::lz4::{self, DecodeError};
use crate::pcdrv::PcdrvServer;
use crate::proto::{self, *};
use crate::ram;
use crate::transport::{Transport, link_log};

/// Longest PCDRV file name read out of target memory.
const PCDRV_NAME_MAX: u32 = 256;
/// How long the host PINGs at a new rate before giving up on it. The
/// monitor's window is about 1.08 s on a retail PS1.
const RATE_TRY: Duration = Duration::from_millis(700);
/// After a failed rate change, how long to wait for both of the monitor's
/// windows to close before PINGing at the old rate.
const RATE_WINDOW: Duration = Duration::from_millis(2500);

const SHORT: Duration = Duration::from_secs(2);
const BULK: Duration = Duration::from_secs(5);
/// Bulk frames in flight when the monitor has [`CAP_PIPELINE`]: frames go out
/// ahead of their ACKs, so an ACK's trip back (an FTDI's 16 ms latency timer)
/// overlaps the next transfers instead of idling the link. 4 x 8 KiB covers
/// that timer at FT232H rates; 1 (no pipelining) otherwise.
const PIPELINE: usize = 4;

/// `now + d`, or far in the future if that does not fit.
pub fn deadline_after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d)
        .or_else(|| now.checked_add(Duration::from_secs(365 * 24 * 3600)))
        .unwrap_or(now)
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("link closed")]
    Closed,
    #[error("monitor: no reply to {0}")]
    Timeout(String),
    #[error("monitor: {what} failed: {} (0x{code:02x})", proto::error_name(*code))]
    Monitor { what: String, code: u16 },
    #[error("monitor: {0}: reply failed its checksum")]
    Checksum(String),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("LZ4: {0}")]
    Lz4(#[from] DecodeError),
    #[error("{0} does not fit in the protocol's 32-bit field")]
    TooLarge(&'static str),
    #[error("monitor: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SessionError>;

fn u32_len(n: usize, what: &'static str) -> Result<u32> {
    u32::try_from(n).map_err(|_| SessionError::TooLarge(what))
}

fn to_usize(n: u32) -> Result<usize> {
    usize::try_from(n).map_err(|_| SessionError::TooLarge("length"))
}

/// A STOPPED event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stop {
    pub reason: u16,
    pub epc: u32,
    pub a: u32,
    pub b: u32,
}

impl Stop {
    pub fn reason_name(&self) -> String {
        proto::stop_reason_name(self.reason)
    }

    /// A stop the cop0 debug unit caused (exec breakpoint or data watch),
    /// which disarms the unit. A BREAKPOINT whose `a` is not a `break` word
    /// is the exec breakpoint (or a `break` in a delay slot, which the
    /// monitor reports the same way: PROTOCOL.md section 13).
    pub fn is_hardware(&self) -> bool {
        self.reason == STOP_DATA_WATCH
            || (self.reason == STOP_BREAKPOINT && BreakCode::decode(self.a).is_none())
    }
}

/// How `run_until_stop` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    /// The stop, or None at the deadline. An exit is reported as reason
    /// [`STOP_EXIT`] with the code in `a`, whichever way the monitor sent it.
    pub stop: Option<Stop>,
    /// The program's a0 at its exit break, or None if it did not exit.
    pub exit_code: Option<u32>,
}

/// How to send a program.
#[derive(Debug, Clone, Copy)]
pub struct LoadOptions {
    /// Send LZ4 slices when the monitor has [`CAP_LZ4`].
    pub lz4: bool,
    /// Longest match per sequence (see [`lz4::cap_matches`]).
    pub max_match: usize,
    /// Use LZ4 only if it shrinks the data below this fraction of its size.
    pub max_ratio: f64,
}

impl Default for LoadOptions {
    fn default() -> Self {
        LoadOptions {
            lz4: true,
            max_match: lz4::DEFAULT_MAX_MATCH,
            max_ratio: 1.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStats {
    pub bytes: usize,
    /// Compressed bytes sent, when the data went out as LZ4.
    pub lz4_bytes: Option<usize>,
}

pub type Console = Box<dyn FnMut(&[u8]) + Send>;

/// One cop0 debug-unit breakpoint, as SET_BP takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwBreak {
    /// SET_BP kind: 0 exec, 1 data read, 2 data write, 3 data read/write.
    pub kind: u16,
    pub addr: u32,
    pub mask: u32,
}

/// The debug-unit breakpoints the host wants armed while the target runs:
/// the monitor has one exec and one data breakpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HwBreaks {
    pub exec: Option<HwBreak>,
    pub data: Option<HwBreak>,
}

pub struct Session<T: Transport> {
    io: T,
    parser: Parser,
    text: Vec<u8>,
    console: Option<Console>,
    pending: VecDeque<Frame>,
    /// Protocol version from the last PONG.
    pub version: Option<u16>,
    /// Capability bits from the last full PONG.
    pub caps: u16,
    /// BIOS Fletcher-32 from the last full PONG (protocol v2).
    pub bios: Option<u32>,
    /// Log PCDRV calls to stderr.
    pub verbose: bool,
    /// Debug-unit breakpoints armed with SET_BP before every CONT. A
    /// hardware stop disarms the whole unit (PROTOCOL.md section 11), so
    /// they are re-sent each time.
    pub hw: HwBreaks,
    /// Whether the monitor's debug unit may be armed right now.
    hw_live: bool,
    /// What [`Session::probe_ram`] found, once it has run.
    ram_size: Option<u32>,
}

impl<T: Transport> Session<T> {
    pub fn new(io: T) -> Self {
        Session {
            io,
            parser: Parser::new(),
            text: Vec::new(),
            console: None,
            pending: VecDeque::new(),
            version: None,
            caps: 0,
            bios: None,
            verbose: false,
            hw: HwBreaks::default(),
            hw_live: false,
            ram_size: None,
        }
    }

    pub fn transport(&mut self) -> &mut T {
        &mut self.io
    }

    /// Send console text to `sink` as it arrives instead of buffering it.
    pub fn set_console(&mut self, sink: Option<Console>) {
        self.console = sink;
        if let Some(sink) = self.console.as_mut()
            && !self.text.is_empty()
        {
            sink(&std::mem::take(&mut self.text));
        }
    }

    /// Remove the console sink, so text is buffered again; returns it.
    pub fn take_console(&mut self) -> Option<Console> {
        self.console.take()
    }

    /// Console text buffered since the last call.
    pub fn take_text(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.text)
    }

    pub async fn send(&mut self, ty: u16, payload: &[u16]) -> Result<()> {
        self.io.write_all(&encode_frame(ty, payload)?).await?;
        self.io.flush().await?;
        Ok(())
    }

    fn pump(&mut self) {
        while let Some(event) = self.parser.next_event() {
            match event {
                Event::Tty(bytes) => match self.console.as_mut() {
                    Some(sink) => sink(&bytes),
                    None => self.text.extend_from_slice(&bytes),
                },
                Event::Frame(f) => self.pending.push_back(f),
            }
        }
    }

    /// The next frame whose type is in `types`, or None at the deadline.
    /// Frames of other types that arrive meanwhile are dropped.
    pub async fn wait_frame(&mut self, types: &[u16], deadline: Instant) -> Result<Option<Frame>> {
        let mut buf = [0u8; 4096];
        loop {
            self.pump();
            if let Some(i) = self.pending.iter().position(|f| types.contains(&f.ty)) {
                let frame = self.pending.remove(i);
                self.pending.drain(..i);
                return Ok(frame);
            }
            self.pending.clear();
            if Instant::now() >= deadline {
                return Ok(None);
            }
            match timeout_at(deadline, self.io.read(&mut buf)).await {
                Err(_) => {}
                Ok(Ok(0)) => return Err(SessionError::Closed),
                Ok(Ok(n)) => self.parser.feed(buf.get(..n).unwrap_or_default()),
                Ok(Err(e)) => return Err(e.into()),
            }
        }
    }

    /// ACK, or the ERROR / timeout / checksum failure as an error.
    async fn expect_ack(&mut self, what: impl Fn() -> String, wait: Duration) -> Result<()> {
        match self.wait_frame(&[ACK, ERROR], deadline_after(wait)).await? {
            None => Err(SessionError::Timeout(what())),
            Some(f) if f.ty == ERROR => Err(SessionError::Monitor {
                what: what(),
                code: f.words.first().copied().unwrap_or(0),
            }),
            Some(f) if !f.ok => Err(SessionError::Checksum(what())),
            Some(_) => Ok(()),
        }
    }

    /// PING until PONG, or false after `wait`. A PONG with only the version
    /// (the SET_BAUD window PONGs) leaves caps and BIOS as they were.
    pub async fn ping(&mut self, wait: Duration, payload: &[u16]) -> Result<bool> {
        let deadline = deadline_after(wait);
        while Instant::now() < deadline {
            self.send(PING, payload).await?;
            let slot = deadline.min(deadline_after(Duration::from_millis(500)));
            if let Some(pong) = self.wait_frame(&[PONG], slot).await?
                && pong.ok
            {
                if let Some(&v) = pong.words.first() {
                    self.version = Some(v);
                }
                if let Some(&caps) = pong.words.get(1) {
                    self.caps = caps;
                }
                if pong.words.len() > 3 {
                    self.bios = Some(word_u32(&pong.words, 2));
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Attach at the first of `rates` where the monitor answers PING: the
    /// first rate gets `first_wait`, each other one `other_wait`. A monitor
    /// left at a fast rate by an earlier SET_BAUD does not answer at the
    /// boot rate. Returns the rate that answered, with the transport at it.
    pub async fn attach_at(
        &mut self,
        rates: &[u32],
        first_wait: Duration,
        other_wait: Duration,
    ) -> Result<Option<u32>> {
        let mut wait = first_wait;
        for &rate in rates {
            self.io.set_baud_rate(rate)?;
            link_log(&format!("PING at {rate} baud for {} ms", wait.as_millis()));
            if self.ping(wait, &[]).await? {
                link_log(&format!("PONG at {rate} baud"));
                return Ok(Some(rate));
            }
            link_log(&format!("no PONG at {rate} baud"));
            wait = other_wait;
        }
        Ok(None)
    }

    /// Write `data` at `addr` in plain LOAD frames of 8 KiB, each ACKed
    /// before the next.
    pub async fn load_raw(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        self.bulk_write(LOAD, "LOAD", addr, data).await
    }

    /// Write `data` at `addr` in WRITE_MEM frames of 8 KiB.
    pub async fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        self.bulk_write(WRITE_MEM, "WRITE_MEM", addr, data).await
    }

    fn pipeline_depth(&self) -> usize {
        if self.caps & CAP_PIPELINE != 0 {
            PIPELINE
        } else {
            1
        }
    }

    async fn bulk_write(&mut self, ty: u16, name: &str, addr: u32, data: &[u8]) -> Result<()> {
        u32_len(data.len(), "write length")?;
        let mut at = addr;
        let mut pending = VecDeque::new();
        for chunk in data.chunks(CHUNK_BYTES) {
            let n = u32_len(chunk.len(), "chunk")?;
            let mut payload = u32_words(&[at, n]);
            payload.extend(bytes_to_words(chunk));
            self.send(ty, &payload).await?;
            pending.push_back(at);
            if pending.len() >= self.pipeline_depth()
                && let Some(a) = pending.pop_front()
            {
                self.expect_ack(|| format!("{name} at 0x{a:08x}"), BULK)
                    .await?;
            }
            // Target addresses are 32-bit and wrap, as `addr + off` does
            // once the reference host packs it into two words.
            at = at.wrapping_add(n);
        }
        while let Some(a) = pending.pop_front() {
            self.expect_ack(|| format!("{name} at 0x{a:08x}"), BULK)
                .await?;
        }
        Ok(())
    }

    /// Write `raw_len` bytes at `addr` from the LZ4 block `comp`, sent as
    /// consecutive slices in LOAD|LZ4 frames, each ACKed before the next.
    pub async fn load_lz4(&mut self, addr: u32, raw_len: usize, comp: &[u8]) -> Result<()> {
        let raw_len = u32_len(raw_len, "LZ4 raw length")?;
        let clen = u32_len(comp.len(), "LZ4 block")?;
        let mut off: u32 = 0;
        let mut pending = VecDeque::new();
        for chunk in comp.chunks(CHUNK_BYTES) {
            let n = u32_len(chunk.len(), "chunk")?;
            let mut payload = u32_words(&[addr, raw_len, clen, off, n]);
            payload.extend(bytes_to_words(chunk));
            self.send(LOAD | LZ4_FLAG, &payload).await?;
            pending.push_back(off);
            if pending.len() >= self.pipeline_depth()
                && let Some(o) = pending.pop_front()
            {
                self.expect_ack(|| format!("LZ4 LOAD at offset {o}"), BULK)
                    .await?;
            }
            // off + n <= clen, a u32.
            off = off.saturating_add(n);
        }
        while let Some(o) = pending.pop_front() {
            self.expect_ack(|| format!("LZ4 LOAD at offset {o}"), BULK)
                .await?;
        }
        Ok(())
    }

    /// Load `data` at `addr`: LZ4 when asked for, the monitor has it, and it
    /// shrinks the data enough; plain LOAD otherwise.
    pub async fn load(&mut self, addr: u32, data: &[u8], opts: &LoadOptions) -> Result<LoadStats> {
        if opts.lz4 && self.caps & CAP_LZ4 != 0 && !data.is_empty() {
            let comp = lz4::compress(data, opts.max_match)?;
            let comp_len = f64::from(u32_len(comp.len(), "LZ4 block")?);
            let raw_len = f64::from(u32_len(data.len(), "load length")?);
            if comp_len < raw_len * opts.max_ratio {
                self.load_lz4(addr, data.len(), &comp).await?;
                return Ok(LoadStats {
                    bytes: data.len(),
                    lz4_bytes: Some(comp.len()),
                });
            }
        }
        self.load_raw(addr, data).await?;
        Ok(LoadStats {
            bytes: data.len(),
            lz4_bytes: None,
        })
    }

    pub async fn read_mem(&mut self, addr: u32, len: u32) -> Result<Vec<u8>> {
        self.send(READ_MEM, &u32_words(&[addr, len])).await?;
        let want = to_usize(len)?;
        let mut out = Vec::with_capacity(want);
        loop {
            let what = || format!("READ_MEM at 0x{addr:08x}");
            let f = match self
                .wait_frame(&[DATA, ERROR], deadline_after(BULK))
                .await?
            {
                None => return Err(SessionError::Timeout(what())),
                Some(f) if f.ty == ERROR => {
                    return Err(SessionError::Monitor {
                        what: what(),
                        code: f.words.first().copied().unwrap_or(0),
                    });
                }
                Some(f) if !f.ok => return Err(SessionError::Checksum(what())),
                Some(f) => f,
            };
            let n = to_usize(word_u32(&f.words, 0))?;
            out.extend(words_to_bytes(&f.words, 2, n));
            // len 0 is answered by one empty DATA frame.
            if out.len() >= want {
                return Ok(out);
            }
        }
    }

    pub async fn get_regs(&mut self) -> Result<[u32; NUM_REGS]> {
        self.send(GET_REGS, &[]).await?;
        match self
            .wait_frame(&[REGS, ERROR], deadline_after(SHORT))
            .await?
        {
            Some(f) if f.ty == REGS && f.ok => {
                let mut regs = [0u32; NUM_REGS];
                for (r, pair) in regs.iter_mut().zip(f.words.as_chunks::<2>().0) {
                    *r = word_u32(pair, 0);
                }
                Ok(regs)
            }
            Some(f) if f.ty == ERROR => Err(SessionError::Monitor {
                what: "GET_REGS".into(),
                code: f.words.first().copied().unwrap_or(0),
            }),
            Some(_) => Err(SessionError::Checksum("GET_REGS".into())),
            None => Err(SessionError::Timeout("GET_REGS".into())),
        }
    }

    pub async fn set_reg(&mut self, index: u16, value: u32) -> Result<()> {
        let mut payload = vec![index];
        payload.extend(u32_words(&[value]));
        self.send(SET_REG, &payload).await?;
        self.expect_ack(|| format!("SET_REG {index}"), SHORT).await
    }

    pub async fn set_bp(&mut self, bp: HwBreak) -> Result<()> {
        let mut payload = vec![bp.kind];
        payload.extend(u32_words(&[bp.addr, bp.mask]));
        self.send(SET_BP, &payload).await?;
        self.expect_ack(|| format!("SET_BP {}", bp.kind), SHORT)
            .await
    }

    pub async fn clr_bp(&mut self, kind: u16) -> Result<()> {
        self.send(CLR_BP, &[kind]).await?;
        self.expect_ack(|| format!("CLR_BP {kind}"), SHORT).await
    }

    /// SET_BP everything in [`Session::hw`]. The unit is off here (a
    /// hardware stop cleared it, any other stop was followed by
    /// [`Session::disarm`]), so SET_BP's OR into DCIC starts from zero.
    /// A breakpoint in RAM is widened to every mirror of its address
    /// ([`ram::mirror_mask`]), which the first such one probes for.
    async fn arm(&mut self) -> Result<()> {
        let bps = [self.hw.exec, self.hw.data];
        let installed = if bps.iter().flatten().any(|b| ram::in_ram_window(b.addr)) {
            self.probe_ram().await?
        } else {
            ram::RAM_WINDOW
        };
        for bp in bps.into_iter().flatten() {
            self.hw_live = true;
            self.set_bp(HwBreak {
                mask: ram::mirror_mask(bp.addr, bp.mask, installed),
                ..bp
            })
            .await?;
        }
        Ok(())
    }

    /// The RAM that repeats over the 8 MiB window: 2, 4 or 8 MiB, probed
    /// the first time and remembered for the session (see [`ram`]). The
    /// target must be halted. When the first DRAM bank does not span the
    /// window (a program shrank it), nothing repeats and this is 8 MiB
    /// without probing.
    pub async fn probe_ram(&mut self) -> Result<u32> {
        if let Some(n) = self.ram_size {
            return Ok(n);
        }
        let n = self.probe_ram_uncached().await?;
        if self.verbose {
            eprintln!(
                "psxmon: {} MiB of RAM repeats over the 8 MiB window",
                n / ram::MIB
            );
        }
        self.ram_size = Some(n);
        Ok(n)
    }

    async fn probe_ram_uncached(&mut self) -> Result<u32> {
        let ctrl = self.read_u32(ram::RAM_SIZE_REG).await?;
        if !ram::window_mirrors(ctrl) {
            if self.verbose {
                eprintln!("psxmon: DRAM_CTRL 0x{ctrl:08x}: no 8 MiB bank, no RAM mirrors");
            }
            return Ok(ram::RAM_WINDOW);
        }
        let at = |off: u32| ram::SENTINEL.wrapping_add(off);
        let v = self.read_u32(ram::SENTINEL).await?;
        let mut mirror = [false; 3];
        for (m, &off) in mirror.iter_mut().zip(ram::PROBE_OFFSETS.iter()) {
            *m = self.read_u32(at(off)).await? == v;
        }
        if mirror.contains(&true) {
            // Equal words may be chance: flip the sentinel, see which follow.
            self.write_mem(ram::SENTINEL, &(!v).to_le_bytes()).await?;
            let mut seen = Ok(());
            for (m, &off) in mirror.iter_mut().zip(ram::PROBE_OFFSETS.iter()) {
                if *m {
                    match self.read_u32(at(off)).await {
                        Ok(w) => *m = w == !v,
                        Err(e) => {
                            seen = Err(e);
                            break;
                        }
                    }
                }
            }
            let restored = self.write_mem(ram::SENTINEL, &v.to_le_bytes()).await;
            seen?;
            restored?;
        }
        Ok(ram::size_from_mirrors(mirror))
    }

    async fn read_u32(&mut self, addr: u32) -> Result<u32> {
        let b = self.read_mem(addr, 4).await?;
        b.first_chunk::<4>()
            .map(|w| u32::from_le_bytes(*w))
            .ok_or_else(|| SessionError::Other(format!("short READ_MEM at 0x{addr:08x}")))
    }

    /// Turn the debug unit off while halted, so that the monitor's own
    /// memory accesses in its command loop cannot trip a watch.
    pub async fn disarm(&mut self) -> Result<()> {
        if self.hw_live {
            self.clr_bp(0).await?;
            self.clr_bp(1).await?;
            self.hw_live = false;
        }
        Ok(())
    }

    /// A hardware stop has already disarmed the debug unit; after any other
    /// stop it is turned off here.
    async fn after_stop(&mut self, stop: &Stop) -> Result<()> {
        if stop.is_hardware() {
            self.hw_live = false;
        }
        self.disarm().await
    }

    /// SET_BP the breakpoints in [`Session::hw`], then CONT.
    pub async fn cont(&mut self) -> Result<()> {
        self.arm().await?;
        self.send(CONT, &[]).await?;
        self.expect_ack(|| "CONT".into(), SHORT).await
    }

    pub async fn run(&mut self, pc: u32, gp: u32, sp: u32) -> Result<()> {
        self.send(RUN, &u32_words(&[pc, gp, sp])).await?;
        self.expect_ack(|| "RUN".into(), SHORT).await
    }

    /// SET_BAUD to `reload`, then PING at the new rate and confirm with
    /// PING [1]. If the new rate does not answer, go back to the old one,
    /// let the monitor's windows close, and PING there. Returns the rate the
    /// link ends up at.
    pub async fn negotiate_rate(&mut self, reload: u16) -> Result<u32> {
        let old = self.io.baud_rate();
        link_log(&format!("SET_BAUD reload {reload} from {old} baud"));
        self.send(SET_BAUD, &[reload]).await?;
        match self
            .wait_frame(&[ACK, ERROR], deadline_after(Duration::from_secs(1)))
            .await?
        {
            Some(f) if f.ty == ACK => {}
            _ => return Ok(old),
        }
        let new = proto::sio1_rate(reload);
        sleep(Duration::from_millis(20)).await;
        self.io.set_baud_rate(new)?;
        if self.ping(RATE_TRY, &[]).await? && self.ping(RATE_TRY, &[1]).await? {
            self.take_text();
            return Ok(new);
        }
        self.io.set_baud_rate(old)?;
        sleep(RATE_WINDOW).await;
        self.take_text();
        if !self.ping(Duration::from_secs(3), &[]).await? {
            return Err(SessionError::Other(format!(
                "lost after trying reload {reload}"
            )));
        }
        // Whatever a garbled PONG decoded to is not console text.
        self.take_text();
        Ok(old)
    }

    /// Wait for the running program to stop, until `deadline`, serving its
    /// PCDRV calls. `break 4, 0` is an exit with the code in a0; `break 0,
    /// 0x101..0x107` is a PCDRV call, served and continued. Without a PCDRV
    /// server every call fails with -1, so a program probing PCinit sees no
    /// host rather than hanging. Any other stop is returned as is, except
    /// the legacy EXIT reason, whose code is in `a`.
    pub async fn run_until_stop(
        &mut self,
        deadline: Instant,
        mut pcdrv: Option<&mut PcdrvServer>,
    ) -> Result<RunResult> {
        loop {
            let slot = deadline.min(deadline_after(Duration::from_millis(50)));
            if let Some(f) = self.wait_frame(&[STOPPED], slot).await? {
                let stop = Stop {
                    reason: f.words.first().copied().unwrap_or(0),
                    epc: word_u32(&f.words, 1),
                    a: word_u32(&f.words, 3),
                    b: word_u32(&f.words, 5),
                };
                self.after_stop(&stop).await?;
                let insn = if stop.reason == STOP_BREAKPOINT {
                    stop.a
                } else {
                    0
                };
                if let Some(code) = BreakCode::decode(insn) {
                    if code.is_exit() {
                        let regs = self.get_regs().await?;
                        let a0 = regs.get(usize::from(REG_A0)).copied().unwrap_or(0);
                        return Ok(RunResult {
                            stop: Some(Stop {
                                reason: STOP_EXIT,
                                a: a0,
                                ..stop
                            }),
                            exit_code: Some(a0),
                        });
                    }
                    if let Some(op) = code.pcdrv_op() {
                        self.serve_pcdrv(op, stop.epc, pcdrv.as_deref_mut()).await?;
                        continue;
                    }
                }
                // Monitors before break-driven PCDRV report exit themselves, code in a.
                let exit_code = (stop.reason == STOP_EXIT).then_some(stop.a);
                return Ok(RunResult {
                    stop: Some(stop),
                    exit_code,
                });
            }
            if Instant::now() >= deadline {
                return Ok(RunResult {
                    stop: None,
                    exit_code: None,
                });
            }
        }
    }

    /// Serve a PCDRV call the target made with `break 0, op`: arguments from
    /// its registers and memory, the result back in v0/v1 (v0 alone for init
    /// and close), then resume past the break.
    async fn serve_pcdrv(
        &mut self,
        op: u32,
        epc: u32,
        pcdrv: Option<&mut PcdrvServer>,
    ) -> Result<()> {
        let regs = self.get_regs().await?;
        let &[a0, a1, a2, a3] = regs
            .get(usize::from(REG_A0)..)
            .and_then(|r| r.first_chunk::<4>())
            .ok_or_else(|| SessionError::Other("REGS too short".into()))?;
        let ret = match pcdrv {
            None => -1,
            Some(server) => match self.pcdrv_call(server, op, [a0, a1, a2, a3]).await {
                Ok(v) => v,
                Err(e) => {
                    if self.verbose {
                        eprintln!("psxmon: pcdrv 0x{op:03x} failed: {e}");
                    }
                    -1
                }
            },
        };
        if self.verbose {
            eprintln!(
                "psxmon: pcdrv 0x{op:03x} a0={a0:#x} a1={a1:#x} a2={a2:#x} a3={a3:#x} -> {ret}"
            );
        }
        // The result goes back as the register's bit pattern.
        if op == PC_INIT || op == PC_CLOSE {
            self.set_reg(REG_V0, ret.cast_unsigned()).await?;
        } else {
            self.set_reg(REG_V0, 0).await?;
            self.set_reg(REG_V1, ret.cast_unsigned()).await?;
        }
        // Past the break; PCs are 32-bit and wrap like the CPU's.
        self.set_reg(REG_PC, epc.wrapping_add(4)).await?;
        self.cont().await
    }

    /// One PCDRV call. Handles and offsets arrive as register bits and are
    /// read as the signed ints the target's pcdrv.h passes.
    async fn pcdrv_call(
        &mut self,
        s: &mut PcdrvServer,
        op: u32,
        [a0, a1, a2, a3]: [u32; 4],
    ) -> std::result::Result<i32, CallError> {
        Ok(match op {
            PC_INIT => 0,
            PC_CREAT | PC_OPEN => {
                let raw = self.read_mem(a0, PCDRV_NAME_MAX).await?;
                let name = raw.split(|&b| b == 0).next().unwrap_or_default();
                if op == PC_CREAT {
                    s.create(name)?
                } else {
                    s.open(name, a2)?
                }
            }
            PC_CLOSE => s.close(a0.cast_signed()),
            PC_READ => {
                let data = s.read(a1.cast_signed(), a2)?;
                if !data.is_empty() {
                    self.write_mem(a3, &data).await?;
                }
                i32::try_from(data.len()).map_err(|_| SessionError::TooLarge("PCread result"))?
            }
            PC_WRITE => {
                if a2.cast_signed() < 0 {
                    -1
                } else {
                    s.check_write(a1.cast_signed(), u64::from(a2))?;
                    let data = if a2 > 0 {
                        self.read_mem(a3, a2).await?
                    } else {
                        Vec::new()
                    };
                    s.write(a1.cast_signed(), &data)?
                }
            }
            PC_LSEEK => s.seek(a0.cast_signed(), a2.cast_signed(), a3)?,
            _ => -1,
        })
    }
}

/// The two ways a PCDRV call can fail; either becomes -1 for the target.
#[derive(Debug, thiserror::Error)]
enum CallError {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Pcdrv(#[from] crate::pcdrv::PcdrvError),
}
