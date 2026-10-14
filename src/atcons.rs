//! ATCONS, the DTL-H2700's ISA card link (PROTOCOL.md section 2.1): a word
//! channel that carries the monitor's frames and a byte channel that carries
//! the console text of OpenBIOS's tty, each gated by a status port the host
//! polls. There is no line rate and no stream framing on the wire.
//!
//! [`AtconsTransport`] presents the two channels to a [`Session`] as one byte
//! stream in the SIO1 grammar (section 2.5), so the session, its frame parser
//! and everything above them run unchanged:
//!
//! - PS1 -> host: console bytes pass through (a `0x00`, which the tty never
//!   sends, is dropped); words are gathered into whole frames (SYNC, TYPE,
//!   LEN, LEN payload words, two CKSUM words; words before a SYNC are
//!   dropped) and handed on as `0x00` plus the frame's words, low byte first.
//! - host -> PS1: a `0x00` starts a frame, whose bytes are paired into words
//!   and written to the word channel, one per WRDY; any other byte outside a
//!   frame is console input and goes to the byte channel.
//!
//! The card is polled, so a thread owns the ports and spins on the status
//! port while words are moving and sleeps between polls when idle.
//!
//! Host ports, as offsets from the card's base (0x1340 on the reference
//! board), from the working C host (`transport_isa.c`, `h2x00-console-stream`):
//! 0 status, 1 byte channel, 2 word channel (16-bit), 4 control, 5 mode,
//! 6 reset mode. Status bits: 0x01 and 0x02 word available, 0x04 the card
//! takes a word (WRDY), 0x10 byte available (acknowledged by writing 0x20 to
//! control).
//!
//! [`Session`]: crate::session::Session

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::proto::SYNC;
use crate::transport::Transport;

/// I/O base of the reference board's card (set by DIP switches).
pub const DEFAULT_BASE: u16 = 0x1340;
/// Ports the card decodes from its base.
pub const PORT_COUNT: u16 = 8;

pub const STATUS: u16 = 0;
pub const BYTE: u16 = 1;
pub const WORD: u16 = 2;
pub const CTRL: u16 = 4;
pub const MODE: u16 = 5;
pub const RESET: u16 = 6;

/// A word from the PS1 is waiting: 0x02 for a burst, 0x01 for a single or
/// last word. Either one gates a word read.
pub const ST_WORD_RX: u8 = 0x03;
/// The card takes a word from the host.
pub const ST_WRDY: u8 = 0x04;
/// A console byte from the PS1 is waiting.
pub const ST_BYTE_RX: u8 = 0x10;
/// Written to CTRL after reading a byte.
pub const CTRL_BYTE_ACK: u8 = 0x20;

/// How long a word may wait for WRDY before the link counts as stuck; the C
/// host uses the same.
pub const WRDY_TIMEOUT: Duration = Duration::from_secs(1);
/// Idle polls before the pump thread starts sleeping between polls.
const SPIN_POLLS: u32 = 2000;
/// Sleep between polls of an idle link.
const IDLE_SLEEP: Duration = Duration::from_micros(200);
/// Console bytes gathered before they are handed on mid-burst.
const TTY_CHUNK: usize = 256;

/// Port access at offsets from the card's base.
pub trait Ports: Send + 'static {
    fn inb(&mut self, off: u16) -> u8;
    fn outb(&mut self, off: u16, v: u8);
    fn inw(&mut self, off: u16) -> u16;
    fn outw(&mut self, off: u16, v: u16);
}

/// `atcons` or `atcons:BASE` (decimal or `0x` hex): the card's base, or
/// None if `port` names something else (a serial device).
pub fn parse_port(port: &str) -> Option<Result<u16, String>> {
    let rest = port.strip_prefix("atcons")?;
    if rest.is_empty() {
        return Some(Ok(DEFAULT_BASE));
    }
    let spec = rest.strip_prefix(':')?;
    let parsed = match spec.strip_prefix("0x").or_else(|| spec.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16),
        None => spec.parse(),
    };
    Some(
        parsed
            .ok()
            .filter(|b| b.checked_add(PORT_COUNT).is_some())
            .ok_or_else(|| format!("{port}: bad ATCONS base (want atcons or atcons:0x1340)")),
    )
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
mod raw {
    use std::arch::asm;
    use std::io;

    use super::{PORT_COUNT, Ports};

    /// The card's ports through `in`/`out`, after `ioperm`. Needs root or
    /// CAP_SYS_RAWIO.
    pub struct IoPorts {
        base: u16,
    }

    impl IoPorts {
        pub fn open(base: u16) -> io::Result<Self> {
            // SAFETY: ioperm only changes this process's I/O permission bitmap.
            let r = unsafe {
                libc::ioperm(
                    libc::c_ulong::from(base),
                    libc::c_ulong::from(PORT_COUNT),
                    1,
                )
            };
            if r != 0 {
                let e = io::Error::last_os_error();
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "ioperm(0x{base:x}, {PORT_COUNT}): {e} (ATCONS port I/O needs root or CAP_SYS_RAWIO)"
                    ),
                ));
            }
            Ok(IoPorts { base })
        }

        /// The absolute port for `off`. `open` checked that base + 8 fits
        /// and every caller passes an offset below 8.
        fn port(&self, off: u16) -> u16 {
            self.base.wrapping_add(off % PORT_COUNT)
        }
    }

    // SAFETY (all four): `open` has granted this process the ports
    // base..base+8 and `port` keeps every access inside them. Port I/O
    // touches no memory Rust knows about.
    impl Ports for IoPorts {
        fn inb(&mut self, off: u16) -> u8 {
            let v: u8;
            unsafe {
                asm!("in al, dx", out("al") v, in("dx") self.port(off),
                     options(nomem, nostack, preserves_flags));
            }
            v
        }
        fn outb(&mut self, off: u16, v: u8) {
            unsafe {
                asm!("out dx, al", in("dx") self.port(off), in("al") v,
                     options(nomem, nostack, preserves_flags));
            }
        }
        fn inw(&mut self, off: u16) -> u16 {
            let v: u16;
            unsafe {
                asm!("in ax, dx", out("ax") v, in("dx") self.port(off),
                     options(nomem, nostack, preserves_flags));
            }
            v
        }
        fn outw(&mut self, off: u16, v: u16) {
            unsafe {
                asm!("out dx, ax", in("dx") self.port(off), in("ax") v,
                     options(nomem, nostack, preserves_flags));
            }
        }
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
pub use raw::IoPorts;

/// The card's ports. Only x86 Linux has port I/O from user space.
#[cfg(not(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64"))))]
pub struct IoPorts;

#[cfg(not(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64"))))]
impl IoPorts {
    pub fn open(_base: u16) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ATCONS needs port I/O, which psxmon has only on x86 Linux",
        ))
    }
}

#[cfg(not(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64"))))]
impl Ports for IoPorts {
    fn inb(&mut self, _off: u16) -> u8 {
        0
    }
    fn outb(&mut self, _off: u16, _v: u8) {}
    fn inw(&mut self, _off: u16) -> u16 {
        0
    }
    fn outw(&mut self, _off: u16, _v: u16) {}
}

/// Reset the card's PS1 into reset mode `mode` (7 boots the monitor in the
/// flash cave, anything else the stock BIOS), then, with `connect`, open the
/// card's host side as `h2x00-console-stream` does: the `0x04` connect byte
/// (which the monitor's tty takes as a keypress), mode bit 4, control 1,
/// then the reply byte and its acknowledge. Returns the reply byte, or None
/// if none came within two seconds.
pub fn reset_card<P: Ports>(p: &mut P, mode: u8, connect: bool) -> Option<u8> {
    const STEP: Duration = Duration::from_millis(50);
    p.outb(RESET, mode);
    std::thread::sleep(STEP);
    p.outb(CTRL, 0x71);
    std::thread::sleep(STEP);
    p.outb(MODE, 0x01);
    if !connect {
        return None;
    }
    p.outb(BYTE, 0x04);
    let m = p.inb(MODE);
    p.outb(MODE, m | 0x10);
    p.outb(CTRL, 0x01);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if p.inb(STATUS) & ST_BYTE_RX != 0 {
            let r = p.inb(BYTE);
            p.outb(CTRL, CTRL_BYTE_ACK);
            return Some(r);
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    None
}

/// One write to the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Out {
    Word(u16),
    Byte(u8),
}

/// host -> PS1: the session's byte stream to channel writes.
#[derive(Default)]
struct Encoder {
    /// Inside a frame: words so far, and the frame's length in words once
    /// LEN has been seen.
    frame: Option<(usize, Option<usize>)>,
    /// The low byte of a word in progress.
    lo: Option<u8>,
}

impl Encoder {
    fn push(&mut self, b: u8, out: &mut Vec<Out>) {
        let Some((words, total)) = self.frame.as_mut() else {
            if b == 0 {
                self.frame = Some((0, None));
            } else {
                out.push(Out::Byte(b));
            }
            return;
        };
        // More zeros before SYNC are the same frame start.
        if *words == 0 && self.lo.is_none() && b == 0 {
            return;
        }
        let Some(lo) = self.lo.take() else {
            self.lo = Some(b);
            return;
        };
        let w = u16::from_le_bytes([lo, b]);
        out.push(Out::Word(w));
        *words = words.saturating_add(1);
        if *words == 3 {
            // SYNC TYPE LEN, then LEN words and two of CKSUM.
            *total = Some(usize::from(w).saturating_add(5));
        }
        if Some(*words) == *total {
            self.frame = None;
        }
    }
}

/// PS1 -> host: words to whole frames in the stream grammar.
#[derive(Default)]
struct Decoder {
    words: Vec<u16>,
}

impl Decoder {
    /// A whole frame as stream bytes, once `w` completes one.
    fn push(&mut self, w: u16) -> Option<Vec<u8>> {
        if self.words.is_empty() && w != SYNC {
            return None;
        }
        self.words.push(w);
        let total = self
            .words
            .get(2)
            .map(|&len| usize::from(len).saturating_add(5))?;
        if self.words.len() < total {
            return None;
        }
        let mut bytes = Vec::with_capacity(total.saturating_mul(2).saturating_add(1));
        bytes.push(0);
        for w in self.words.drain(..) {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        Some(bytes)
    }
}

type Inbound = io::Result<Vec<u8>>;

/// The pump thread: poll the card, hand on what the PS1 sent, write what the
/// host queued. Ends when the transport is dropped and everything queued has
/// been written, or when a word waits for WRDY longer than [`WRDY_TIMEOUT`].
fn pump<P: Ports>(mut p: P, cmds: mpsc::Receiver<Vec<Out>>, inbound: UnboundedSender<Inbound>) {
    let mut out: VecDeque<Out> = VecDeque::new();
    let mut dec = Decoder::default();
    let mut tty: Vec<u8> = Vec::new();
    let mut wrdy_since: Option<Instant> = None;
    let mut idle: u32 = 0;
    let mut open = true;
    loop {
        while open {
            match cmds.try_recv() {
                Ok(v) => out.extend(v),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => open = false,
            }
        }
        if (!open && out.is_empty()) || inbound.is_closed() {
            return;
        }
        let st = p.inb(STATUS);
        let mut busy = false;
        if st & ST_BYTE_RX != 0 {
            let b = p.inb(BYTE);
            p.outb(CTRL, CTRL_BYTE_ACK);
            if b != 0 {
                tty.push(b);
            }
            busy = true;
        }
        if st & ST_WORD_RX != 0 {
            if let Some(frame) = dec.push(p.inw(WORD)) {
                if !tty.is_empty() {
                    let _ = inbound.send(Ok(std::mem::take(&mut tty)));
                }
                let _ = inbound.send(Ok(frame));
            }
            busy = true;
        }
        match out.front().copied() {
            Some(Out::Byte(b)) => {
                p.outb(BYTE, b);
                out.pop_front();
                busy = true;
            }
            Some(Out::Word(w)) if st & ST_WRDY != 0 => {
                p.outw(WORD, w);
                out.pop_front();
                wrdy_since = None;
                busy = true;
            }
            Some(Out::Word(_)) => {
                let since = *wrdy_since.get_or_insert_with(Instant::now);
                if since.elapsed() > WRDY_TIMEOUT {
                    let _ = inbound.send(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "ATCONS: the card took no word for {} ms (WRDY); {} words dropped",
                            WRDY_TIMEOUT.as_millis(),
                            out.len()
                        ),
                    )));
                    out.clear();
                    wrdy_since = None;
                }
            }
            None => {}
        }
        if !tty.is_empty() && (!busy || tty.len() >= TTY_CHUNK) {
            let _ = inbound.send(Ok(std::mem::take(&mut tty)));
        }
        if busy || !out.is_empty() {
            idle = 0;
            continue;
        }
        idle = idle.saturating_add(1);
        if idle > SPIN_POLLS && open {
            match cmds.recv_timeout(IDLE_SLEEP) {
                Ok(v) => out.extend(v),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => open = false,
            }
        }
    }
}

/// The ATCONS card as a session transport. See the module documentation.
pub struct AtconsTransport {
    cmds: Option<mpsc::Sender<Vec<Out>>>,
    inbound: UnboundedReceiver<Inbound>,
    /// Received bytes not yet read, from `at`.
    buf: Vec<u8>,
    at: usize,
    enc: Encoder,
    thread: Option<JoinHandle<()>>,
}

impl AtconsTransport {
    /// Open the card at `base` through port I/O.
    pub fn open(base: u16) -> io::Result<Self> {
        IoPorts::open(base).map(Self::with_ports)
    }

    /// Run the link over `ports` (a real card, or a model of one).
    pub fn with_ports<P: Ports>(ports: P) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (in_tx, in_rx) = unbounded_channel();
        let thread = std::thread::spawn(move || pump(ports, cmd_rx, in_tx));
        AtconsTransport {
            cmds: Some(cmd_tx),
            inbound: in_rx,
            buf: Vec::new(),
            at: 0,
            enc: Encoder::default(),
            thread: Some(thread),
        }
    }
}

impl Drop for AtconsTransport {
    fn drop(&mut self) {
        // Closing the command channel lets the thread write what is queued
        // (bounded by the WRDY timeout) and end.
        self.cmds = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Transport for AtconsTransport {
    fn set_baud_rate(&mut self, _baud: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ATCONS has no line rate",
        ))
    }

    /// 0: the link has no line rate.
    fn baud_rate(&self) -> u32 {
        0
    }

    fn byte_stream(&self) -> bool {
        false
    }
}

impl AsyncRead for AtconsTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.at >= this.buf.len() {
            match this.inbound.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // The pump thread is gone: end of stream.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(Some(Ok(bytes))) => {
                    this.buf = bytes;
                    this.at = 0;
                }
            }
        }
        let rest = this.buf.get(this.at..).unwrap_or_default();
        let n = rest.len().min(out.remaining());
        out.put_slice(rest.get(..n).unwrap_or_default());
        this.at = this.at.saturating_add(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AtconsTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let mut outs = Vec::with_capacity(bytes.len().div_ceil(2));
        for &b in bytes {
            this.enc.push(b, &mut outs);
        }
        let sent = this
            .cmds
            .as_ref()
            .is_some_and(|c| outs.is_empty() || c.send(outs).is_ok());
        Poll::Ready(if sent {
            Ok(bytes.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ATCONS pump thread has stopped",
            ))
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::frame::{Event, Parser, encode_frame};
    use crate::proto::{HELLO, PING, PONG, READ_MEM};
    use crate::session::Session;

    #[test]
    fn port_spec() {
        assert_eq!(parse_port("/dev/ttyUSB0"), None);
        assert_eq!(parse_port("atcons"), Some(Ok(DEFAULT_BASE)));
        assert_eq!(parse_port("atcons:0x300"), Some(Ok(0x300)));
        assert_eq!(parse_port("atcons:4928"), Some(Ok(0x1340)));
        assert!(matches!(parse_port("atcons:zz"), Some(Err(_))));
        assert!(matches!(parse_port("atcons:0xfffc"), Some(Err(_))));
        assert_eq!(parse_port("atconsx"), None);
    }

    #[test]
    fn encoder_splits_frames_from_console_input() {
        let mut enc = Encoder::default();
        let mut out = Vec::new();
        let mut wire = b"hi".to_vec();
        wire.extend(encode_frame(READ_MEM, &[1, 2, 3, 4]).expect("frame"));
        wire.push(b'!');
        wire.extend(encode_frame(PING, &[]).expect("frame"));
        for b in wire {
            enc.push(b, &mut out);
        }
        let ck = |ty: u16, p: &[u16]| {
            crate::frame::split_u32(crate::frame::fletcher(
                [ty, u16::try_from(p.len()).expect("len")]
                    .into_iter()
                    .chain(p.iter().copied()),
            ))
        };
        let mut want = vec![Out::Byte(b'h'), Out::Byte(b'i')];
        want.extend(
            [SYNC, READ_MEM, 4, 1, 2, 3, 4]
                .into_iter()
                .chain(ck(READ_MEM, &[1, 2, 3, 4]))
                .map(Out::Word),
        );
        want.push(Out::Byte(b'!'));
        want.extend(
            [SYNC, PING, 0]
                .into_iter()
                .chain(ck(PING, &[]))
                .map(Out::Word),
        );
        assert_eq!(out, want);
        // Zero words inside a frame are data.
        let mut out = Vec::new();
        for b in encode_frame(READ_MEM, &[0, 0]).expect("frame") {
            enc.push(b, &mut out);
        }
        assert_eq!(out.len(), 7);
        assert!(enc.frame.is_none());
    }

    #[test]
    fn decoder_resyncs_and_frames_parse() {
        let mut dec = Decoder::default();
        let words = [0x1234u16, 0, SYNC, PONG, 2, 0, 0x55aa, 0x1111, 0x2222];
        let mut got = Vec::new();
        for w in words {
            got.extend(dec.push(w));
        }
        assert_eq!(got.len(), 1);
        let mut p = Parser::new();
        p.feed(got.first().expect("frame"));
        match p.next_event() {
            Some(Event::Frame(f)) => {
                assert_eq!((f.ty, f.words.as_slice()), (PONG, &[0u16, 0x55aa][..]));
            }
            other => panic!("{other:?}"),
        }
    }

    /// The card as the host sees it, with the monitor behind it reduced to
    /// "answer each PING with a PONG".
    #[derive(Default)]
    struct Card {
        to_host_words: VecDeque<u16>,
        to_host_bytes: VecDeque<u8>,
        from_host_words: Vec<u16>,
        from_host_bytes: Vec<u8>,
        acks: usize,
        /// Refuse words (WRDY low).
        full: bool,
    }

    #[derive(Clone, Default)]
    struct Model(Arc<Mutex<Card>>);

    impl Model {
        fn card(&self) -> std::sync::MutexGuard<'_, Card> {
            self.0.lock().expect("card")
        }
    }

    fn frame_words(ty: u16, payload: &[u16]) -> Vec<u16> {
        let bytes = encode_frame(ty, payload).expect("frame");
        bytes
            .get(1..)
            .expect("words")
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect()
    }

    impl Ports for Model {
        fn inb(&mut self, off: u16) -> u8 {
            let mut c = self.card();
            match off {
                STATUS => {
                    let mut st = 0;
                    if !c.to_host_words.is_empty() {
                        st |= 0x01;
                    }
                    if !c.to_host_bytes.is_empty() {
                        st |= ST_BYTE_RX;
                    }
                    if !c.full {
                        st |= ST_WRDY;
                    }
                    st
                }
                BYTE => c.to_host_bytes.pop_front().unwrap_or(0xff),
                _ => 0,
            }
        }
        fn outb(&mut self, off: u16, v: u8) {
            let mut c = self.card();
            match (off, v) {
                (CTRL, CTRL_BYTE_ACK) => c.acks = c.acks.saturating_add(1),
                (BYTE, _) => c.from_host_bytes.push(v),
                _ => {}
            }
        }
        fn inw(&mut self, _off: u16) -> u16 {
            self.card().to_host_words.pop_front().unwrap_or(0xffff)
        }
        fn outw(&mut self, _off: u16, v: u16) {
            let mut c = self.card();
            c.from_host_words.push(v);
            let ping = frame_words(PING, &[]);
            if c.from_host_words.ends_with(&ping) {
                c.from_host_words.clear();
                let pong = frame_words(PONG, &[2, 1, 0x5678, 0x1234]);
                c.to_host_words.extend(pong);
            }
        }
    }

    #[tokio::test]
    async fn session_attaches_over_the_card() {
        let model = Model::default();
        {
            let mut c = model.card();
            // What sits on the card after a boot: the banner and a HELLO.
            c.to_host_bytes.extend(b"OpenBIOS Monitor.\n");
            c.to_host_words.push_back(0x0bad);
            c.to_host_words
                .extend(frame_words(HELLO, &[2, 1, 0x5678, 0x1234]));
        }
        let mut s = Session::new(AtconsTransport::with_ports(model.clone()));
        let hello = s
            .wait_frame(
                &[HELLO],
                crate::session::deadline_after(Duration::from_secs(2)),
            )
            .await
            .expect("io")
            .expect("hello");
        assert_eq!(hello.words, vec![2, 1, 0x5678, 0x1234]);
        assert!(s.ping(Duration::from_secs(2), &[]).await.expect("ping"));
        assert_eq!((s.version, s.caps, s.bios), (Some(2), 1, Some(0x1234_5678)));
        assert_eq!(s.take_text(), b"OpenBIOS Monitor.\n");
        assert!(s.transport().set_baud_rate(115_200).is_err());
        drop(s);
        let c = model.card();
        assert_eq!(c.acks, 18);
        assert!(c.from_host_bytes.is_empty());
    }

    #[tokio::test]
    async fn a_stuck_card_is_an_error_not_a_hang() {
        let model = Model::default();
        model.card().full = true;
        let mut s = Session::new(AtconsTransport::with_ports(model.clone()));
        let r = s.ping(Duration::from_secs(3), &[]).await;
        assert!(
            matches!(&r, Err(crate::SessionError::Io(e)) if e.kind() == io::ErrorKind::TimedOut),
            "{r:?}"
        );
    }
}
