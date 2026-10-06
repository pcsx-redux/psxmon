//! Byte links a session runs over: a serial port, a TCP connection, or an
//! in-memory pipe for tests.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc as std_mpsc;
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::Duration;

use serialport::SerialPort;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

/// An async byte link with a settable line rate.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {
    /// Change the host side's line rate on the open link.
    fn set_baud_rate(&mut self, baud: u32) -> io::Result<()>;
    fn baud_rate(&self) -> u32;
}

/// How long the I/O thread blocks in one read before it looks at its
/// command queue again: the most a write waits on an idle link.
const POLL: Duration = Duration::from_millis(2);

/// The most the I/O thread writes before it drains what has arrived.
const WRITE_CHUNK: usize = 256;

enum Cmd {
    Write(Vec<u8>),
    Flush(oneshot::Sender<()>),
    SetBaud(u32, std_mpsc::Sender<io::Result<()>>),
}

/// A serial port, 8N1, no flow control on the host side.
///
/// One OS thread owns the blocking port: it reads with a short timeout and
/// hands what arrives to the async side over a channel, and between reads it
/// runs the writes and rate changes queued by the async side, in order. An
/// async read is then only a channel receive, so dropping one (a timed-out
/// `wait_frame`) never touches the port.
pub struct SerialTransport {
    rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    chunk: Vec<u8>,
    pos: usize,
    cmd: Option<std_mpsc::Sender<Cmd>>,
    flush: Option<oneshot::Receiver<()>>,
    thread: Option<JoinHandle<()>>,
    baud: u32,
}

impl SerialTransport {
    pub fn open(path: &str, baud: u32) -> io::Result<Self> {
        let mut port = serialport::new(path, baud)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(POLL)
            .open()
            .map_err(io::Error::from)?;
        raise_modem_lines(&mut port);
        port.clear(serialport::ClearBuffer::All)
            .map_err(io::Error::from)?;
        Self::from_port(port, baud)
    }

    /// Run a session over an open port whose read timeout is short.
    pub fn from_port(port: Box<dyn SerialPort>, baud: u32) -> io::Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let (cmd, cmds) = std_mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("serial-io".into())
            .spawn(move || io_thread(port, &tx, &cmds))?;
        Ok(SerialTransport {
            rx,
            chunk: Vec::new(),
            pos: 0,
            cmd: Some(cmd),
            flush: None,
            thread: Some(thread),
            baud,
        })
    }

    fn command(&self, c: Cmd) -> io::Result<()> {
        self.cmd
            .as_ref()
            .and_then(|q| q.send(c).ok())
            .ok_or_else(closed)
    }
}

/// The PS1 transmits only while the host holds RTS up (its CTS). A pty has
/// no modem lines, so a failure here is not fatal. On Windows every
/// SetCommState, which a rate change goes through, re-applies the DCB's
/// RTS_CONTROL_DISABLE and drops RTS, so this runs after each one too.
fn raise_modem_lines(port: &mut Box<dyn SerialPort>) {
    let _ = port.write_request_to_send(true);
    let _ = port.write_data_terminal_ready(true);
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "serial I/O thread has stopped")
}

fn transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// Pass on what `read` returned. False when the thread should stop.
fn deliver(
    got: io::Result<usize>,
    buf: &[u8],
    tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
) -> bool {
    match got {
        Ok(0) => false,
        Ok(n) => tx
            .send(Ok(buf.get(..n).unwrap_or_default().to_vec()))
            .is_ok(),
        Err(e) if transient(&e) => true,
        Err(e) => {
            let _ = tx.send(Err(e));
            false
        }
    }
}

/// Read what is already buffered, without waiting. False to stop.
fn drain(
    port: &mut Box<dyn SerialPort>,
    buf: &mut [u8],
    tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
) -> bool {
    let ready = port
        .bytes_to_read()
        .ok()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0);
    if ready == 0 {
        return true;
    }
    let want = ready.min(buf.len());
    let got = port.read(buf.get_mut(..want).unwrap_or_default());
    deliver(got, buf, tx)
}

/// Write all of `data`, draining input between chunks so a long write does
/// not overrun the receive buffer. False to stop.
fn write_out(
    port: &mut Box<dyn SerialPort>,
    mut data: &[u8],
    buf: &mut [u8],
    tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
) -> bool {
    while !data.is_empty() {
        let take = data.len().min(WRITE_CHUNK);
        match port.write(data.get(..take).unwrap_or_default()) {
            Ok(n) => data = data.get(n..).unwrap_or_default(),
            Err(e) if transient(&e) => {}
            Err(e) => {
                let _ = tx.send(Err(e));
                return false;
            }
        }
        if !drain(port, buf, tx) {
            return false;
        }
    }
    true
}

fn io_thread(
    mut port: Box<dyn SerialPort>,
    tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    cmds: &std_mpsc::Receiver<Cmd>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        loop {
            match cmds.try_recv() {
                Ok(Cmd::Write(data)) => {
                    if !write_out(&mut port, &data, &mut buf, tx) {
                        return;
                    }
                }
                Ok(Cmd::Flush(done)) => {
                    let _ = done.send(());
                }
                Ok(Cmd::SetBaud(baud, done)) => {
                    let r = port.set_baud_rate(baud).map_err(io::Error::from);
                    raise_modem_lines(&mut port);
                    let _ = done.send(r);
                }
                Err(std_mpsc::TryRecvError::Empty) => break,
                Err(std_mpsc::TryRecvError::Disconnected) => return,
            }
        }
        let got = port.read(&mut buf);
        if !deliver(got, &buf, tx) {
            return;
        }
    }
}

impl Drop for SerialTransport {
    fn drop(&mut self) {
        // The thread sees the closed queue after at most one read timeout
        // and closes the port.
        self.cmd = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Transport for SerialTransport {
    fn set_baud_rate(&mut self, baud: u32) -> io::Result<()> {
        // Queued behind the writes before it, so a frame sent at the old
        // rate goes out at the old rate. Bytes read before the change are
        // already in the channel.
        let (done, wait) = std_mpsc::channel();
        self.command(Cmd::SetBaud(baud, done))?;
        wait.recv().map_err(|_| closed())??;
        self.baud = baud;
        Ok(())
    }

    fn baud_rate(&self) -> u32 {
        self.baud
    }
}

impl AsyncRead for SerialTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.pos >= this.chunk.len() {
            match this.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // The thread stopped at end of file.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(Some(Ok(bytes))) => {
                    this.chunk = bytes;
                    this.pos = 0;
                }
            }
        }
        let rest = this.chunk.get(this.pos..).unwrap_or_default();
        let n = rest.len().min(buf.remaining());
        buf.put_slice(rest.get(..n).unwrap_or_default());
        this.pos = this.pos.saturating_add(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SerialTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.command(Cmd::Write(buf.to_vec())).map(|()| buf.len()))
    }

    /// Ready once the I/O thread has handed every earlier write to the OS.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.flush.is_none() {
            let (done, wait) = oneshot::channel();
            this.command(Cmd::Flush(done))?;
            this.flush = Some(wait);
        }
        let Some(wait) = this.flush.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(wait).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => {
                this.flush = None;
                Poll::Ready(r.map_err(|_| closed()))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// The `HOST:PORT` of a `--port` that names a TCP link: `tcp:HOST:PORT` or
/// `tcp://HOST:PORT`. None for any other port.
pub fn parse_tcp_port(port: &str) -> Option<&str> {
    port.strip_prefix("tcp://")
        .or_else(|| port.strip_prefix("tcp:"))
}

/// A TCP connection to something that bridges to the monitor's byte stream:
/// PCSX-Redux's SIO1 server, or a serial-to-TCP bridge. The line rate is the
/// far end's business, so there is none here.
pub struct TcpTransport {
    io: TcpStream,
}

impl TcpTransport {
    /// Connect to `addr` (`HOST:PORT`; an IPv6 host in brackets).
    pub async fn connect(addr: &str) -> io::Result<Self> {
        let io = TcpStream::connect(addr).await?;
        // Frames are small and each waits for its reply.
        io.set_nodelay(true)?;
        Ok(TcpTransport { io })
    }
}

impl Transport for TcpTransport {
    fn set_baud_rate(&mut self, _baud: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a TCP link has no line rate",
        ))
    }

    /// 0: the link has no line rate.
    fn baud_rate(&self) -> u32 {
        0
    }
}

impl AsyncRead for TcpTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// One end of an in-memory byte pipe. The host end's line rate is shared
/// with whoever holds the other end (a simulator can garble bytes when the
/// two sides disagree on it).
pub struct MemTransport {
    io: DuplexStream,
    baud: Arc<AtomicU32>,
}

impl MemTransport {
    /// A connected pair: (host end, device end, the host end's rate cell).
    pub fn pair(baud: u32) -> (MemTransport, DuplexStream, Arc<AtomicU32>) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let cell = Arc::new(AtomicU32::new(baud));
        (
            MemTransport {
                io: a,
                baud: cell.clone(),
            },
            b,
            cell,
        )
    }
}

impl Transport for MemTransport {
    fn set_baud_rate(&mut self, baud: u32) -> io::Result<()> {
        self.baud.store(baud, Ordering::SeqCst);
        Ok(())
    }

    fn baud_rate(&self) -> u32 {
        self.baud.load(Ordering::SeqCst)
    }
}

impl AsyncRead for MemTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for MemTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Any transport, chosen at run time (a serial port, TCP, or the ATCONS
/// card).
impl<T: Transport + ?Sized> Transport for Box<T> {
    fn set_baud_rate(&mut self, baud: u32) -> io::Result<()> {
        (**self).set_baud_rate(baud)
    }

    fn baud_rate(&self) -> u32 {
        (**self).baud_rate()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read, Write};
    use std::time::Duration;

    use serialport::{SerialPort, TTYPort};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    use super::{POLL, SerialTransport, TcpTransport, Transport, parse_tcp_port};

    /// A read abandoned at its deadline leaves the link usable: the next
    /// read gets the bytes, writes still go out, and so does a rate change.
    #[tokio::test]
    async fn timed_out_read_then_read() {
        let (mut far, mut near) = TTYPort::pair().expect("pty pair");
        near.set_timeout(POLL).expect("timeout");
        far.set_timeout(Duration::from_secs(2)).expect("timeout");
        let mut link = SerialTransport::from_port(Box::new(near), 9600).expect("transport");
        let mut buf = [0u8; 16];

        let idle = timeout(Duration::from_millis(50), link.read(&mut buf)).await;
        assert!(idle.is_err(), "read with nothing sent returned {idle:?}");

        far.write_all(b"hello").expect("far write");
        let n = timeout(Duration::from_secs(2), link.read(&mut buf))
            .await
            .expect("read after timeout")
            .expect("read");
        assert_eq!(buf.get(..n), Some(&b"hello"[..]));

        link.set_baud_rate(115_200).expect("rate");
        assert_eq!(link.baud_rate(), 115_200);
        link.write_all(b"ping").await.expect("write");
        link.flush().await.expect("flush");
        let mut got = [0u8; 4];
        far.read_exact(&mut got).expect("far read");
        assert_eq!(&got, b"ping");

        let idle = timeout(Duration::from_millis(50), link.read(&mut buf)).await;
        assert!(idle.is_err(), "read with nothing sent returned {idle:?}");
        far.write_all(b"again").expect("far write");
        let mut got = [0u8; 5];
        timeout(Duration::from_secs(2), link.read_exact(&mut got))
            .await
            .expect("read after second timeout")
            .expect("read");
        assert_eq!(&got, b"again");
    }

    #[test]
    fn tcp_port_forms() {
        assert_eq!(parse_tcp_port("tcp:127.0.0.1:6699"), Some("127.0.0.1:6699"));
        assert_eq!(parse_tcp_port("tcp://host:1"), Some("host:1"));
        assert_eq!(parse_tcp_port("tcp:[::1]:6699"), Some("[::1]:6699"));
        assert_eq!(parse_tcp_port("/dev/ttyUSB0"), None);
        assert_eq!(parse_tcp_port("atcons"), None);
    }

    /// Bytes go both ways over TCP, and a rate change is refused.
    #[tokio::test]
    async fn tcp_round_trip_and_no_rate() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let far = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut got = [0u8; 4];
            sock.read_exact(&mut got).await.expect("far read");
            sock.write_all(b"pong").await.expect("far write");
            got
        });
        let mut link = TcpTransport::connect(&addr).await.expect("connect");
        assert_eq!(link.baud_rate(), 0);
        assert!(link.set_baud_rate(115_200).is_err());
        link.write_all(b"ping").await.expect("write");
        link.flush().await.expect("flush");
        let mut got = [0u8; 4];
        timeout(Duration::from_secs(2), link.read_exact(&mut got))
            .await
            .expect("reply in time")
            .expect("read");
        assert_eq!(&got, b"pong");
        assert_eq!(&far.await.expect("far"), b"ping");
    }
}
