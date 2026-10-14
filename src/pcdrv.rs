//! PCDRV host file server, rooted at a directory. Names from the target are
//! flattened (backslashes to slashes, leading slashes dropped), resolved
//! lexically against the root, and refused if they land outside it. Writes
//! are held to per-file, per-run and file-count quotas, and a single read is
//! capped, since the target picks every length. Mirrors runner-agent
//! `unirom/pcdrv.ts`.
//!
//! With networking enabled, `tcp://HOST:PORT` opens a TCP connection in the
//! same handle space; reads on it never block. `probe:net` opens only when
//! networking is enabled. Neither name, nor any other `scheme://` name, ever
//! reaches the file system.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Cap on bytes written to one file.
    pub per_file_bytes: u64,
    /// Cap on bytes written across the run.
    pub total_bytes: u64,
    /// Cap on files created across the run.
    pub file_count: u32,
}

impl Default for Quota {
    fn default() -> Self {
        Quota {
            per_file_bytes: 16 << 20,
            total_bytes: 64 << 20,
            file_count: 256,
        }
    }
}

/// Ceiling on one PCread: the length comes from the target's a2.
pub const MAX_READ_BYTES: u32 = 2 << 20;

/// Longest wait for a `tcp://` connect, and for one socket write.
pub const NET_TIMEOUT: Duration = Duration::from_secs(5);

/// The name that opens only when networking is enabled.
pub const NET_PROBE: &[u8] = b"probe:net";

/// Which `tcp://` targets the target may open.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetPolicy {
    /// Off: every `tcp://` and `probe:net` open fails.
    pub enabled: bool,
    /// `HOST:PORT` targets allowed, matched literally against what the
    /// target wrote after `tcp://`. Empty allows any.
    pub allow: Vec<String>,
}

/// Split `HOST:PORT` (IPv6 hosts in brackets) into host and port.
pub fn parse_net_target(text: &str) -> Result<(&str, u16), PcdrvError> {
    let bad = || PcdrvError::Net(format!("not HOST:PORT: {text}"));
    let (host, port) = text.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    if host.is_empty() {
        return Err(bad());
    }
    Ok((host, port))
}

#[derive(Debug, thiserror::Error)]
pub enum PcdrvError {
    #[error("path escapes base: {0}")]
    Escape(String),
    #[error("bad PCDRV handle {0}")]
    BadHandle(i32),
    #[error("{0}")]
    Quota(String),
    #[error("{0} out of range")]
    Range(&'static str),
    #[error("no PCDRV directory: file I/O is off")]
    NoFiles,
    #[error("{0}")]
    Net(String),
    #[error("{0} not supported on this handle")]
    Unsupported(&'static str),
    #[error("connection closed by peer")]
    Closed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

struct OpenFile {
    file: File,
    pos: u64,
    written: u64,
}

enum Handle {
    File(OpenFile),
    Socket(TcpStream),
    Probe,
}

/// What a target-supplied name asks for.
enum Target<'a> {
    File,
    Probe,
    Tcp(&'a str),
    BadScheme(&'a str),
}

fn classify(text: &str) -> Target<'_> {
    if text.as_bytes() == NET_PROBE {
        return Target::Probe;
    }
    match text.split_once("://") {
        Some(("tcp", rest)) => Target::Tcp(rest),
        Some((scheme, _)) => Target::BadScheme(scheme),
        None => Target::File,
    }
}

pub struct PcdrvServer {
    base: Option<PathBuf>,
    net: NetPolicy,
    files: BTreeMap<i32, Handle>,
    next_fd: i32,
    quota: Quota,
    total_bytes: u64,
    created: u32,
}

/// `path` with `.` and `..` folded away without touching the file system,
/// as node's `path.resolve` does. `..` at the root stays at the root.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

impl PcdrvServer {
    pub fn new(base: impl AsRef<Path>, quota: Quota) -> std::io::Result<Self> {
        let base = normalize(&std::path::absolute(base.as_ref())?);
        Ok(PcdrvServer {
            base: Some(base),
            ..Self::without_files(quota)
        })
    }

    /// A server with no file root: every file open fails, so only
    /// `tcp://` and `probe:net` (once networking is enabled) can open.
    pub fn without_files(quota: Quota) -> Self {
        PcdrvServer {
            base: None,
            net: NetPolicy::default(),
            files: BTreeMap::new(),
            next_fd: 3,
            quota,
            total_bytes: 0,
            created: 0,
        }
    }

    /// Set which `tcp://` targets may be opened; off by default.
    pub fn set_net(&mut self, net: NetPolicy) {
        self.net = net;
    }

    pub fn base(&self) -> Option<&Path> {
        self.base.as_deref()
    }

    /// Where a target-supplied name lands under the base, or an error if it
    /// would escape it, or there is no base. Names are Latin-1 on the
    /// target side.
    pub fn resolve_name(&self, name: &[u8]) -> Result<PathBuf, PcdrvError> {
        let base = self.base.as_ref().ok_or(PcdrvError::NoFiles)?;
        let text = latin1(name);
        let text = text.replace('\\', "/");
        let relative = text.trim_start_matches('/');
        let path = normalize(&base.join(relative));
        if path != *base && !path.starts_with(base) {
            return Err(PcdrvError::Escape(relative.to_owned()));
        }
        Ok(path)
    }

    fn alloc(&mut self, handle_of: Handle) -> Result<i32, PcdrvError> {
        let handle = self.next_fd;
        self.next_fd = handle
            .checked_add(1)
            .ok_or(PcdrvError::Range("file handles"))?;
        self.files.insert(handle, handle_of);
        Ok(handle)
    }

    fn alloc_file(&mut self, file: File) -> Result<i32, PcdrvError> {
        self.alloc(Handle::File(OpenFile {
            file,
            pos: 0,
            written: 0,
        }))
    }

    fn net_enabled(&self) -> Result<(), PcdrvError> {
        if self.net.enabled {
            Ok(())
        } else {
            Err(PcdrvError::Net("networking is off (--pcdrv-net)".into()))
        }
    }

    /// Connect to `HOST:PORT` if the policy allows it.
    fn connect(&self, target: &str) -> Result<TcpStream, PcdrvError> {
        self.net_enabled()?;
        let (host, port) = parse_net_target(target)?;
        if !self.net.allow.is_empty() && !self.net.allow.iter().any(|a| a == target) {
            return Err(PcdrvError::Net(format!(
                "{target} not in --pcdrv-net-allow"
            )));
        }
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let mut last = None;
        for addr in (bare, port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, NET_TIMEOUT) {
                Ok(stream) => {
                    stream.set_nonblocking(true)?;
                    stream.set_write_timeout(Some(NET_TIMEOUT))?;
                    stream.set_nodelay(true)?;
                    return Ok(stream);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(
            || PcdrvError::Net(format!("{target}: no address")),
            PcdrvError::Io,
        ))
    }

    /// Open a non-file name; `None` for a plain file name.
    fn open_special(&mut self, text: &str) -> Option<Result<i32, PcdrvError>> {
        Some(match classify(text) {
            Target::File => return None,
            Target::Probe => self.net_enabled().and_then(|()| self.alloc(Handle::Probe)),
            Target::Tcp(target) => self
                .connect(target)
                .and_then(|stream| self.alloc(Handle::Socket(stream))),
            Target::BadScheme(scheme) => Err(PcdrvError::Net(format!(
                "unsupported scheme {scheme}:// (only tcp://)"
            ))),
        })
    }

    /// PCcreat: create or truncate for reading and writing.
    pub fn create(&mut self, name: &[u8]) -> Result<i32, PcdrvError> {
        if !matches!(classify(&latin1(name)), Target::File) {
            return Err(PcdrvError::Unsupported("PCcreat of a network name"));
        }
        if self.created >= self.quota.file_count {
            return Err(PcdrvError::Quota(format!(
                "output file count quota exceeded ({})",
                self.quota.file_count
            )));
        }
        let path = self.resolve_name(name)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        self.created = self.created.saturating_add(1);
        self.alloc_file(file)
    }

    /// PCopen: bit 0 of `flags` opens for writing too. `tcp://HOST:PORT`
    /// connects instead, and `probe:net` opens a dummy handle; both only
    /// when networking is enabled.
    pub fn open(&mut self, name: &[u8], flags: u32) -> Result<i32, PcdrvError> {
        if let Some(r) = self.open_special(&latin1(name)) {
            return r;
        }
        let path = self.resolve_name(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(flags & 1 != 0)
            .open(&path)?;
        self.alloc_file(file)
    }

    /// PCclose: 0, also for a handle that is not open.
    pub fn close(&mut self, handle: i32) -> i32 {
        self.files.remove(&handle);
        0
    }

    fn expect(&mut self, handle: i32) -> Result<&mut Handle, PcdrvError> {
        self.files
            .get_mut(&handle)
            .ok_or(PcdrvError::BadHandle(handle))
    }

    /// Refuse a write of `length` bytes before its payload is fetched from
    /// the target, if it would breach a quota. Sockets have no quota.
    pub fn check_write(&mut self, handle: i32, length: u64) -> Result<(), PcdrvError> {
        let (quota, total) = (self.quota, self.total_bytes);
        let f = match self.expect(handle)? {
            Handle::File(f) => f,
            Handle::Socket(_) => return Ok(()),
            Handle::Probe => return Err(PcdrvError::Unsupported("PCwrite")),
        };
        if f.written.saturating_add(length) > quota.per_file_bytes {
            return Err(PcdrvError::Quota(format!(
                "per-file output quota exceeded (cap {} bytes)",
                quota.per_file_bytes
            )));
        }
        if total.saturating_add(length) > quota.total_bytes {
            return Err(PcdrvError::Quota(format!(
                "total output quota exceeded (cap {} bytes)",
                quota.total_bytes
            )));
        }
        Ok(())
    }

    /// PCwrite at the handle's position; returns the byte count.
    pub fn write(&mut self, handle: i32, data: &[u8]) -> Result<i32, PcdrvError> {
        let result = i32::try_from(data.len()).map_err(|_| PcdrvError::Range("PCwrite length"))?;
        let len = u64::try_from(data.len()).map_err(|_| PcdrvError::Range("PCwrite length"))?;
        self.check_write(handle, len)?;
        let f = match self.expect(handle)? {
            Handle::File(f) => f,
            Handle::Socket(stream) => {
                // Blocking for the write alone, bounded by NET_TIMEOUT.
                stream.set_nonblocking(false)?;
                let sent = stream.write_all(data);
                stream.set_nonblocking(true)?;
                sent?;
                return Ok(result);
            }
            Handle::Probe => return Err(PcdrvError::Unsupported("PCwrite")),
        };
        f.file.seek(SeekFrom::Start(f.pos))?;
        f.file.write_all(data)?;
        // Bounded by the quotas checked above.
        f.pos = f.pos.saturating_add(len);
        f.written = f.written.saturating_add(len);
        self.total_bytes = self.total_bytes.saturating_add(len);
        Ok(result)
    }

    /// PCread of up to `length` bytes at the handle's position. On a socket,
    /// whatever has arrived, possibly nothing, without waiting; a closed
    /// connection is an error.
    pub fn read(&mut self, handle: i32, length: u32) -> Result<Vec<u8>, PcdrvError> {
        let h = self.expect(handle)?;
        if length > MAX_READ_BYTES {
            return Err(PcdrvError::Quota(format!(
                "read length quota exceeded (cap {MAX_READ_BYTES} bytes)"
            )));
        }
        let f = match h {
            Handle::File(f) => f,
            Handle::Socket(stream) => return read_socket(stream, length),
            Handle::Probe => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        f.file.seek(SeekFrom::Start(f.pos))?;
        let n = (&mut f.file)
            .take(u64::from(length))
            .read_to_end(&mut out)?;
        f.pos = f
            .pos
            .saturating_add(u64::try_from(n).map_err(|_| PcdrvError::Range("PCread"))?);
        Ok(out)
    }

    /// PClseek: whence 0 set, 1 current, 2 end; a negative result clamps to 0.
    pub fn seek(&mut self, handle: i32, offset: i32, whence: u32) -> Result<i32, PcdrvError> {
        let Handle::File(f) = self.expect(handle)? else {
            return Err(PcdrvError::Unsupported("PClseek"));
        };
        let range = |_| PcdrvError::Range("PClseek position");
        let base = match whence {
            1 => i64::try_from(f.pos).map_err(range)?,
            2 => i64::try_from(f.file.metadata()?.len()).map_err(range)?,
            _ => 0,
        };
        let pos = base.saturating_add(i64::from(offset)).max(0);
        // The target gets the position back as an int.
        let result = i32::try_from(pos).map_err(range)?;
        f.pos = u64::try_from(pos).map_err(range)?;
        Ok(result)
    }

    pub fn close_all(&mut self) {
        self.files.clear();
    }
}

fn latin1(name: &[u8]) -> String {
    name.iter().copied().map(char::from).collect()
}

/// One non-blocking read of up to `length` bytes.
fn read_socket(stream: &mut TcpStream, length: u32) -> Result<Vec<u8>, PcdrvError> {
    let len = usize::try_from(length).map_err(|_| PcdrvError::Range("PCread length"))?;
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut out = vec![0; len];
    match stream.read(&mut out) {
        Ok(0) => Err(PcdrvError::Closed),
        Ok(n) => {
            out.truncate(n);
            Ok(out)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            Ok(Vec::new())
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(s: &PcdrvServer, name: &[u8]) -> PathBuf {
        s.resolve_name(name).expect("name stays inside the jail")
    }

    #[test]
    fn jail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = PcdrvServer::new(dir.path(), Quota::default()).expect("server");
        let base = s.base().expect("server has a base").to_path_buf();
        assert_eq!(resolve(&s, b"IN.TXT"), base.join("IN.TXT"));
        assert_eq!(resolve(&s, b"\\sub\\A.BIN"), base.join("sub/A.BIN"));
        assert_eq!(resolve(&s, b"///x"), base.join("x"));
        assert_eq!(resolve(&s, b"a/../b"), base.join("b"));
        assert!(s.resolve_name(b"../x").is_err());
        assert!(s.resolve_name(b"..\\..\\etc\\passwd").is_err());
        assert!(s.resolve_name(b"a/../../x").is_err());
        // Back into the base by name is inside, as with path.resolve.
        let leaf = base
            .file_name()
            .and_then(|n| n.to_str())
            .expect("tempdir has a UTF-8 name");
        assert_eq!(
            resolve(&s, format!("../{leaf}/y").as_bytes()),
            base.join("y")
        );
    }

    #[test]
    fn files_and_quotas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let quota = Quota {
            per_file_bytes: 10,
            total_bytes: 15,
            file_count: 2,
        };
        let mut s = PcdrvServer::new(dir.path(), quota).expect("server");
        let a = s.create(b"d/A").expect("create d/A");
        assert_eq!(a, 3);
        assert_eq!(s.write(a, b"0123456789").expect("write within quota"), 10);
        assert!(matches!(s.write(a, b"x"), Err(PcdrvError::Quota(_))));
        assert_eq!(s.seek(a, 2, 0).expect("seek set"), 2);
        assert_eq!(s.read(a, 3).expect("read"), b"234");
        assert_eq!(s.seek(a, -1, 2).expect("seek end"), 9);
        assert_eq!(s.seek(a, -100, 1).expect("seek clamps"), 0);
        let b = s.create(b"B").expect("create B");
        assert!(matches!(s.write(b, b"123456"), Err(PcdrvError::Quota(_))));
        assert!(matches!(s.create(b"C"), Err(PcdrvError::Quota(_))));
        assert_eq!(s.close(a), 0);
        assert!(matches!(s.read(a, 1), Err(PcdrvError::BadHandle(3))));
        assert!(s.open(b"missing", 0).is_err());
        let r = s.open(b"d/A", 0).expect("open d/A");
        assert!(s.read(r, MAX_READ_BYTES.saturating_add(1)).is_err());
        assert!(s.write(r, b"z").is_err(), "opened read-only");
        let on_disk = std::fs::read(dir.path().join("d/A")).expect("d/A on disk");
        assert_eq!(on_disk, b"0123456789");
    }

    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    fn listener() -> (TcpListener, String) {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let port = l.local_addr().expect("local addr").port();
        (l, format!("127.0.0.1:{port}"))
    }

    fn net_server(allow: &[&str]) -> PcdrvServer {
        let mut s = PcdrvServer::without_files(Quota::default());
        s.set_net(NetPolicy {
            enabled: true,
            allow: allow.iter().map(|a| (*a).to_owned()).collect(),
        });
        s
    }

    fn open_tcp(s: &mut PcdrvServer, target: &str) -> Result<i32, PcdrvError> {
        s.open(format!("tcp://{target}").as_bytes(), 0)
    }

    /// Poll `read` until it yields bytes or fails, for up to 5 s.
    fn read_until_data(s: &mut PcdrvServer, fd: i32) -> Result<Vec<u8>, PcdrvError> {
        let start = Instant::now();
        loop {
            let data = s.read(fd, 64)?;
            if !data.is_empty() || start.elapsed() > NET_TIMEOUT {
                return Ok(data);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn accept(l: &TcpListener) -> TcpStream {
        let (peer, _) = l.accept().expect("accept");
        peer
    }

    #[test]
    fn socket_write_reaches_listener() {
        let (l, target) = listener();
        let mut s = net_server(&[]);
        let fd = open_tcp(&mut s, &target).expect("tcp open");
        assert_eq!(fd, 3, "same handle space as files");
        let mut peer = accept(&l);
        // Quotas are for files: a write past per_file_bytes still goes out.
        let quota = Quota {
            per_file_bytes: 2,
            total_bytes: 2,
            file_count: 0,
        };
        let mut small = PcdrvServer::without_files(quota);
        small.set_net(NetPolicy {
            enabled: true,
            allow: Vec::new(),
        });
        let fd2 = open_tcp(&mut small, &target).expect("tcp open under tiny quota");
        let mut peer2 = accept(&l);
        assert_eq!(s.write(fd, b"hello").expect("socket write"), 5);
        assert_eq!(small.write(fd2, b"quota").expect("no quota on sockets"), 5);
        let mut got = [0; 5];
        peer.read_exact(&mut got).expect("listener reads");
        assert_eq!(&got, b"hello");
        peer2.read_exact(&mut got).expect("listener reads");
        assert_eq!(&got, b"quota");
        assert_eq!(s.close(fd), 0);
        assert!(matches!(s.write(fd, b"x"), Err(PcdrvError::BadHandle(3))));
    }

    #[test]
    fn socket_read_never_blocks() {
        let (l, target) = listener();
        let mut s = net_server(&[]);
        let fd = open_tcp(&mut s, &target).expect("tcp open");
        let mut peer = accept(&l);
        let start = Instant::now();
        assert_eq!(s.read(fd, 16).expect("read with nothing sent"), b"");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "read waited {:?}",
            start.elapsed()
        );
        peer.write_all(b"ping").expect("listener writes");
        assert_eq!(read_until_data(&mut s, fd).expect("read"), b"ping");
        assert!(s.read(fd, MAX_READ_BYTES.saturating_add(1)).is_err());
    }

    #[test]
    fn socket_eof_is_an_error() {
        let (l, target) = listener();
        let mut s = net_server(&[]);
        let fd = open_tcp(&mut s, &target).expect("tcp open");
        let mut peer = accept(&l);
        peer.write_all(b"bye").expect("listener writes");
        drop(peer);
        drop(l);
        assert_eq!(
            read_until_data(&mut s, fd).expect("data before EOF"),
            b"bye"
        );
        let start = Instant::now();
        let end = loop {
            match s.read(fd, 16) {
                Ok(d) if d.is_empty() && start.elapsed() < NET_TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                other => break other,
            }
        };
        assert!(matches!(end, Err(PcdrvError::Closed)), "{end:?}");
    }

    #[test]
    fn socket_seek_is_an_error() {
        let (l, target) = listener();
        let mut s = net_server(&[]);
        let fd = open_tcp(&mut s, &target).expect("tcp open");
        let _peer = accept(&l);
        assert!(matches!(s.seek(fd, 0, 0), Err(PcdrvError::Unsupported(_))));
    }

    #[test]
    fn probe_net() {
        let mut on = net_server(&[]);
        let fd = on.open(NET_PROBE, 0).expect("probe:net with networking");
        assert_eq!(on.read(fd, 16).expect("probe reads"), b"");
        assert!(on.write(fd, b"x").is_err());
        assert!(on.seek(fd, 0, 0).is_err());
        assert_eq!(on.close(fd), 0);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut off = PcdrvServer::new(dir.path(), Quota::default()).expect("server");
        assert!(off.open(NET_PROBE, 0).is_err());
        assert!(off.create(NET_PROBE).is_err());
        std::fs::write(dir.path().join("probe:net"), b"").expect("decoy file");
        assert!(off.open(NET_PROBE, 0).is_err(), "never a file");
    }

    #[test]
    fn tcp_refused_when_disabled() {
        let (l, target) = listener();
        l.set_nonblocking(true).expect("nonblocking listener");
        let dir = tempfile::tempdir().expect("tempdir");
        let mut files_only = PcdrvServer::new(dir.path(), Quota::default()).expect("server");
        let mut bare = PcdrvServer::without_files(Quota::default());
        for s in [&mut files_only, &mut bare] {
            assert!(matches!(open_tcp(s, &target), Err(PcdrvError::Net(_))));
        }
        assert!(l.accept().is_err(), "nothing connected");
        assert!(matches!(bare.open(b"A", 0), Err(PcdrvError::NoFiles)));
        assert!(matches!(bare.create(b"A"), Err(PcdrvError::NoFiles)));
        let entries = std::fs::read_dir(dir.path()).expect("read dir").count();
        assert_eq!(entries, 0);
    }

    #[test]
    fn allowlist() {
        let (l, target) = listener();
        let (_other, other) = listener();
        let mut s = net_server(&[&target]);
        let fd = open_tcp(&mut s, &target).expect("listed target");
        let _peer = accept(&l);
        assert!(fd >= 3);
        assert!(matches!(open_tcp(&mut s, &other), Err(PcdrvError::Net(_))));
        // Literal match: the same address spelled another way is refused.
        let port = target.rsplit_once(':').map(|(_, p)| p).expect("port");
        assert!(open_tcp(&mut s, &format!("localhost:{port}")).is_err());
    }

    #[test]
    fn other_schemes_never_touch_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = PcdrvServer::new(dir.path(), Quota::default()).expect("server");
        s.set_net(NetPolicy {
            enabled: true,
            allow: Vec::new(),
        });
        for name in [&b"udp://127.0.0.1:9"[..], b"file://X", b"http://h:80"] {
            assert!(s.open(name, 1).is_err());
            assert!(s.create(name).is_err());
        }
        assert!(
            s.create(b"tcp://127.0.0.1:9").is_err(),
            "creat is files only"
        );
        assert!(s.open(b"tcp://nonsense", 0).is_err());
        let entries = std::fs::read_dir(dir.path()).expect("read dir").count();
        assert_eq!(entries, 0, "no file created");
        assert!(parse_net_target("h:0x10").is_err());
        assert!(parse_net_target(":80").is_err());
        assert_eq!(parse_net_target("[::1]:80").expect("v6"), ("[::1]", 80));
    }
}
