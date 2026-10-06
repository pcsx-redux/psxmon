//! psxmon: command-line host for the PS1 debug monitor.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use gdbstub::stub::DisconnectReason;
use psxmon::gdb::MonTarget;
use psxmon::pcdrv::{PcdrvServer, Quota};
use psxmon::proto::{self, CAP_LZ4, CAP_SLOT, CAP_STOP, HELLO, STOP_EXIT};
use psxmon::session::{LoadOptions, Session, deadline_after};
use psxmon::transport::{self, parse_tcp_port};
use psxmon::{
    AtconsTransport, SerialTransport, TcpTransport, Transport, atcons, bios, exe, h2700, iso, lz4,
};

/// A session on whichever link --port names.
type MonSession = Session<Box<dyn Transport>>;

/// Largest target exit code passed through as the process exit status;
/// anything above it (or negative) exits with this value.
const EXIT_CODE_MAX: u8 = 123;
/// Exit status when the target did not stop before --timeout.
const EXIT_TIMEOUT: u8 = 124;
/// Exit status on a host, link or protocol error.
const EXIT_ERROR: u8 = 125;
/// Exit status when the target stopped without exiting (fault, breakpoint).
const EXIT_STOPPED: u8 = 126;

#[derive(Parser)]
#[command(
    name = "psxmon",
    version,
    about = "Host tool for the PS1 debug monitor"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Link {
    /// Serial device the monitor is on; `tcp:HOST:PORT` (or
    /// `tcp://HOST:PORT`) for a TCP link such as PCSX-Redux's SIO1 server;
    /// or `atcons[:BASE]` for the DTL-H2700's ISA card (base 0x1340 by
    /// default; x86 Linux, root).
    #[arg(long, env = "PSXMON_PORT")]
    port: String,
    /// Line rate the monitor listens at after boot (not used on TCP or
    /// ATCONS).
    #[arg(long, default_value_t = 115200)]
    baud: u32,
    /// SIO1 reload to switch to after attaching (9 = 230400, 5 = 414720).
    #[arg(long, value_name = "RELOAD")]
    fast_reload: Option<u16>,
    /// Seconds to PING for before giving up on the monitor.
    #[arg(long, value_name = "SECS", default_value_t = 5.0)]
    attach_timeout: f64,
    /// Log to stderr: the rates tried and their outcome, and on a serial
    /// port every byte each way (hex), the RTS/DTR results at open and after
    /// each rate change. `run` adds load details and PCDRV calls, `gdb`
    /// stops, steps and breakpoints.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args)]
struct RunArgs {
    /// Program to run (PS-EXE, ELF, CPE or PSF).
    file: PathBuf,
    #[command(flatten)]
    link: Link,
    /// Send the program LZ4-compressed when the monitor supports it (default).
    #[arg(long, overrides_with = "no_lz4")]
    lz4: bool,
    /// Send the program uncompressed.
    #[arg(long, overrides_with = "lz4")]
    no_lz4: bool,
    /// Longest LZ4 match copy per sequence.
    #[arg(long, value_name = "BYTES", default_value_t = lz4::DEFAULT_MAX_MATCH)]
    max_match: usize,
    /// Serve PCDRV file I/O from this directory.
    #[arg(long, value_name = "DIR")]
    pcdrv: Option<PathBuf>,
    /// Seconds to let the program run.
    #[arg(long, value_name = "SECS", default_value_t = 60.0)]
    timeout: f64,
}

#[derive(Args)]
struct GdbArgs {
    /// Program to load (PS-EXE, ELF, CPE or PSF); gdb finds it halted on its
    /// first instruction. Without it, gdb attaches to whatever program the
    /// monitor has halted.
    file: Option<PathBuf>,
    #[command(flatten)]
    link: Link,
    /// Address to accept the gdb connection on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:3333")]
    listen: String,
    /// Send the program uncompressed.
    #[arg(long)]
    no_lz4: bool,
    /// Longest LZ4 match copy per sequence.
    #[arg(long, value_name = "BYTES", default_value_t = lz4::DEFAULT_MAX_MATCH)]
    max_match: usize,
    /// Serve PCDRV file I/O from this directory.
    #[arg(long, value_name = "DIR")]
    pcdrv: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Upload a program, run it, stream its console text to stdout, serve
    /// PCDRV, and exit with its exit code.
    Run(RunArgs),
    /// Serve one gdb remote connection (target remote HOST:PORT) to the
    /// target, optionally loading a program first. Console text goes to
    /// stdout and PCDRV is served, as with `run`.
    Gdb(GdbArgs),
    /// Print the monitor's protocol version, capabilities and BIOS.
    Ping {
        #[command(flatten)]
        link: Link,
    },
    /// Read target memory to a file.
    Dump {
        #[arg(value_parser = parse_u32)]
        addr: u32,
        #[arg(value_parser = parse_u32)]
        len: u32,
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        #[command(flatten)]
        link: Link,
    },
    /// Write a file into target memory.
    Write {
        #[arg(value_parser = parse_u32)]
        addr: u32,
        file: PathBuf,
        #[command(flatten)]
        link: Link,
    },
    /// Build an H2700 flash image: STOCK, a dump of the cart's own flash or
    /// the FLASH27 kit's H2700.IMG, with the OpenBIOS monitor (MONITOR, the
    /// openbios-h2700 ELF from a release) in its code cave and the entry
    /// jump pointed at it.
    PatchH2700 {
        stock: PathBuf,
        monitor: PathBuf,
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Reset the DTL-H2700's PS1 through its ISA card (x86 Linux, root).
    /// Mode 7 boots the monitor in the flash cave, other modes the stock
    /// BIOS. Then connect the card's host side and, in mode 7, copy the
    /// boot's console text to stdout until the monitor's HELLO.
    H2700Reset {
        /// Reset mode.
        #[arg(long, default_value_t = 7)]
        mode: u8,
        /// The card: atcons or atcons:BASE.
        #[arg(long, default_value = "atcons")]
        port: String,
        /// Reset only; leave the card's host side closed.
        #[arg(long)]
        no_connect: bool,
        /// Seconds to wait for the monitor's HELLO after a mode 7 reset (0:
        /// do not wait).
        #[arg(long, value_name = "SECS", default_value_t = 5.0)]
        console: f64,
    },
    /// Build a bootable disc image from EXE, a PS-EXE, as PSX.EXE: the same
    /// `.bin` as PCSX-Redux's exe2iso, plus a `.cue` next to it.
    Mkdisc {
        exe: PathBuf,
        /// The `.bin` to write; the `.cue` gets the same name.
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
        /// License for sectors 0-15: an SDK file (2336-byte sectors) or the
        /// start of a raw 2352-byte image. Without it they are zeroed.
        #[arg(long, value_name = "FILE")]
        license: Option<PathBuf>,
        /// Leave out the 150 blank sectors after the end of the volume.
        #[arg(long)]
        no_pad: bool,
    },
}

fn parse_u32(s: &str) -> std::result::Result<u32, String> {
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(&hex.replace('_', ""), 16),
        None => s.replace('_', "").parse(),
    };
    r.map_err(|e| format!("{s}: {e}"))
}

fn seconds(secs: f64, what: &str) -> Result<Duration> {
    Duration::try_from_secs_f64(secs).with_context(|| format!("{what}: bad number of seconds"))
}

/// How long to PING at each rate other than --baud before trying the next.
const PROBE_WAIT: Duration = Duration::from_secs(1);

/// How long to wait for a HELLO pending on the ATCONS card before PINGing.
const HELLO_WAIT: Duration = Duration::from_millis(300);

async fn attach(link: &Link) -> Result<MonSession> {
    transport::set_link_log(link.verbose);
    if let Some(base) = atcons::parse_port(&link.port) {
        return attach_atcons(link, base.map_err(anyhow::Error::msg)?).await;
    }
    if let Some(addr) = parse_tcp_port(&link.port) {
        return attach_tcp(link, addr).await;
    }
    let io = SerialTransport::open(&link.port, link.baud)
        .with_context(|| format!("opening {}", link.port))?;
    let mut s: MonSession = Session::new(Box::new(io));
    // A monitor an earlier SET_BAUD left at a faster rate does not answer at
    // --baud, so fall back to the rates it can have been left at: the boot
    // rate, 230400 (reload 9), and whatever --fast-reload names.
    let mut rates = vec![link.baud, proto::sio1_rate(18), proto::sio1_rate(9)];
    rates.extend(link.fast_reload.map(proto::sio1_rate));
    let mut seen = Vec::new();
    rates.retain(|r| {
        let fresh = !seen.contains(r);
        seen.push(*r);
        fresh
    });
    let first_wait = seconds(link.attach_timeout, "--attach-timeout")?;
    let Some(rate) = s.attach_at(&rates, first_wait, PROBE_WAIT).await? else {
        bail!(
            "no PONG from the monitor on {} at {rates:?} baud",
            link.port
        );
    };
    if rate != link.baud {
        eprintln!("psxmon: monitor answered at {rate} baud, not {}", link.baud);
    }
    // Anything before the first PONG is boot or line noise, not program text.
    s.take_text();
    if let Some(reload) = link.fast_reload {
        let rate = s.negotiate_rate(reload).await?;
        if rate != proto::sio1_rate(reload) {
            eprintln!("psxmon: reload {reload} did not answer, staying at {rate} baud");
        }
    }
    Ok(s)
}

/// Attach over TCP: PING until PONG. The far end owns the line rate, so
/// there is no rate to probe or change.
async fn attach_tcp(link: &Link, addr: &str) -> Result<MonSession> {
    if link.fast_reload.is_some() {
        bail!("--fast-reload: a TCP link has no line rate");
    }
    let io = TcpTransport::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    let mut s: MonSession = Session::new(Box::new(io));
    let wait = seconds(link.attach_timeout, "--attach-timeout")?;
    if !s.ping(wait, &[]).await? {
        bail!("no PONG from the monitor at {addr}");
    }
    // Anything before the first PONG is boot text, not the program's.
    s.take_text();
    Ok(s)
}

/// Attach on the ATCONS card: read the HELLO the monitor may have left in
/// the word channel at start-up (a later reader would otherwise take it for
/// a reply), then PING.
async fn attach_atcons(link: &Link, base: u16) -> Result<MonSession> {
    if link.fast_reload.is_some() {
        bail!("--fast-reload: ATCONS has no line rate");
    }
    let io = AtconsTransport::open(base)
        .with_context(|| format!("opening the ATCONS card at 0x{base:04x}"))?;
    let mut s: MonSession = Session::new(Box::new(io));
    s.wait_frame(&[HELLO], deadline_after(HELLO_WAIT)).await?;
    let wait = seconds(link.attach_timeout, "--attach-timeout")?;
    if !s.ping(wait, &[]).await? {
        bail!("no PONG from the monitor on the ATCONS card at 0x{base:04x}");
    }
    s.take_text();
    Ok(s)
}

/// Reset the H2700's PS1 through the card, and with mode 7 show the boot's
/// console text and wait for the monitor's HELLO.
async fn h2700_reset(port: &str, mode: u8, connect: bool, console: f64) -> Result<ExitCode> {
    let base = atcons::parse_port(port)
        .with_context(|| format!("{port}: not an ATCONS port (want atcons[:BASE])"))?
        .map_err(anyhow::Error::msg)?;
    let mut ports = atcons::IoPorts::open(base)
        .with_context(|| format!("opening the ATCONS card at 0x{base:04x}"))?;
    let reply = atcons::reset_card(&mut ports, mode, connect);
    eprintln!("psxmon: reset the card at 0x{base:04x} into mode {mode}");
    if !connect {
        return Ok(ExitCode::SUCCESS);
    }
    if mode != 7 || console <= 0.0 {
        match reply {
            Some(r) => eprintln!("psxmon: connect reply 0x{r:02x}"),
            None => eprintln!("psxmon: no connect reply"),
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut sink = stdout_console();
    // Under the monitor the "reply" is the first byte of the boot's console
    // text (the stock BIOS answers the connect byte; OpenBIOS takes it as a
    // keypress).
    if let Some(r) = reply {
        sink(&[r]);
    }
    let mut s = Session::new(AtconsTransport::with_ports(ports));
    s.set_console(Some(sink));
    let deadline = deadline_after(seconds(console, "--console")?);
    match s.wait_frame(&[HELLO], deadline).await? {
        Some(h) => {
            let w = |i: usize| h.words.get(i).copied().unwrap_or(0);
            let bios = u32::from(w(2)) | (u32::from(w(3)) << 16);
            eprintln!(
                "psxmon: HELLO protocol {} caps {} bios 0x{bios:08x} {}",
                w(0),
                describe_caps(w(1)),
                bios::bios_name(bios)
            );
            Ok(ExitCode::SUCCESS)
        }
        None => bail!("no HELLO from the monitor within {console} s"),
    }
}

fn describe_caps(caps: u16) -> String {
    let mut names = vec![];
    if caps & CAP_LZ4 != 0 {
        names.push("lz4");
    }
    if caps & CAP_STOP != 0 {
        names.push("stop");
    }
    if caps & CAP_SLOT != 0 {
        names.push("slot");
    }
    format!(
        "0x{caps:04x} ({})",
        if names.is_empty() {
            "none".into()
        } else {
            names.join(", ")
        }
    )
}

async fn ping(link: Link) -> Result<ExitCode> {
    let s = attach(&link).await?;
    match s.version {
        Some(v) => println!("protocol {v}"),
        None => println!("protocol unknown"),
    }
    println!("caps {}", describe_caps(s.caps));
    match s.bios {
        Some(b) => println!("bios 0x{b:08x} {}", bios::bios_name(b)),
        None => println!("bios not reported"),
    }
    Ok(ExitCode::SUCCESS)
}

async fn run(args: RunArgs) -> Result<ExitCode> {
    let RunArgs {
        file,
        link,
        lz4: _,
        no_lz4,
        max_match,
        pcdrv,
        timeout,
    } = args;
    let verbose = link.verbose;
    let lz4 = !no_lz4;
    if max_match < 7 {
        bail!("--max-match must be at least 7");
    }
    let image = exe::load(&file).with_context(|| format!("loading {}", file.display()))?;
    let mut server = match pcdrv {
        Some(dir) => Some(
            PcdrvServer::new(&dir, Quota::default())
                .with_context(|| format!("PCDRV dir {}", dir.display()))?,
        ),
        None => None,
    };
    let mut s = attach(&link).await?;
    s.verbose = verbose;
    let opts = LoadOptions {
        lz4,
        max_match,
        ..Default::default()
    };
    let t0 = StdInstant::now();
    for seg in &image.segments {
        let st = s.load(seg.addr, &seg.data, &opts).await?;
        if verbose {
            let how = st
                .lz4_bytes
                .map_or("plain".to_string(), |n| format!("lz4 {n} bytes"));
            eprintln!(
                "psxmon: loaded {} bytes at 0x{:08x} ({how})",
                st.bytes, seg.addr
            );
        }
    }
    if verbose {
        eprintln!(
            "psxmon: load took {} ms {}; run pc=0x{:08x} gp=0x{:08x} sp=0x{:08x}",
            t0.elapsed().as_millis(),
            match s.transport().baud_rate() {
                0 => format!("on {}", link.port),
                b => format!("at {b} baud"),
            },
            image.pc,
            image.gp,
            image.sp
        );
    }
    s.set_console(Some(Box::new(|bytes: &[u8]| {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(bytes);
        let _ = out.flush();
    })));
    let deadline = deadline_after(seconds(timeout, "--timeout")?);
    s.run(image.pc, image.gp, image.sp).await?;
    let result = s.run_until_stop(deadline, server.as_mut()).await?;
    if let Some(sv) = server.as_mut() {
        sv.close_all();
    }
    Ok(match (result.stop, result.exit_code) {
        (_, Some(code)) => {
            eprintln!("psxmon: exit code {code} (0x{code:x})");
            ExitCode::from(exit_status(code))
        }
        (Some(stop), None) => {
            debug_assert_ne!(stop.reason, STOP_EXIT);
            eprintln!(
                "psxmon: target stopped: {} at 0x{:08x}, a=0x{:08x} b=0x{:08x}",
                stop.reason_name(),
                stop.epc,
                stop.a,
                stop.b
            );
            ExitCode::from(EXIT_STOPPED)
        }
        (None, None) => {
            eprintln!("psxmon: timed out after {timeout} s");
            ExitCode::from(EXIT_TIMEOUT)
        }
    })
}

fn stdout_console() -> psxmon::session::Console {
    Box::new(|bytes: &[u8]| {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(bytes);
        let _ = out.flush();
    })
}

fn gdb(args: GdbArgs) -> Result<ExitCode> {
    let GdbArgs {
        file,
        link,
        listen,
        no_lz4,
        max_match,
        pcdrv,
    } = args;
    let verbose = link.verbose;
    if max_match < 7 {
        bail!("--max-match must be at least 7");
    }
    let image = file
        .as_ref()
        .map(|f| exe::load(f).with_context(|| format!("loading {}", f.display())))
        .transpose()?;
    let server = match pcdrv {
        Some(dir) => Some(
            PcdrvServer::new(&dir, Quota::default())
                .with_context(|| format!("PCDRV dir {}", dir.display()))?,
        ),
        None => None,
    };
    // Bind first, so a busy port fails before the target is touched.
    let listener =
        std::net::TcpListener::bind(&listen).with_context(|| format!("listening on {listen}"))?;
    // gdbstub's event loop blocks, so the session gets a runtime of its own
    // that each target operation drives with block_on.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut s = rt.block_on(attach(&link))?;
    s.verbose = verbose;
    s.set_console(Some(stdout_console()));
    let mut t = MonTarget::new(rt, s, server);
    t.verbose = verbose;
    if let Some(img) = &image {
        let opts = LoadOptions {
            lz4: !no_lz4,
            max_match,
            ..Default::default()
        };
        t.start_program(img, &opts)?;
        eprintln!(
            "psxmon: program loaded, halted at its entry 0x{:08x}",
            img.pc
        );
    } else if !t.has_context()? {
        eprintln!(
            "psxmon: the monitor has no halted program: gdb will read zeroed registers \
             and cannot continue or step"
        );
    }
    eprintln!("psxmon: waiting for gdb on {listen}");
    let (conn, peer) = listener.accept().context("accepting the gdb connection")?;
    conn.set_nodelay(true)?;
    eprintln!("psxmon: gdb connected from {peer}");
    let reason = t.serve(conn)?;
    if let Some(sv) = t.pcdrv_mut() {
        sv.close_all();
    }
    Ok(match (reason, t.exit_code) {
        (_, Some(code)) => {
            eprintln!("psxmon: exit code {code} (0x{code:x})");
            ExitCode::from(exit_status(code))
        }
        (DisconnectReason::Kill, None) => {
            eprintln!("psxmon: gdb killed the session; target left halted");
            ExitCode::SUCCESS
        }
        (_, None) => {
            eprintln!("psxmon: gdb detached; target left halted");
            ExitCode::SUCCESS
        }
    })
}

async fn dump(addr: u32, len: u32, output: PathBuf, link: Link) -> Result<ExitCode> {
    let mut s = attach(&link).await?;
    let data = s.read_mem(addr, len).await?;
    std::fs::write(&output, &data[..len as usize])
        .with_context(|| format!("writing {}", output.display()))?;
    eprintln!(
        "psxmon: read {len} bytes at 0x{addr:08x} to {}",
        output.display()
    );
    Ok(ExitCode::SUCCESS)
}

async fn write(addr: u32, file: PathBuf, link: Link) -> Result<ExitCode> {
    let data = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
    let mut s = attach(&link).await?;
    s.write_mem(addr, &data).await?;
    eprintln!("psxmon: wrote {} bytes at 0x{addr:08x}", data.len());
    Ok(ExitCode::SUCCESS)
}

fn patch_h2700(stock: &Path, monitor: &Path, output: &Path) -> Result<ExitCode> {
    let stock_bytes =
        std::fs::read(stock).with_context(|| format!("reading {}", stock.display()))?;
    let mon = exe::load(monitor).with_context(|| format!("loading {}", monitor.display()))?;
    let img = h2700::patch(&stock_bytes, &mon).with_context(|| stock.display().to_string())?;
    std::fs::write(output, img).with_context(|| format!("writing {}", output.display()))?;
    eprintln!(
        "psxmon: {}: monitor {} bytes, entry 0x{:08x}",
        output.display(),
        mon.total_bytes(),
        mon.pc
    );
    Ok(ExitCode::SUCCESS)
}

fn mkdisc(exe_path: &Path, output: &Path, license: Option<&Path>, pad: bool) -> Result<ExitCode> {
    let exe = std::fs::read(exe_path).with_context(|| format!("reading {}", exe_path.display()))?;
    let lic = license
        .map(|p| std::fs::read(p).with_context(|| format!("reading {}", p.display())))
        .transpose()?;
    let bin =
        iso::build(&exe, lic.as_deref(), pad).with_context(|| exe_path.display().to_string())?;
    let bin_name = output
        .file_name()
        .with_context(|| format!("{} has no file name", output.display()))?
        .to_string_lossy();
    let cue_path = output.with_extension("cue");
    let cue = format!("FILE \"{bin_name}\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n");
    std::fs::write(output, &bin).with_context(|| format!("writing {}", output.display()))?;
    std::fs::write(&cue_path, cue).with_context(|| format!("writing {}", cue_path.display()))?;
    eprintln!(
        "psxmon: {}: {} sectors, PSX.EXE {} bytes, cue {}",
        output.display(),
        bin.len() / iso::SECTOR_RAW,
        exe.len(),
        cue_path.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// The process exit status for a target exit code: the code itself when it
/// is 0..=123, else 123, so it never reads as one of psxmon's own statuses.
fn exit_status(code: u32) -> u8 {
    u8::try_from(code)
        .ok()
        .filter(|&c| c <= EXIT_CODE_MAX)
        .unwrap_or(EXIT_CODE_MAX)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Gdb(args) => gdb(args),
        cmd => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|rt| rt.block_on(dispatch(cmd))),
    };
    result.unwrap_or_else(|e| {
        eprintln!("psxmon: {e:#}");
        ExitCode::from(EXIT_ERROR)
    })
}

async fn dispatch(cmd: Cmd) -> Result<ExitCode> {
    match cmd {
        // Runs its own runtime; main() calls it outside this one.
        Cmd::Gdb(_) => bail!("gdb cannot run inside the async dispatcher"),
        Cmd::Run(args) => run(args).await,
        Cmd::Ping { link } => ping(link).await,
        Cmd::Dump {
            addr,
            len,
            output,
            link,
        } => dump(addr, len, output, link).await,
        Cmd::Write { addr, file, link } => write(addr, file, link).await,
        Cmd::PatchH2700 {
            stock,
            monitor,
            output,
        } => patch_h2700(&stock, &monitor, &output),
        Cmd::H2700Reset {
            mode,
            port,
            no_connect,
            console,
        } => h2700_reset(&port, mode, !no_connect, console).await,
        Cmd::Mkdisc {
            exe,
            output,
            license,
            no_pad,
        } => mkdisc(&exe, &output, license.as_deref(), !no_pad),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_passes_small_codes_and_caps_the_rest() {
        assert_eq!(exit_status(0), 0);
        assert_eq!(exit_status(42), 42);
        assert_eq!(exit_status(123), 123);
        assert_eq!(exit_status(124), EXIT_CODE_MAX);
        assert_eq!(exit_status(20000), EXIT_CODE_MAX);
        assert_eq!(exit_status(u32::MAX), EXIT_CODE_MAX);
        assert_eq!(parse_u32("0x8001_0000"), Ok(0x8001_0000));
        assert_eq!(parse_u32("4096"), Ok(4096));
        assert!(parse_u32("0x1_0000_0000").is_err());
    }
}
