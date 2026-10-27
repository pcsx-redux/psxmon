//! Find the serial port the monitor is on when no `--port` is given.
//!
//! Only FTDI USB bridges (vendor 0x0403) are opened: opening a port toggles
//! DTR, which resets an Arduino or drops an ESP32 into its bootloader, and
//! the PINGs would land on whatever is attached. Each candidate gets PINGs
//! at one rate, without the resync zeros [`Session::ping`] sends, and the
//! one port that answers is the answer.

use std::time::Duration;

use serialport::{SerialPortInfo, SerialPortType};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};

use crate::session::{Session, deadline_after};
use crate::transport::SerialTransport;

/// FTDI's USB vendor id.
pub const FTDI_VID: u16 = 0x0403;

/// Once one port has answered, how much longer the others get to answer,
/// so that two monitors are reported as two.
pub const SETTLE: Duration = Duration::from_secs(1);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    #[error("listing serial ports: {0}")]
    List(String),
    #[error("no FTDI serial port (USB vendor 0403) found; pass --port DEV")]
    NoFtdi,
    #[error(
        "no PONG at {baud} baud on any FTDI port ({}); check the console is on and \
         the monitor running, pass --baud if it listens at another rate, or --port DEV",
        .tried.join(", ")
    )]
    NoAnswer { baud: u32, tried: Vec<String> },
    #[error("the monitor answers on several ports ({}); pick one with --port", .0.join(", "))]
    Several(Vec<String>),
}

/// The FTDI ports among `ports`, by name, sorted.
pub fn ftdi_ports(ports: &[SerialPortInfo]) -> Vec<String> {
    let mut names: Vec<String> = ports
        .iter()
        .filter(|p| matches!(&p.port_type, SerialPortType::UsbPort(u) if u.vid == FTDI_VID))
        .map(|p| p.port_name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// What PINGing one port came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pong,
    Silent,
    /// The port did not open or the link failed: the message.
    Failed(String),
}

/// The port to use, given what each candidate came to.
pub fn choose(baud: u32, results: &[(String, Outcome)]) -> Result<String, ProbeError> {
    let answered: Vec<String> = results
        .iter()
        .filter(|(_, o)| *o == Outcome::Pong)
        .map(|(n, _)| n.clone())
        .collect();
    match answered.as_slice() {
        [one] => Ok(one.clone()),
        [] if results.is_empty() => Err(ProbeError::NoFtdi),
        [] => Err(ProbeError::NoAnswer {
            baud,
            tried: results
                .iter()
                .map(|(n, o)| match o {
                    Outcome::Failed(e) => format!("{n}: {e}"),
                    _ => n.clone(),
                })
                .collect(),
        }),
        _ => Err(ProbeError::Several(answered)),
    }
}

async fn ping_port(name: String, baud: u32, wait: Duration) -> (String, Outcome) {
    let deadline = deadline_after(wait);
    // Opening blocks, and the runtime has one thread: open on a thread of
    // its own, so a port that hangs in open cannot hold up the others or
    // the deadline. A port that opens after the deadline is closed again
    // when the thread's send fails.
    let (tx, rx) = oneshot::channel();
    let path = name.clone();
    let spawned = std::thread::Builder::new()
        .name("probe-open".into())
        .spawn(move || {
            let _ = tx.send(SerialTransport::open(&path, baud));
        });
    if let Err(e) = spawned {
        return (name, Outcome::Failed(e.to_string()));
    }
    let io = match timeout_at(deadline, rx).await {
        Ok(Ok(Ok(io))) => io,
        Ok(Ok(Err(e))) => return (name, Outcome::Failed(e.to_string())),
        Ok(Err(_)) => return (name, Outcome::Failed("open failed".into())),
        Err(_) => return (name, Outcome::Failed("open did not return".into())),
    };
    let mut s = Session::new(io);
    let left = deadline.saturating_duration_since(Instant::now());
    let outcome = match s.probe_ping(left).await {
        Ok(true) => Outcome::Pong,
        Ok(false) => Outcome::Silent,
        Err(e) => Outcome::Failed(e.to_string()),
    };
    (name, outcome)
}

/// PING every FTDI port at `baud` for up to `wait` and return the one the
/// monitor answers on. All ports are PINGed at once; after the first PONG
/// the rest get [`SETTLE`] more, then count as silent.
pub async fn find(baud: u32, wait: Duration) -> Result<String, ProbeError> {
    let ports = serialport::available_ports().map_err(|e| ProbeError::List(e.to_string()))?;
    let names = ftdi_ports(&ports);
    crate::transport::link_log(&format!("probing FTDI ports: {names:?}"));
    let mut set = JoinSet::new();
    for name in &names {
        set.spawn(ping_port(name.clone(), baud, wait));
    }
    let mut results: Vec<(String, Outcome)> = Vec::new();
    let mut cutoff: Option<Instant> = None;
    loop {
        let next = match cutoff {
            Some(at) => match timeout_at(at, set.join_next()).await {
                Ok(n) => n,
                Err(_) => break,
            },
            None => set.join_next().await,
        };
        let Some(joined) = next else { break };
        let (name, outcome) = match joined {
            Ok(r) => r,
            Err(e) => (String::from("?"), Outcome::Failed(e.to_string())),
        };
        if outcome == Outcome::Pong && cutoff.is_none() {
            cutoff = Some(deadline_after(SETTLE));
        }
        results.push((name, outcome));
    }
    set.abort_all();
    // Ports cut off by the settle window were not heard from.
    for name in names {
        if !results.iter().any(|(n, _)| *n == name) {
            results.push((name, Outcome::Silent));
        }
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    for (n, o) in &results {
        crate::transport::link_log(&format!("probe {n}: {o:?}"));
    }
    choose(baud, &results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serialport::UsbPortInfo;

    fn usb(name: &str, vid: u16) -> SerialPortInfo {
        SerialPortInfo {
            port_name: name.into(),
            port_type: SerialPortType::UsbPort(UsbPortInfo {
                vid,
                pid: 0x6001,
                serial_number: None,
                manufacturer: None,
                product: None,
            }),
        }
    }

    #[test]
    fn only_ftdi_ports_are_candidates() {
        let ports = [
            usb("/dev/ttyUSB1", FTDI_VID),
            usb("/dev/ttyACM0", 0x2341), // Arduino
            usb("/dev/ttyUSB2", 0x10c4), // CP210x, as on ESP32 boards
            SerialPortInfo {
                port_name: "/dev/ttyS0".into(),
                port_type: SerialPortType::PciPort,
            },
            usb("/dev/ttyUSB0", FTDI_VID),
        ];
        assert_eq!(ftdi_ports(&ports), ["/dev/ttyUSB0", "/dev/ttyUSB1"]);
    }

    fn r(n: &str, o: Outcome) -> (String, Outcome) {
        (n.into(), o)
    }

    #[test]
    fn one_answer_is_chosen() {
        let res = [
            r("/dev/ttyUSB0", Outcome::Silent),
            r("/dev/ttyUSB1", Outcome::Pong),
        ];
        assert_eq!(choose(115200, &res), Ok("/dev/ttyUSB1".into()));
    }

    #[test]
    fn no_candidates_and_no_answer_are_different_errors() {
        assert_eq!(choose(115200, &[]), Err(ProbeError::NoFtdi));
        let res = [
            r("/dev/ttyUSB0", Outcome::Silent),
            r("/dev/ttyUSB1", Outcome::Failed("Permission denied".into())),
        ];
        let e = choose(9600, &res);
        assert_eq!(
            e,
            Err(ProbeError::NoAnswer {
                baud: 9600,
                tried: vec![
                    "/dev/ttyUSB0".into(),
                    "/dev/ttyUSB1: Permission denied".into()
                ],
            })
        );
        let msg = e.map_err(|e| e.to_string()).err().unwrap_or_default();
        assert!(msg.contains("9600 baud"), "{msg}");
        assert!(msg.contains("/dev/ttyUSB1: Permission denied"), "{msg}");
    }

    #[test]
    fn several_answers_are_listed_not_guessed() {
        let res = [
            r("/dev/ttyUSB0", Outcome::Pong),
            r("/dev/ttyUSB1", Outcome::Pong),
        ];
        let e = choose(115200, &res);
        assert_eq!(
            e,
            Err(ProbeError::Several(vec![
                "/dev/ttyUSB0".into(),
                "/dev/ttyUSB1".into()
            ]))
        );
    }
}
