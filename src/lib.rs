//! Host side of the PS1 debug monitor (`monitor/PROTOCOL.md`, protocol
//! version 2): framing on a byte link, a session that loads and runs
//! programs and serves their PCDRV calls, and the pieces it is built from.

pub mod atcons;
pub mod bios;
pub mod exe;
pub mod frame;
pub mod gdb;
pub mod h2700;
pub mod iso;
pub mod lz4;
pub mod mips;
pub mod pcdrv;
pub mod proto;
pub mod ram;
pub mod session;
pub mod stepsim;
pub mod transport;

pub use atcons::AtconsTransport;
pub use session::{LoadOptions, RunResult, Session, SessionError, Stop};
pub use transport::{MemTransport, SerialTransport, TcpTransport, Transport};
