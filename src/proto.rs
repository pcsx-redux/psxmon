//! Message types, constants, capability bits, error codes and stop reasons of
//! the monitor wire protocol, version 2 (`monitor/PROTOCOL.md`).

/// Protocol version this host speaks (`MON_PROTO_VER`).
pub const PROTO_VER: u16 = 0x0002;

/// Frame anchor, sent low byte first (`0xAA 0x55`). Not covered by the checksum.
pub const SYNC: u16 = 0x55aa;

/// Largest LEN a stream (SIO1) frame may carry: an 8 KiB payload plus 16
/// header words. The receiver treats a larger LEN as noise.
pub const STREAM_MAX_LEN: u16 = 4096 + 16;

/// Bytes per bulk frame, both ways: LOAD / WRITE_MEM chunks from the host,
/// DATA frames from the monitor.
pub const CHUNK_BYTES: usize = 8192;

/// Longest payload of a command other than WRITE_MEM and LOAD.
pub const CMD_MAX_WORDS: usize = 16;

// Host -> PS1.
pub const PING: u16 = 0x01;
pub const READ_MEM: u16 = 0x02;
pub const WRITE_MEM: u16 = 0x03;
pub const GET_REGS: u16 = 0x04;
pub const SET_REG: u16 = 0x05;
pub const SET_BP: u16 = 0x06;
pub const CLR_BP: u16 = 0x07;
pub const LOAD: u16 = 0x08;
pub const RUN: u16 = 0x09;
pub const CONT: u16 = 0x0a;
pub const STOP: u16 = 0x0b;
pub const STEP: u16 = 0x0c;
pub const SET_BAUD: u16 = 0x0d;

// PS1 -> host.
pub const ACK: u16 = 0x40;
pub const DATA: u16 = 0x41;
pub const REGS: u16 = 0x42;
pub const PONG: u16 = 0x43;
pub const ERROR: u16 = 0x4f;
pub const HELLO: u16 = 0x80;
pub const STOPPED: u16 = 0x81;

/// Bit 15 of TYPE on WRITE_MEM and LOAD: the payload is a slice of an LZ4 block.
pub const LZ4_FLAG: u16 = 0x8000;

/// Capability bit: WRITE_MEM and LOAD accept [`LZ4_FLAG`].
pub const CAP_LZ4: u16 = 0x0001;
/// Capability bit: the monitor reads STOP while the target runs, and stops
/// it with reason [`STOP_INTERRUPT`] at the target's next interrupt.
pub const CAP_STOP: u16 = 0x0002;
/// Capability bit: the monitor is entered from the kernel exception
/// handler's patch slot, ahead of the handler chains, so a program that
/// resets the chains keeps it.
pub const CAP_SLOT: u16 = 0x0004;
/// Capability bit: the link holds a whole bulk frame while the monitor is
/// busy with the previous one, so WRITE_MEM/LOAD frames may be sent ahead of
/// their ACKs (FT232H; never SIO1, whose FIFO overruns).
pub const CAP_PIPELINE: u16 = 0x0008;

// ERROR codes.
pub const E_BADCMD: u16 = 0x01;
pub const E_BADSTATE: u16 = 0x02;
pub const E_BADADDR: u16 = 0x03;
pub const E_BADREG: u16 = 0x04;
pub const E_BADLEN: u16 = 0x05;
pub const E_CKSUM: u16 = 0x06;
pub const E_NOFD: u16 = 0x07;
pub const E_DECODE: u16 = 0x08;

pub fn error_name(code: u16) -> &'static str {
    match code {
        E_BADCMD => "EBADCMD",
        E_BADSTATE => "EBADSTATE",
        E_BADADDR => "EBADADDR",
        E_BADREG => "EBADREG",
        E_BADLEN => "EBADLEN",
        E_CKSUM => "ECKSUM",
        E_NOFD => "ENOFD",
        E_DECODE => "EDECODE",
        _ => "unknown error",
    }
}

// STOPPED reasons.
pub const STOP_BREAKPOINT: u16 = 0x01;
pub const STOP_INTERRUPT: u16 = 0x02;
pub const STOP_DATA_WATCH: u16 = 0x03;
pub const STOP_FAULT: u16 = 0x04;
/// Sent only by monitors from before break-driven exit: the exit code is in `a`.
pub const STOP_EXIT: u16 = 0x05;

pub fn stop_reason_name(reason: u16) -> String {
    match reason {
        STOP_BREAKPOINT => "breakpoint".into(),
        STOP_INTERRUPT => "interrupt".into(),
        STOP_DATA_WATCH => "data-watch".into(),
        STOP_FAULT => "fault".into(),
        STOP_EXIT => "exit".into(),
        r => format!("reason {r}"),
    }
}

// REGS / SET_REG indices (gdb g-packet order).
pub const REG_V0: u16 = 2;
pub const REG_V1: u16 = 3;
pub const REG_A0: u16 = 4;
pub const REG_SR: u16 = 32;
pub const REG_LO: u16 = 33;
pub const REG_HI: u16 = 34;
pub const REG_BADVADDR: u16 = 35;
pub const REG_CAUSE: u16 = 36;
pub const REG_PC: u16 = 37;
pub const NUM_REGS: usize = 38;

// PCDRV calls, the code2 of `break 0, code2`.
pub const PC_INIT: u32 = 0x101;
pub const PC_CREAT: u32 = 0x102;
pub const PC_OPEN: u32 = 0x103;
pub const PC_CLOSE: u32 = 0x104;
pub const PC_READ: u32 = 0x105;
pub const PC_WRITE: u32 = 0x106;
pub const PC_LSEEK: u32 = 0x107;

/// SIO1 at x16 runs at `SIO1_RATE_CLOCK / reload` baud (nominal).
pub const SIO1_RATE_CLOCK: u32 = 2_073_600;

/// Nominal line rate of a SIO1 reload value (18 -> 115200, 9 -> 230400).
pub fn sio1_rate(reload: u16) -> u32 {
    let reload = u32::from(reload.max(1));
    // Rounded to nearest; the clock plus half a reload cannot overflow u32.
    SIO1_RATE_CLOCK
        .saturating_add(reload / 2)
        .checked_div(reload)
        .unwrap_or(SIO1_RATE_CLOCK)
}

/// A software `break code1, code2`, decoded from its instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakCode {
    pub code1: u32,
    pub code2: u32,
}

impl BreakCode {
    /// The codes of `insn` if it is a `break` (function field 0x0D, as the
    /// monitor tests it).
    pub fn decode(insn: u32) -> Option<BreakCode> {
        ((insn & 0x3f) == 0x0d).then_some(BreakCode {
            code1: (insn >> 16) & 0x3ff,
            code2: (insn >> 6) & 0x3ff,
        })
    }

    pub fn encode(self) -> u32 {
        ((self.code1 & 0x3ff) << 16) | ((self.code2 & 0x3ff) << 6) | 0x0d
    }

    /// `break 4, 0`: program exit, code in a0.
    pub fn is_exit(self) -> bool {
        self.code1 == 4 && self.code2 == 0
    }

    /// `break 0, 0x101..0x107`: a PCDRV call.
    pub fn pcdrv_op(self) -> Option<u32> {
        (self.code1 == 0 && (PC_INIT..=PC_LSEEK).contains(&self.code2)).then_some(self.code2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn break_codes() {
        let exit = BreakCode::decode(0x0004000d).expect("a break");
        assert!(exit.is_exit());
        let entry = BreakCode { code1: 4, code2: 1 }.encode();
        assert_eq!(entry, 0x0004004d);
        let pc = BreakCode::decode((0x106 << 6) | 0x0d).expect("a break");
        assert_eq!(pc.pcdrv_op(), Some(PC_WRITE));
        assert_eq!(BreakCode::decode(0x0000_0000), None);
        assert_eq!(sio1_rate(18), 115200);
        assert_eq!(sio1_rate(9), 230400);
    }
}
