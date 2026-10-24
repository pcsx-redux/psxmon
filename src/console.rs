//! The target's console text as psxmon writes it to stdout.

/// What goes in front of each line of the target's console text on a
/// terminal, to tell it from psxmon's own messages.
pub const TTY_PREFIX: &[u8] = b"PSX> ";

/// The most console text held back waiting for the end of its line. A
/// longer line goes out in pieces.
pub const HOLD_MAX: usize = 4096;

/// Turns the target's console bytes, as they arrive, into what goes to
/// stdout: [`TTY_PREFIX`] before each line when `prefix` is set (stdout is
/// a terminal), and with `hold`, whole lines only. `-v` sets `hold`: its
/// link lines go to the same terminal, and one written while the target's
/// line is still open would land in the middle of it. Without `hold` the
/// text goes out as it comes.
#[derive(Debug)]
pub struct ConsoleLines {
    prefix: bool,
    hold: bool,
    at_start: bool,
    held: Vec<u8>,
}

impl ConsoleLines {
    pub fn new(prefix: bool, hold: bool) -> Self {
        ConsoleLines {
            prefix,
            hold,
            at_start: true,
            held: Vec::new(),
        }
    }

    /// What to write now that `bytes` arrived.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        if !self.hold {
            return self.emit(bytes);
        }
        self.held.extend_from_slice(bytes);
        // Complete lines go out; the open line after them only once it
        // outgrows HOLD_MAX.
        let done = self
            .held
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i.saturating_add(1));
        let open = self.held.len().saturating_sub(done);
        let upto = if open > HOLD_MAX {
            self.held.len()
        } else {
            done
        };
        if upto == 0 {
            return Vec::new();
        }
        let rest = self.held.split_off(upto);
        let line = std::mem::replace(&mut self.held, rest);
        self.emit(&line)
    }

    /// What to write when the target's text ends: anything held, and on a
    /// terminal a newline if the text stopped mid-line, so psxmon's next
    /// message starts on a line of its own.
    pub fn finish(&mut self) -> Vec<u8> {
        let held = std::mem::take(&mut self.held);
        let mut out = self.emit(&held);
        if self.prefix && !self.at_start {
            out.push(b'\n');
            self.at_start = true;
        }
        out
    }

    fn emit(&mut self, bytes: &[u8]) -> Vec<u8> {
        if !self.prefix {
            return bytes.to_vec();
        }
        let mut v = Vec::with_capacity(bytes.len().saturating_add(TTY_PREFIX.len()));
        for &b in bytes {
            if self.at_start {
                v.extend_from_slice(TTY_PREFIX);
            }
            v.push(b);
            self.at_start = b == b'\n';
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsoleLines, HOLD_MAX};

    #[test]
    fn prefix_marks_each_line_start_across_calls() {
        let mut c = ConsoleLines::new(true, false);
        assert_eq!(c.feed(b"a\nb"), b"PSX> a\nPSX> b");
        assert_eq!(c.feed(b"c\n"), b"c\n");
        assert_eq!(c.feed(b"\n\n"), b"PSX> \nPSX> \n");
        assert_eq!(c.feed(b""), b"");
        assert_eq!(c.finish(), b"");
    }

    #[test]
    fn without_hold_a_fragment_goes_out_at_once() {
        let mut c = ConsoleLines::new(true, false);
        assert_eq!(c.feed(b"S"), b"PSX> S");
        assert_eq!(c.finish(), b"\n");
    }

    /// The `-v` report: "S" came in a read of its own, and the link line
    /// logged next was written onto "PSX> S".
    #[test]
    fn hold_keeps_a_line_split_across_reads_whole() {
        let mut c = ConsoleLines::new(true, true);
        assert_eq!(c.feed(b"S"), b"");
        assert_eq!(
            c.feed(b"ound SE Limit 24\r\n"),
            b"PSX> Sound SE Limit 24\r\n"
        );
        assert_eq!(c.feed(b"EQ SIZE 43"), b"");
        assert_eq!(c.feed(b"-44ec\r\nnext"), b"PSX> EQ SIZE 43-44ec\r\n");
        assert_eq!(c.finish(), b"PSX> next\n");
        assert_eq!(c.finish(), b"");
    }

    #[test]
    fn hold_on_a_pipe_keeps_the_bytes_exact() {
        let mut c = ConsoleLines::new(false, true);
        assert_eq!(c.feed(b"a"), b"");
        assert_eq!(c.feed(b"b\r\nc"), b"ab\r\n");
        assert_eq!(c.finish(), b"c");
    }

    #[test]
    fn hold_lets_a_line_longer_than_the_cap_through() {
        let mut c = ConsoleLines::new(false, true);
        let long = vec![b'x'; HOLD_MAX];
        assert_eq!(c.feed(&long), b"");
        assert_eq!(c.feed(b"y"), [long.as_slice(), b"y"].concat());
        assert_eq!(c.finish(), b"");
    }

    #[test]
    fn hold_keeps_a_short_open_line_after_a_long_batch() {
        let mut c = ConsoleLines::new(false, true);
        let lines = b"a\n".repeat(HOLD_MAX);
        assert_eq!(c.feed(&[lines.as_slice(), b"b"].concat()), lines);
        assert_eq!(c.finish(), b"b");
    }
}
