//! Upload rate figures for the line psxmon prints after a load.

use std::time::Duration;

/// The shortest stretch of an upload the peak rate is taken over. ACKs
/// arrive in bursts, and the rate between two close ones says more about
/// the link's buffering than about its speed.
pub const PEAK_SPAN: Duration = Duration::from_millis(250);

/// Bytes delivered over time: a point per ACK, from the start of the load.
#[derive(Debug)]
pub struct RateMeter {
    points: Vec<(Duration, usize)>,
}

impl Default for RateMeter {
    fn default() -> Self {
        RateMeter {
            points: vec![(Duration::ZERO, 0)],
        }
    }
}

impl RateMeter {
    /// `total` bytes delivered `at` after the start.
    pub fn record(&mut self, at: Duration, total: usize) {
        self.points.push((at, total));
    }

    /// Bytes per second from the start to the last point.
    pub fn average(&self) -> Option<f64> {
        let &(t, n) = self.points.last()?;
        per_second(n, t)
    }

    /// The highest rate over any stretch of at least [`PEAK_SPAN`] between
    /// two points; the average when the whole upload is shorter than that.
    pub fn peak(&self) -> Option<f64> {
        let mut best: Option<f64> = None;
        for (i, &(ti, ni)) in self.points.iter().enumerate() {
            for &(tj, nj) in self.points.iter().skip(i) {
                let span = tj.saturating_sub(ti);
                if span < PEAK_SPAN {
                    continue;
                }
                if let Some(r) = per_second(nj.saturating_sub(ni), span) {
                    best = Some(best.map_or(r, |b| b.max(r)));
                }
            }
        }
        best.or_else(|| self.average())
    }
}

fn per_second(bytes: usize, over: Duration) -> Option<f64> {
    let s = over.as_secs_f64();
    (s > 0.0).then(|| bytes as f64 / s)
}

#[cfg(test)]
mod tests {
    use super::RateMeter;
    use std::time::Duration;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn nothing_recorded_has_no_rate() {
        let m = RateMeter::default();
        assert_eq!(m.average(), None);
        assert_eq!(m.peak(), None);
    }

    #[test]
    fn peak_is_the_fastest_stretch_and_average_the_whole() {
        let mut m = RateMeter::default();
        // 100 kB/s for a second, then 400 kB/s for half a second.
        m.record(ms(500), 50_000);
        m.record(ms(1000), 100_000);
        m.record(ms(1250), 200_000);
        m.record(ms(1500), 300_000);
        assert_eq!(m.average(), Some(200_000.0));
        assert_eq!(m.peak(), Some(400_000.0));
    }

    #[test]
    fn a_burst_of_close_acks_is_not_the_peak() {
        let mut m = RateMeter::default();
        m.record(ms(300), 30_000);
        // Two ACKs 1 ms apart: 8 MB/s between them, not over PEAK_SPAN.
        m.record(ms(301), 38_000);
        m.record(ms(600), 60_000);
        // 0 to 301 ms is the fastest stretch long enough: about 126 kB/s.
        let peak = m.peak().expect("peak");
        assert!((126_000.0..127_000.0).contains(&peak), "{peak}");
    }

    #[test]
    fn peak_looks_past_the_first_point_far_enough_away() {
        let mut m = RateMeter::default();
        m.record(ms(250), 100);
        m.record(ms(251), 100_000);
        let peak = m.peak().expect("peak");
        let avg = m.average().expect("average");
        assert!(peak >= avg, "{peak} < {avg}");
    }

    #[test]
    fn an_upload_shorter_than_the_span_peaks_at_its_average() {
        let mut m = RateMeter::default();
        m.record(ms(100), 10_000);
        assert_eq!(m.peak(), Some(100_000.0));
    }
}
