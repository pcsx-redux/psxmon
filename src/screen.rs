//! Find the framebuffer that was on screen in the boot-time VRAM copy.
//!
//! The monitor's loaders copy VRAM to 0x80080000 and, before resetting the
//! GPU for that, save GPUSTAT and the GP1(10h) drawing area and offset to a
//! 32-byte block at 0x80180000. The display start (GP1(05h)) cannot be read
//! back, so which buffer was shown is a guess: the drawing area is the buffer
//! being drawn, and the shown one is usually the neighbouring buffer whose
//! pixels look most like it. Measured against the true display start in
//! PCSX-Redux on seven games the rule was not tuned on, the guess was exact 66%
//! of the time, and the right buffer was one of the three candidates this
//! returns 83% of the time. It is weakest on triple buffering, on games that
//! draw into the shown buffer, and on 24-bit movies.

pub const STATE_ADDR: u32 = 0x8018_0000;
pub const STATE_LEN: u32 = 32;
const STATE_MAGIC: u32 = 0x5355_5047; // "GPUS"
const STATE_VERSION: u32 = 1;

pub const VRAM_WIDTH: u32 = 1024;
pub const VRAM_HEIGHT: u32 = 512;
/// Bytes in one 1024-halfword VRAM line.
const VRAM_STRIDE: usize = 2048;

/// The GPU state the loader saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuState {
    pub gpustat: u32,
    /// Drawing area top-left, GP1(10h) index 3.
    pub draw_x: u32,
    pub draw_y: u32,
    /// GP1(10h) index 7; stale GPUREAD on the original 160-pin GPU.
    pub gpu_version: u32,
}

impl GpuState {
    /// Parse the 32-byte block, or `None` if it does not carry the tag
    /// (a monitor built before the block existed, or RAM overwritten since).
    #[must_use]
    pub fn parse(block: &[u8]) -> Option<Self> {
        let word = |i: usize| -> Option<u32> {
            let at = i.checked_mul(4)?;
            let b = block.get(at..at.checked_add(4)?)?;
            Some(u32::from_le_bytes(b.try_into().ok()?))
        };
        if word(0)? != STATE_MAGIC || word(1)? != STATE_VERSION {
            return None;
        }
        let tl = word(4)?;
        Some(Self {
            gpustat: word(2)?,
            draw_x: tl & 0x3ff,
            draw_y: (tl >> 10) & 0x1ff,
            gpu_version: word(7)?,
        })
    }

    #[must_use]
    pub fn mode(&self) -> Mode {
        Mode::from_gpustat(self.gpustat)
    }
}

/// The display mode, from GPUSTAT bits 16-23.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in lines: 240 or 480 (NTSC), 256 or 512 (PAL).
    pub height: u32,
    pub depth24: bool,
    pub interlaced: bool,
    pub pal: bool,
    pub display_on: bool,
}

impl Mode {
    #[must_use]
    pub fn from_gpustat(s: u32) -> Self {
        let width = if s & (1 << 16) != 0 {
            368
        } else {
            [256, 320, 512, 640]
                .get(((s >> 17) & 3) as usize)
                .copied()
                .unwrap_or(320)
        };
        let interlaced = s & (1 << 22) != 0;
        let pal = s & (1 << 20) != 0;
        let double = interlaced && s & (1 << 19) != 0;
        let height = match (pal, double) {
            (false, false) => 240,
            (false, true) => 480,
            (true, false) => 256,
            (true, true) => 512,
        };
        Self {
            width,
            height,
            depth24: s & (1 << 21) != 0,
            interlaced,
            pal,
            display_on: s & (1 << 23) == 0,
        }
    }

    /// Width of one buffer in VRAM halfwords (24-bit pixels take 1.5).
    #[must_use]
    pub fn vram_width(&self) -> u32 {
        if self.depth24 {
            self.width.wrapping_mul(3) / 2
        } else {
            self.width
        }
    }
}

/// Where a candidate came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The neighbouring buffer that looks most like the one being drawn.
    Neighbour,
    /// The buffer holding the drawing area (single-buffered or 480i output).
    DrawBuffer,
    /// The drawing area's own top-left corner (24-bit movies are shown from
    /// where they are decoded, which need not be a buffer boundary).
    DrawArea,
}

/// A buffer origin in VRAM halfwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub x: u32,
    pub y: u32,
    pub why: Why,
}

/// The guess first, then the other candidates, without duplicates.
#[must_use]
pub fn candidates(state: &GpuState, vram: &[u8]) -> Vec<Candidate> {
    let mode = state.mode();
    let wv = mode.vram_width();
    let h = mode.height;
    let (tx, ty) = (state.draw_x, state.draw_y);
    let ox = tx.wrapping_sub(tx.checked_rem(wv).unwrap_or(0));
    let oy = ty.wrapping_sub(ty.checked_rem(h).unwrap_or(0));
    let draw_buffer = Candidate {
        x: ox,
        y: oy,
        why: Why::DrawBuffer,
    };
    let draw_area = Candidate {
        x: tx,
        y: ty,
        why: Why::DrawArea,
    };
    let mut out = Vec::with_capacity(3);
    if mode.depth24 {
        out.push(draw_area);
    } else if h < 480
        && oy.saturating_add(h) <= VRAM_HEIGHT
        && let Some(n) = closest_neighbour(vram, &mode, ox, oy)
    {
        out.push(n);
    }
    for c in [draw_buffer, draw_area] {
        if !out.iter().any(|o| o.x == c.x && o.y == c.y) {
            out.push(c);
        }
    }
    out
}

/// Grid neighbours of the buffer at (ox, oy): up to three buffers either
/// side, one above and one below, kept inside VRAM.
fn neighbours(mode: &Mode, ox: u32, oy: u32) -> Vec<(u32, u32)> {
    let wv = mode.vram_width();
    let h = mode.height;
    let mut out = Vec::new();
    for k in 1..=3u32 {
        let d = wv.saturating_mul(k);
        if let Some(x) = ox.checked_sub(d) {
            out.push((x, oy));
        }
        let x = ox.saturating_add(d);
        if x.saturating_add(wv) <= VRAM_WIDTH {
            out.push((x, oy));
        }
    }
    if let Some(y) = oy.checked_sub(h) {
        out.push((ox, y));
    }
    let y = oy.saturating_add(h);
    if y.saturating_add(h) <= VRAM_HEIGHT {
        out.push((ox, y));
    }
    out
}

fn closest_neighbour(vram: &[u8], mode: &Mode, ox: u32, oy: u32) -> Option<Candidate> {
    let reference = channels(vram, ox, oy, mode.vram_width(), mode.height);
    neighbours(mode, ox, oy)
        .into_iter()
        .map(|(x, y)| {
            let other = channels(vram, x, y, mode.vram_width(), mode.height);
            let diff: u64 = reference
                .iter()
                .zip(&other)
                .map(|(a, b)| u64::from(a.abs_diff(*b)))
                .fold(0u64, u64::wrapping_add);
            (diff, x, y)
        })
        .min_by_key(|&(diff, _, _)| diff)
        .map(|(_, x, y)| Candidate {
            x,
            y,
            why: Why::Neighbour,
        })
}

fn halfword(vram: &[u8], x: u32, y: u32) -> u16 {
    let row = (y & (VRAM_HEIGHT - 1)) as usize;
    let col = (x & (VRAM_WIDTH - 1)) as usize;
    let at = row
        .wrapping_mul(VRAM_STRIDE)
        .wrapping_add(col.wrapping_mul(2));
    vram.get(at..at.wrapping_add(2))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

/// The 5-bit R, G, B channels of a w x h halfword rectangle, for comparing.
fn channels(vram: &[u8], x: u32, y: u32, w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for dy in 0..h {
        for dx in 0..w {
            let p = halfword(vram, x.wrapping_add(dx), y.wrapping_add(dy));
            out.extend([p & 0x1f, (p >> 5) & 0x1f, (p >> 10) & 0x1f].map(|c| c.to_le_bytes()[0]));
        }
    }
    out
}

fn expand5(v: u16) -> u8 {
    let v = v.to_le_bytes()[0] & 0x1f;
    (v << 3) | (v >> 2)
}

/// Decode the visible picture at a buffer origin to RGB8, `mode.width` x
/// `mode.height`, wrapping at the VRAM edges as the GPU does.
#[must_use]
pub fn picture(vram: &[u8], x: u32, y: u32, mode: &Mode) -> Vec<u8> {
    let mut out = Vec::new();
    for dy in 0..mode.height {
        let row = (y.wrapping_add(dy) & (VRAM_HEIGHT - 1)) as usize;
        let line =
            vram.get(row.wrapping_mul(VRAM_STRIDE)..row.wrapping_add(1).wrapping_mul(VRAM_STRIDE));
        let line = line.unwrap_or(&[]);
        let byte = |i: usize| line.get(i & (VRAM_STRIDE - 1)).copied().unwrap_or(0);
        let start = (x & (VRAM_WIDTH - 1)) as usize * 2;
        for dx in 0..mode.width as usize {
            if mode.depth24 {
                let at = start.wrapping_add(dx.wrapping_mul(3));
                out.extend([byte(at), byte(at.wrapping_add(1)), byte(at.wrapping_add(2))]);
            } else {
                let at = start.wrapping_add(dx.wrapping_mul(2));
                let p = u16::from_le_bytes([byte(at), byte(at.wrapping_add(1))]);
                out.extend([expand5(p), expand5(p >> 5), expand5(p >> 10)]);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(gpustat: u32, tl: (u32, u32)) -> Vec<u8> {
        [
            STATE_MAGIC,
            STATE_VERSION,
            gpustat,
            0,
            tl.0 | (tl.1 << 10),
            0,
            0,
            2,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
    }

    fn put(vram: &mut [u8], x: u32, y: u32, p: u16) {
        let at = (y as usize)
            .wrapping_mul(VRAM_STRIDE)
            .wrapping_add((x as usize).wrapping_mul(2));
        vram[at..at.wrapping_add(2)].copy_from_slice(&p.to_le_bytes());
    }

    /// Fill a w x h rectangle with a pattern that varies with `seed`.
    fn fill(vram: &mut [u8], x: u32, y: u32, w: u32, h: u32, seed: u16) {
        for dy in 0..h {
            for dx in 0..w {
                let dx16 = u16::try_from(dx).expect("width fits");
                let dy16 = u16::try_from(dy).expect("height fits");
                let v = (dx16.wrapping_mul(7) ^ dy16.wrapping_mul(13) ^ seed) & 0x7fff;
                put(vram, x.wrapping_add(dx), y.wrapping_add(dy), v);
            }
        }
    }

    #[test]
    fn untagged_block_is_none() {
        assert_eq!(GpuState::parse(&[0; 32]), None);
        assert_eq!(GpuState::parse(&block(0, (0, 0))[..16]), None);
    }

    #[test]
    fn mode_from_gpustat() {
        // Redux, psyqo hello after a reset: 320x240, 15-bit, display on.
        let m = Mode::from_gpustat(0x3602_241f);
        assert_eq!(
            (m.width, m.height, m.depth24, m.display_on),
            (320, 240, false, true)
        );
        // GP1(00h) reset value: 256x240, display off.
        let m = Mode::from_gpustat(0x1480_2000);
        assert_eq!((m.width, m.display_on), (256, false));
        // 640x480i, 24-bit.
        let m = Mode::from_gpustat((3 << 17) | (1 << 19) | (1 << 21) | (1 << 22));
        assert_eq!(
            (m.width, m.height, m.depth24, m.vram_width()),
            (640, 480, true, 960)
        );
    }

    #[test]
    fn double_buffer_picks_the_matching_neighbour() {
        let mut vram = vec![0u8; VRAM_STRIDE * VRAM_HEIGHT as usize];
        // Drawing into (0,240); last frame at (0,0) looks alike; textures at (320,240).
        fill(&mut vram, 0, 0, 320, 240, 1);
        fill(&mut vram, 0, 240, 320, 240, 1);
        fill(&mut vram, 0, 240, 320, 40, 0x5555);
        fill(&mut vram, 320, 240, 320, 240, 0x2a2a);
        let s = GpuState::parse(&block(0x0002_0000, (0, 240))).expect("block");
        let c = candidates(&s, &vram);
        assert_eq!((c[0].x, c[0].y, c[0].why), (0, 0, Why::Neighbour));
        assert_eq!((c[1].x, c[1].y, c[1].why), (0, 240, Why::DrawBuffer));
        assert_eq!(c.len(), 2, "draw area equals the draw buffer here");
    }

    #[test]
    fn buffer_spacing_comes_from_the_mode_not_the_drawing_area() {
        // Drawing area starts 16 lines into a 240-spaced buffer (FF7 shape).
        let mut vram = vec![0u8; VRAM_STRIDE * VRAM_HEIGHT as usize];
        fill(&mut vram, 0, 0, 320, 240, 3);
        fill(&mut vram, 0, 240, 320, 240, 3);
        let s = GpuState::parse(&block(0x0002_0000, (0, 16))).expect("block");
        let c = candidates(&s, &vram);
        assert_eq!((c[0].x, c[0].y), (0, 240));
        assert_eq!((c[1].x, c[1].y, c[1].why), (0, 0, Why::DrawBuffer));
        assert_eq!((c[2].x, c[2].y, c[2].why), (0, 16, Why::DrawArea));
    }

    #[test]
    fn interlaced_and_24_bit_do_not_guess_a_neighbour() {
        let vram = vec![0u8; VRAM_STRIDE * VRAM_HEIGHT as usize];
        let i480 = (3 << 17) | (1 << 19) | (1 << 22);
        let c = candidates(
            &GpuState::parse(&block(i480, (0, 0))).expect("block"),
            &vram,
        );
        assert_eq!((c[0].x, c[0].y, c[0].why), (0, 0, Why::DrawBuffer));
        let d24 = (1 << 17) | (1 << 21);
        let c = candidates(
            &GpuState::parse(&block(d24, (0, 256))).expect("block"),
            &vram,
        );
        assert_eq!((c[0].x, c[0].y, c[0].why), (0, 256, Why::DrawArea));
    }

    #[test]
    fn picture_decodes_15_and_24_bit() {
        let mut vram = vec![0u8; VRAM_STRIDE * VRAM_HEIGHT as usize];
        put(&mut vram, 10, 5, 0x7c1f); // blue + red
        let m = Mode::from_gpustat(0);
        let p = picture(&vram, 10, 5, &m);
        assert_eq!(p.len(), 256 * 240 * 3);
        assert_eq!(&p[..3], &[255, 0, 255]);
        // 24-bit: three bytes per pixel straight from the halfword stream.
        let at = 7 * VRAM_STRIDE + 20 * 2;
        vram[at..at + 6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        let m = Mode::from_gpustat(1 << 21);
        let p = picture(&vram, 20, 7, &m);
        assert_eq!(&p[..6], &[1, 2, 3, 4, 5, 6]);
    }
}
