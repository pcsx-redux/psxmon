//! Program images: what gets written where, and where execution starts.
//! PS-EXE, ELF, CPE and PSF/MiniPSF, told apart by their magic.

use std::collections::HashMap;
use std::path::Path;

/// Size of the PS-EXE header; the text follows it.
pub const PS_EXE_HEADER_SIZE: usize = 2048;
/// Stack top for a PS-EXE that sets none (`s_addr + s_size == 0`), as the
/// reference host uses.
pub const DEFAULT_STACK: u32 = 0x801f_fff0;
/// Stack top for ELF and CPE programs, which carry none: the top of 8 MB,
/// which a 2 MB console with the BIOS's 8 MB RAM window mirrors to the top of
/// its 2 MB.
pub const DEFAULT_STACK_ELF_CPE: u32 = 0x807f_ff00;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub addr: u32,
    pub data: Vec<u8>,
}

/// A loadable program: segments to write, then RUN with `pc`, `gp`, `sp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub segments: Vec<Segment>,
    pub pc: u32,
    pub gp: u32,
    pub sp: u32,
}

impl Image {
    pub fn total_bytes(&self) -> usize {
        self.segments
            .iter()
            .map(|s| s.data.len())
            .fold(0, usize::saturating_add)
    }

    /// Merge each segment into the one before it when it starts exactly
    /// where that one ends, so a CPE's many small load chunks go out as few
    /// transfers. Order is kept, so later data still wins over earlier.
    pub fn coalesce(&mut self) {
        let mut out: Vec<Segment> = Vec::with_capacity(self.segments.len());
        for seg in self.segments.drain(..) {
            if let Some(prev) = out.last_mut()
                && u32::try_from(prev.data.len())
                    .ok()
                    .and_then(|n| prev.addr.checked_add(n))
                    == Some(seg.addr)
            {
                prev.data.extend_from_slice(&seg.data);
            } else {
                out.push(seg);
            }
        }
        self.segments = out;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExeError {
    #[error("file too small to be a PS-EXE: need at least a 0x800-byte header")]
    TooSmall,
    #[error("unrecognised program format (want PS-EXE, ELF, CPE or PSF)")]
    Unknown,
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("ELF: {0}")]
    Elf(String),
    #[error("CPE: {0}")]
    Cpe(String),
    #[error("PSF: {0}")]
    Psf(String),
    #[error("{0} does not fit in the address space")]
    TooLarge(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn rd16(b: &[u8], off: usize, what: &'static str) -> Result<u16, ExeError> {
    let bytes = b
        .get(off..)
        .and_then(|s| s.first_chunk::<2>())
        .ok_or(ExeError::Truncated(what))?;
    Ok(u16::from_le_bytes(*bytes))
}

fn rd32(b: &[u8], off: usize, what: &'static str) -> Result<u32, ExeError> {
    let bytes = b
        .get(off..)
        .and_then(|s| s.first_chunk::<4>())
        .ok_or(ExeError::Truncated(what))?;
    Ok(u32::from_le_bytes(*bytes))
}

fn to_usize(v: u32, what: &'static str) -> Result<usize, ExeError> {
    usize::try_from(v).map_err(|_| ExeError::TooLarge(what))
}

/// `base + index * size`, for walking header tables.
fn table_entry(base: usize, index: usize, size: usize) -> Result<usize, ExeError> {
    index
        .checked_mul(size)
        .and_then(|o| base.checked_add(o))
        .ok_or(ExeError::TooLarge("header table"))
}

/// A PS-EXE, the way the reference host loads it: the file is padded with
/// zeros to a 2 KiB multiple, the text is `t_size` bytes after the header
/// (all of it when `t_size` is 0), loaded at `t_addr`; entry `pc0`, `gp0`,
/// and `sp = s_addr + s_size` or [`DEFAULT_STACK`].
pub fn parse_ps_exe(file: &[u8]) -> Result<Image, ExeError> {
    let text = file.get(PS_EXE_HEADER_SIZE..).ok_or(ExeError::TooSmall)?;
    let padded = text
        .len()
        .checked_next_multiple_of(PS_EXE_HEADER_SIZE)
        .ok_or(ExeError::TooLarge("PS-EXE"))?;
    let size = match to_usize(rd32(file, 0x1c, "PS-EXE header")?, "t_size")? {
        0 => padded,
        n => n.min(padded),
    };
    let mut data = text
        .get(..size.min(text.len()))
        .unwrap_or_default()
        .to_vec();
    data.resize(size, 0);
    // (s_addr + s_size) >>> 0 in the reference host: a u32 sum that wraps.
    let sp = rd32(file, 0x30, "PS-EXE header")?.wrapping_add(rd32(file, 0x34, "PS-EXE header")?);
    Ok(Image {
        segments: vec![Segment {
            addr: rd32(file, 0x18, "PS-EXE header")?,
            data,
        }],
        pc: rd32(file, 0x10, "PS-EXE header")?,
        gp: rd32(file, 0x14, "PS-EXE header")?,
        sp: if sp == 0 { DEFAULT_STACK } else { sp },
    })
}

const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_NOBITS: u32 = 8;
const SHF_ALLOC: u32 = 2;
const EM_MIPS: u16 = 8;

struct ElfSection {
    name: String,
    ty: u32,
    flags: u32,
    offset: usize,
    size: usize,
    link: u32,
}

/// The NUL-terminated string at `off` in `table`.
fn c_string(table: &[u8], off: usize) -> String {
    let s = table.get(off..).unwrap_or_default();
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(s.get(..end).unwrap_or_default()).into_owned()
}

fn elf_sections(file: &[u8]) -> Result<Vec<ElfSection>, ExeError> {
    let shoff = to_usize(rd32(file, 0x20, "ELF header")?, "e_shoff")?;
    let shentsize = usize::from(rd16(file, 0x2e, "ELF header")?);
    let shnum = usize::from(rd16(file, 0x30, "ELF header")?);
    let shstrndx = usize::from(rd16(file, 0x32, "ELF header")?);
    if shoff == 0 || shnum == 0 {
        return Ok(Vec::new());
    }
    let mut raw = Vec::with_capacity(shnum);
    for k in 0..shnum {
        let at = table_entry(shoff, k, shentsize)?;
        let field = |o: usize| rd32(file, at.saturating_add(o), "ELF section header");
        raw.push((
            field(0)?,
            ElfSection {
                name: String::new(),
                ty: field(0x04)?,
                flags: field(0x08)?,
                offset: to_usize(field(0x10)?, "sh_offset")?,
                size: to_usize(field(0x14)?, "sh_size")?,
                link: field(0x18)?,
            },
        ));
    }
    let names = raw
        .get(shstrndx)
        .and_then(|(_, s)| file.get(s.offset..s.offset.saturating_add(s.size)))
        .unwrap_or_default();
    Ok(raw
        .into_iter()
        .map(|(name_off, mut s)| {
            s.name = to_usize(name_off, "sh_name")
                .map(|o| c_string(names, o))
                .unwrap_or_default();
            s
        })
        .collect())
}

/// The value of symbol `wanted` in the ELF symbol tables, if any.
fn elf_symbol(file: &[u8], sections: &[ElfSection], wanted: &str) -> Option<u32> {
    for symtab in sections.iter().filter(|s| s.ty == SHT_SYMTAB) {
        let strtab = sections.get(usize::try_from(symtab.link).ok()?)?;
        let strings = file.get(strtab.offset..strtab.offset.saturating_add(strtab.size))?;
        let table = file.get(symtab.offset..symtab.offset.saturating_add(symtab.size))?;
        for sym in table.as_chunks::<16>().0 {
            let name = usize::try_from(rd32(sym, 0, "symbol").ok()?).ok()?;
            if c_string(strings, name) == wanted {
                return rd32(sym, 4, "symbol").ok();
            }
        }
    }
    None
}

/// A named address from an ELF symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub addr: u32,
    /// `st_size`; 0 for assembler labels and other unsized symbols.
    pub size: u32,
}

/// The defined function, object and untyped symbols of an ELF, sorted by
/// address. Section, file and undefined symbols are left out.
pub fn elf_symbols(file: &[u8]) -> Result<Vec<Symbol>, ExeError> {
    if !file.starts_with(b"\x7fELF") {
        return Err(ExeError::Elf("not an ELF file".into()));
    }
    if file.get(4) != Some(&1) || file.get(5) != Some(&1) {
        return Err(ExeError::Elf("not a 32-bit little-endian ELF".into()));
    }
    let sections = elf_sections(file)?;
    let mut out = Vec::new();
    for symtab in sections.iter().filter(|s| s.ty == SHT_SYMTAB) {
        let Some(strings) = usize::try_from(symtab.link)
            .ok()
            .and_then(|i| sections.get(i))
            .and_then(|t| file.get(t.offset..t.offset.saturating_add(t.size)))
        else {
            continue;
        };
        let table = file
            .get(symtab.offset..symtab.offset.saturating_add(symtab.size))
            .ok_or(ExeError::Truncated("ELF symbol table"))?;
        for sym in table.as_chunks::<16>().0 {
            let name = c_string(strings, to_usize(rd32(sym, 0, "symbol")?, "st_name")?);
            let addr = rd32(sym, 4, "symbol")?;
            let size = rd32(sym, 8, "symbol")?;
            let info = sym.get(12).copied().unwrap_or(0);
            let shndx = rd16(sym, 14, "symbol")?;
            // STT_NOTYPE, STT_OBJECT, STT_FUNC; SHN_UNDEF is 0.
            if info & 0xf <= 2 && shndx != 0 && !name.is_empty() && !name.starts_with('$') {
                out.push(Symbol { name, addr, size });
            }
        }
    }
    out.sort_by_key(|s| s.addr);
    Ok(out)
}

/// A 32-bit little-endian MIPS ELF. Each PT_LOAD segment is written at its
/// `p_paddr`, trimmed to the allocated, file-backed sections it holds other
/// than `*_Header` ones (the PS-EXE header section the nugget linker script
/// emits, and the ELF headers a linker may place in the first segment, are
/// not program data). An ELF without section headers loads whole segments.
/// Entry from `e_entry`; gp from `_gp` if present, else 0; sp
/// [`DEFAULT_STACK_ELF_CPE`]. BSS is not zeroed: PS1 programs clear their
/// own, as they must when run from a PS-EXE.
pub fn parse_elf(file: &[u8]) -> Result<Image, ExeError> {
    let ident = file.get(..16).ok_or(ExeError::Truncated("ELF header"))?;
    if ident.get(4) != Some(&1) || ident.get(5) != Some(&1) {
        return Err(ExeError::Elf("not a 32-bit little-endian ELF".into()));
    }
    let machine = rd16(file, 0x12, "ELF header")?;
    if machine != EM_MIPS {
        return Err(ExeError::Elf(format!("machine {machine} is not MIPS")));
    }
    let entry = rd32(file, 0x18, "ELF header")?;
    let phoff = to_usize(rd32(file, 0x1c, "ELF header")?, "e_phoff")?;
    let phentsize = usize::from(rd16(file, 0x2a, "ELF header")?);
    let phnum = usize::from(rd16(file, 0x2c, "ELF header")?);
    let sections = elf_sections(file)?;
    let program: Vec<(usize, usize)> = sections
        .iter()
        .filter(|s| {
            s.flags & SHF_ALLOC != 0
                && s.ty != SHT_NOBITS
                && s.size > 0
                && !s.name.ends_with("_Header")
        })
        .map(|s| (s.offset, s.offset.saturating_add(s.size)))
        .collect();

    let mut segments = Vec::new();
    for k in 0..phnum {
        let at = table_entry(phoff, k, phentsize)?;
        let field = |o: usize| rd32(file, at.saturating_add(o), "ELF program header");
        if field(0)? != PT_LOAD {
            continue;
        }
        let offset = to_usize(field(0x04)?, "p_offset")?;
        let paddr = field(0x0c)?;
        let end = offset.saturating_add(to_usize(field(0x10)?, "p_filesz")?);
        let (lo, hi) = if sections.is_empty() {
            (offset, end)
        } else {
            let inside = program.iter().filter(|&&(s, e)| s >= offset && e <= end);
            let lo = inside.clone().map(|&(s, _)| s).min();
            let hi = inside.map(|&(_, e)| e).max();
            match (lo, hi) {
                (Some(lo), Some(hi)) => (lo, hi),
                _ => continue,
            }
        };
        if lo >= hi {
            continue;
        }
        let data = file
            .get(lo..hi)
            .ok_or(ExeError::Truncated("ELF segment"))?
            .to_vec();
        let delta = u32::try_from(lo.saturating_sub(offset))
            .map_err(|_| ExeError::TooLarge("ELF segment"))?;
        let addr = paddr
            .checked_add(delta)
            .ok_or(ExeError::TooLarge("ELF segment"))?;
        segments.push(Segment { addr, data });
    }
    if segments.is_empty() {
        return Err(ExeError::Elf("no loadable segments".into()));
    }
    Ok(Image {
        segments,
        pc: entry,
        gp: elf_symbol(file, &sections, "_gp").unwrap_or(0),
        sp: DEFAULT_STACK_ELF_CPE,
    })
}

/// The CPE register id that holds the initial PC. psx-spx, PCSX-Redux's
/// loader and ps1-packer all use it; none documents an id for SP or GP.
pub const CPE_REG_PC: u16 = 0x90;

/// A PsyQ CPE: the 4-byte `CPE\x01` id, then chunks. 0x00 end; 0x01 load
/// `[addr:u32][size:u32][data]`; 0x03..0x06 set register `[reg:u16]` to a
/// 4/2/1/3-byte value; 0x02 run address and 0x07 workspace `[u32]` and 0x08
/// select unit `[u8]` are skipped. Register 0x90 is the entry PC; values
/// for other registers are ignored. gp is 0, sp [`DEFAULT_STACK_ELF_CPE`].
pub fn parse_cpe(file: &[u8]) -> Result<Image, ExeError> {
    let mut rest = file.get(4..).ok_or(ExeError::Truncated("CPE header"))?;
    let mut take = |n: usize| -> Result<&[u8], ExeError> {
        let (head, tail) = rest
            .split_at_checked(n)
            .ok_or(ExeError::Truncated("CPE chunk"))?;
        rest = tail;
        Ok(head)
    };
    let mut segments = Vec::new();
    let mut pc = None;
    loop {
        let &[op] = take(1)?
            .first_chunk::<1>()
            .ok_or(ExeError::Truncated("CPE chunk"))?;
        match op {
            0x00 => break,
            0x01 => {
                let addr = rd32(take(4)?, 0, "CPE load chunk")?;
                let size = to_usize(rd32(take(4)?, 0, "CPE load chunk")?, "CPE load size")?;
                segments.push(Segment {
                    addr,
                    data: take(size)?.to_vec(),
                });
            }
            0x03..=0x06 => {
                let reg = rd16(take(2)?, 0, "CPE register chunk")?;
                let width = match op {
                    0x03 => 4,
                    0x04 => 2,
                    0x05 => 1,
                    _ => 3,
                };
                let mut value = [0u8; 4];
                for (dst, src) in value.iter_mut().zip(take(width)?) {
                    *dst = *src;
                }
                if reg == CPE_REG_PC {
                    pc = Some(u32::from_le_bytes(value));
                }
            }
            0x02 | 0x07 => {
                take(4)?;
            }
            0x08 => {
                take(1)?;
            }
            other => return Err(ExeError::Cpe(format!("unsupported chunk 0x{other:02x}"))),
        }
    }
    let pc = pc.ok_or_else(|| ExeError::Cpe("no entry point (register 0x90)".into()))?;
    let mut image = Image {
        segments,
        pc,
        gp: 0,
        sp: DEFAULT_STACK_ELF_CPE,
    };
    image.coalesce();
    Ok(image)
}

/// Parse a program file by its magic.
pub fn parse(file: &[u8]) -> Result<Image, ExeError> {
    if file.starts_with(b"\x7fELF") {
        parse_elf(file)
    } else if file.starts_with(b"CPE\x01") {
        parse_cpe(file)
    } else if file.starts_with(b"PS-X EXE") {
        parse_ps_exe(file)
    } else if file.starts_with(PSF_MAGIC) {
        Err(ExeError::Psf(
            "a PSF is loaded from a path, to find its _lib files (exe::load)".into(),
        ))
    } else {
        Err(ExeError::Unknown)
    }
}

/// Load a program file. A PSF pulls in its `_lib` files, found relative to
/// the file that names them; PSF warnings (skipped libraries) go to stderr.
pub fn load(path: &Path) -> Result<Image, ExeError> {
    let file = std::fs::read(path)?;
    if file.starts_with(PSF_MAGIC) {
        let psf = load_psf(path)?;
        for w in &psf.warnings {
            eprintln!("psxmon: {w}");
        }
        return Ok(psf.image);
    }
    parse(&file)
}

/// `PSF` then version 0x01, the PlayStation one.
pub const PSF_MAGIC: &[u8; 4] = b"PSF\x01";
/// PCSX-Redux's `loadPSF` gives up at this `_lib` nesting depth.
pub const PSF_MAX_DEPTH: u32 = 10;

/// Video region a PSF asks for, from its `refresh` tag or the PS-EXE's
/// region marker. Informational: psxmon cannot change the console's region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    Ntsc,
    Pal,
}

/// A loaded PSF: the program image, the region hint, and the `_lib`
/// entries that were skipped (missing, not a PSF, or nested too deep).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Psf {
    pub image: Image,
    pub region: Option<Region>,
    pub warnings: Vec<String>,
}

#[derive(Default)]
struct PsfState {
    segments: Vec<Segment>,
    pc: Option<u32>,
    gp: Option<u32>,
    sp: Option<u32>,
    region: Option<Region>,
    /// Whether any PS-EXE has been loaded yet, across the whole chain.
    seen_exe: bool,
    warnings: Vec<String>,
}

/// The PSF tag area, the way PCSX-Redux reads it: after `[TAG]`, split on
/// `\n` and `\r`, each line cut at its first `=`, no trimming, keys
/// case-sensitive, the last of a repeated key wins. Lines without `=` are
/// ignored. No `[TAG]` means no tags.
pub fn psf_tags(tag_area: &[u8]) -> HashMap<String, String> {
    let mut pairs = HashMap::new();
    let Some(text) = tag_area.strip_prefix(b"[TAG]") else {
        return pairs;
    };
    for line in text.split(|&b| b == b'\n' || b == b'\r') {
        if let Some(eq) = line.iter().position(|&b| b == b'=') {
            let (key, value) = line.split_at(eq);
            pairs.insert(
                String::from_utf8_lossy(key).into_owned(),
                String::from_utf8_lossy(value.get(1..).unwrap_or_default()).into_owned(),
            );
        }
    }
    pairs
}

/// A PSF (version 0x01) or MiniPSF with its `_lib` chain, loaded with the
/// semantics of PCSX-Redux's `loadPSF`/`loadPSEXE` (`binloader.cc`):
///
/// - Layout: `PSF\x01`, reserved size R, program size N, CRC (not
///   checked), R reserved bytes (skipped), N bytes of zlib-compressed
///   PS-EXE, then optionally `[TAG]` and the tags (see [`psf_tags`]).
/// - Order: the `_lib` file (recursively), then this file's PS-EXE, then
///   `_lib2`, `_lib3`, ... for as long as the numbering is unbroken. Library
///   paths are relative to the directory of the file naming them. Later
///   writes win where they overlap.
/// - pc and sp come from the FIRST PS-EXE loaded (for a MiniPSF on a lib,
///   the lib's): pc is `pc0`, sp is `s_addr` (not `s_addr + s_size`) and
///   only when non-zero, else [`DEFAULT_STACK`]. Later PS-EXEs are overlays.
///   Redux does not set gp for a PSF; psxmon uses the first PS-EXE's `gp0`.
/// - Each PS-EXE writes exactly `t_size` bytes (fewer if the data is
///   shorter) at `t_addr`; no padding.
/// - Region: the first `refresh` tag met in load order (50 PAL, 60 NTSC)
///   is set before any PS-EXE loads, then every PS-EXE's byte at 0x71
///   (`A`/`J` NTSC, `E` PAL) overrides it as it loads.
/// - A `_lib` that does not open, is not a PSF, or is 10 levels deep is
///   skipped, as Redux does; psxmon records a warning. A decompressed
///   program that is not a PS-EXE loads nothing but still counts as the
///   first exe. A corrupt zlib stream is an error.
pub fn load_psf(path: &Path) -> Result<Psf, ExeError> {
    let file = std::fs::read(path)?;
    if !file.starts_with(PSF_MAGIC) {
        return Err(ExeError::Psf(
            "not a PSF (want \"PSF\" version 0x01)".into(),
        ));
    }
    let mut st = PsfState::default();
    load_psf_file(path, &file, &mut st, false, 0)?;
    let pc = st
        .pc
        .ok_or_else(|| ExeError::Psf("no PS-EXE with an entry point in the chain".into()))?;
    Ok(Psf {
        image: Image {
            segments: st.segments,
            pc,
            gp: st.gp.unwrap_or(0),
            sp: st.sp.unwrap_or(DEFAULT_STACK),
        },
        region: st.region,
        warnings: st.warnings,
    })
}

/// A `_lib` entry: open and load it, or record why it was skipped.
fn load_psf_lib(
    parent: &Path,
    tag: &str,
    name: &str,
    st: &mut PsfState,
    seen_refresh: bool,
    depth: u32,
) -> Result<(), ExeError> {
    let dir = parent.parent().unwrap_or_else(|| Path::new(""));
    let path = dir.join(name);
    let file = match std::fs::read(&path) {
        Ok(f) => f,
        Err(e) => {
            st.warnings.push(format!(
                "{}: {tag} {}: {e}; skipped",
                parent.display(),
                path.display()
            ));
            return Ok(());
        }
    };
    if !load_psf_file(&path, &file, st, seen_refresh, depth)? {
        st.warnings.push(format!(
            "{}: {tag} {}: not a PSF or nested {PSF_MAX_DEPTH} deep; skipped",
            parent.display(),
            path.display()
        ));
    }
    Ok(())
}

/// Redux's `loadPSF`: false (nothing loaded) on a bad magic or too deep.
fn load_psf_file(
    path: &Path,
    file: &[u8],
    st: &mut PsfState,
    mut seen_refresh: bool,
    depth: u32,
) -> Result<bool, ExeError> {
    if depth >= PSF_MAX_DEPTH || !file.starts_with(PSF_MAGIC) {
        return Ok(false);
    }
    let reserved = to_usize(rd32(file, 4, "PSF header")?, "PSF reserved size")?;
    let program = to_usize(rd32(file, 8, "PSF header")?, "PSF program size")?;
    let start = 16usize
        .checked_add(reserved)
        .ok_or(ExeError::TooLarge("PSF reserved area"))?;
    let end = start
        .checked_add(program)
        .ok_or(ExeError::TooLarge("PSF program"))?;
    let compressed = file
        .get(start..end)
        .ok_or(ExeError::Truncated("PSF program"))?;
    let tags = psf_tags(file.get(end..).unwrap_or_default());

    if !seen_refresh && let Some(refresh) = tags.get("refresh") {
        match refresh.as_str() {
            "50" => st.region = Some(Region::Pal),
            "60" => st.region = Some(Region::Ntsc),
            _ => {}
        }
        seen_refresh = true;
    }
    let next = depth.saturating_add(1);
    if let Some(lib) = tags.get("_lib") {
        load_psf_lib(path, "_lib", lib, st, seen_refresh, next)?;
    }
    let exe = miniz_oxide::inflate::decompress_to_vec_zlib(compressed).map_err(|e| {
        ExeError::Psf(format!(
            "{}: bad zlib stream: {:?}",
            path.display(),
            e.status
        ))
    })?;
    load_psf_exe(&exe, st);
    st.seen_exe = true;
    for n in 2u32.. {
        let key = format!("_lib{n}");
        let Some(lib) = tags.get(&key) else {
            break;
        };
        load_psf_lib(path, &key, lib, st, seen_refresh, next)?;
    }
    Ok(true)
}

/// Redux's `loadPSEXE` with `overlay = seen_exe`.
fn load_psf_exe(exe: &[u8], st: &mut PsfState) {
    if !exe.starts_with(b"PS-X EXE") {
        return;
    }
    let field = |off: usize| rd32(exe, off, "PS-EXE header").unwrap_or(0);
    if !st.seen_exe {
        st.pc = Some(field(0x10));
        st.gp = Some(field(0x14));
        let sp = field(0x30);
        if sp != 0 {
            st.sp = Some(sp);
        }
    }
    let size = usize::try_from(field(0x1c)).unwrap_or(usize::MAX);
    let text = exe.get(PS_EXE_HEADER_SIZE..).unwrap_or_default();
    let data = text.get(..size.min(text.len())).unwrap_or_default();
    st.segments.push(Segment {
        addr: field(0x18),
        data: data.to_vec(),
    });
    match exe.get(0x71) {
        Some(b'A' | b'J') => st.region = Some(Region::Ntsc),
        Some(b'E') => st.region = Some(Region::Pal),
        _ => {}
    }
}

/// A minimal PS-EXE around `text`, for tests and tools.
pub fn build_ps_exe(
    text: &[u8],
    t_addr: u32,
    pc: u32,
    gp: u32,
    stack: u32,
) -> Result<Vec<u8>, ExeError> {
    let padded = text
        .len()
        .checked_next_multiple_of(PS_EXE_HEADER_SIZE)
        .ok_or(ExeError::TooLarge("PS-EXE"))?;
    let t_size = u32::try_from(padded).map_err(|_| ExeError::TooLarge("PS-EXE"))?;
    let mut h = vec![0u8; PS_EXE_HEADER_SIZE];
    let mut put = |off: usize, bytes: &[u8]| {
        if let Some(dst) = h.get_mut(off..off.saturating_add(bytes.len())) {
            dst.copy_from_slice(bytes);
        }
    };
    put(0, b"PS-X EXE");
    put(0x10, &pc.to_le_bytes());
    put(0x14, &gp.to_le_bytes());
    put(0x18, &t_addr.to_le_bytes());
    put(0x1c, &t_size.to_le_bytes());
    put(0x30, &stack.to_le_bytes());
    h.extend_from_slice(text);
    h.resize(PS_EXE_HEADER_SIZE.saturating_add(padded), 0);
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_exe_fields() {
        let file =
            build_ps_exe(&[1, 2, 3], 0x8001_0000, 0x8001_0000, 0x8002_0000, 0).expect("build");
        let img = parse(&file).expect("parse");
        assert_eq!(img.pc, 0x8001_0000);
        assert_eq!(img.gp, 0x8002_0000);
        assert_eq!(img.sp, DEFAULT_STACK);
        assert_eq!(img.segments.len(), 1);
        let seg = img.segments.first().expect("one segment");
        assert_eq!(seg.addr, 0x8001_0000);
        assert_eq!(seg.data.len(), 2048);
        assert_eq!(seg.data.get(..4), Some(&[1u8, 2, 3, 0][..]));
        assert!(matches!(parse_ps_exe(&[0; 16]), Err(ExeError::TooSmall)));
        assert!(matches!(parse(&[0; 4096]), Err(ExeError::Unknown)));
    }

    #[test]
    fn short_file_is_padded_and_t_size_clamped() {
        let mut file =
            build_ps_exe(&[9; 10], 0x8001_0000, 0x8001_0000, 0, 0x801f_0000).expect("build");
        if let Some(t_size) = file.get_mut(0x1c..0x20) {
            t_size.copy_from_slice(&0x10000u32.to_le_bytes());
        }
        file.truncate(2048 + 100);
        let img = parse(&file).expect("parse");
        assert_eq!(img.segments.first().map(|s| s.data.len()), Some(2048));
        assert_eq!(img.sp, 0x801f_0000);
    }

    /// A little-endian MIPS ELF32 with the layout a nugget link produces:
    /// a first R segment holding the ELF headers and `.PSX_EXE_Header`, a
    /// second holding `.text` and `.data` with a gap between them, a
    /// `.bss`, and a symbol table with `_gp`.
    fn build_elf(with_gp: bool) -> Vec<u8> {
        fn put(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
            let end = off.checked_add(bytes.len()).expect("small offsets");
            if buf.len() < end {
                buf.resize(end, 0);
            }
            buf.get_mut(off..end)
                .expect("resized")
                .copy_from_slice(bytes);
        }
        fn table<const N: usize>(rows: &[[u32; N]]) -> Vec<u8> {
            rows.iter()
                .flatten()
                .flat_map(|v| v.to_le_bytes())
                .collect()
        }
        let w32 = |v: u32| v.to_le_bytes();
        let w16 = |v: u16| v.to_le_bytes();
        let mut f = vec![0u8; 0x1000];
        put(&mut f, 0, b"\x7fELF\x01\x01\x01");
        put(&mut f, 0x10, &w16(2)); // ET_EXEC
        put(&mut f, 0x12, &w16(EM_MIPS));
        put(&mut f, 0x18, &w32(0x8001_0000)); // e_entry
        put(&mut f, 0x1c, &w32(0x34)); // e_phoff
        put(&mut f, 0x2a, &w16(32)); // e_phentsize
        put(&mut f, 0x2c, &w16(2)); // e_phnum
        put(&mut f, 0x2e, &w16(40)); // e_shentsize
        // Program headers: [type, offset, vaddr, paddr, filesz, memsz, flags, align]
        let phdrs: [[u32; 8]; 2] = [
            [
                PT_LOAD,
                0,
                0x8000_f000,
                0x8000_f000,
                0x1000,
                0x1000,
                4,
                0x1000,
            ],
            [
                PT_LOAD,
                0x1000,
                0x8001_0000,
                0x8001_0000,
                0x40,
                0x100,
                7,
                0x1000,
            ],
        ];
        put(&mut f, 0x34, &table(&phdrs));
        put(&mut f, 0x800, b"PS-X EXE header bytes");
        put(&mut f, 0x1000, &[0xaa; 0x10]); // .text
        put(&mut f, 0x1020, &[0xbb; 0x20]); // .data
        // Strings, symbols.
        let shstr = b"\0.PSX_EXE_Header\0.text\0.data\0.bss\0.symtab\0.strtab\0.shstrtab\0";
        put(&mut f, 0x1100, shstr);
        let strtab = b"\0_start\0_gp\0";
        put(&mut f, 0x1180, strtab);
        let gp_name: u32 = if with_gp { 8 } else { 1 };
        let syms: [[u32; 4]; 2] = [[0, 0, 0, 0], [gp_name, 0x8001_8000, 0, 0]];
        put(&mut f, 0x1200, &table(&syms));
        // Section headers: [name, type, flags, addr, offset, size, link, info, align, entsize]
        let shdrs: [[u32; 10]; 8] = [
            [0; 10],
            [1, 1, SHF_ALLOC, 0x8000_f800, 0x800, 0x800, 0, 0, 1, 0],
            [17, 1, SHF_ALLOC | 4, 0x8001_0000, 0x1000, 0x10, 0, 0, 4, 0],
            [23, 1, SHF_ALLOC | 1, 0x8001_0020, 0x1020, 0x20, 0, 0, 4, 0],
            [
                29,
                SHT_NOBITS,
                SHF_ALLOC | 1,
                0x8001_0040,
                0x1040,
                0xc0,
                0,
                0,
                4,
                0,
            ],
            [34, SHT_SYMTAB, 0, 0, 0x1200, 32, 6, 1, 4, 16],
            [
                42,
                3,
                0,
                0,
                0x1180,
                u32::try_from(strtab.len()).expect("short"),
                0,
                0,
                1,
                0,
            ],
            [
                50,
                3,
                0,
                0,
                0x1100,
                u32::try_from(shstr.len()).expect("short"),
                0,
                0,
                1,
                0,
            ],
        ];
        let shoff = 0x1300usize;
        put(&mut f, shoff, &table(&shdrs));
        put(&mut f, 0x20, &w32(u32::try_from(shoff).expect("small")));
        put(&mut f, 0x30, &w16(8)); // e_shnum
        put(&mut f, 0x32, &w16(7)); // e_shstrndx
        f
    }

    #[test]
    fn elf_loads_program_sections_by_paddr() {
        let img = parse(&build_elf(true)).expect("parse ELF");
        assert_eq!(img.pc, 0x8001_0000);
        assert_eq!(img.gp, 0x8001_8000);
        assert_eq!(img.sp, 0x807f_ff00);
        // The header segment is skipped; the program segment spans .text
        // through .data, gap included, and no BSS.
        assert_eq!(img.segments.len(), 1);
        let seg = img.segments.first().expect("segment");
        assert_eq!(seg.addr, 0x8001_0000);
        assert_eq!(seg.data.len(), 0x40);
        assert_eq!(seg.data.get(..0x10), Some(&[0xaa; 0x10][..]));
        assert_eq!(seg.data.get(0x10..0x20), Some(&[0; 0x10][..]));
        assert_eq!(seg.data.get(0x20..), Some(&[0xbb; 0x20][..]));
        assert_eq!(parse(&build_elf(false)).expect("parse ELF").gp, 0);
    }

    #[test]
    fn elf_symbols_keep_defined_functions_objects_and_labels() {
        // build_elf's `_gp` is undefined (st_shndx 0), so it is left out.
        assert_eq!(elf_symbols(&build_elf(true)).expect("symbols"), vec![]);
        // Make it a defined function of size 0x40 in section 2: st_size at
        // +8, st_info at +12, st_shndx at +14 of symbol 1.
        let sym = 0x1200 + 16;
        let mut f = build_elf(true);
        f.splice(sym + 8..sym + 16, [0x40, 0, 0, 0, 2, 0, 2, 0]);
        let want = Symbol {
            name: "_gp".into(),
            addr: 0x8001_8000,
            size: 0x40,
        };
        assert_eq!(elf_symbols(&f).expect("symbols"), vec![want]);
        // A section symbol (STT_SECTION, 3) is not a name for code.
        f[sym + 12] = 3;
        assert_eq!(elf_symbols(&f).expect("symbols"), vec![]);
        assert!(elf_symbols(b"PS-X EXE").is_err());
        // ELF64 and big-endian layouts are refused, not misread.
        for (at, v) in [(4, 2), (5, 2)] {
            let mut g = build_elf(true);
            g[at] = v;
            assert!(matches!(elf_symbols(&g), Err(ExeError::Elf(_))));
        }
    }

    #[test]
    fn elf_rejects_wrong_class_and_machine() {
        let mut f = build_elf(true);
        if let Some(class) = f.get_mut(4) {
            *class = 2;
        }
        assert!(matches!(parse(&f), Err(ExeError::Elf(_))));
        let mut f = build_elf(true);
        f.splice(0x12..0x14, 3u16.to_le_bytes());
        assert!(matches!(parse(&f), Err(ExeError::Elf(_))));
    }

    fn cpe_load(addr: u32, data: &[u8]) -> Vec<u8> {
        let mut c = vec![0x01];
        c.extend(addr.to_le_bytes());
        c.extend(u32::try_from(data.len()).expect("short").to_le_bytes());
        c.extend(data);
        c
    }

    #[test]
    fn cpe_chunks() {
        let mut f = b"CPE\x01".to_vec();
        f.extend([0x08, 0x00]); // select unit 0
        f.extend([0x03, 0x90, 0x00]); // PC
        f.extend(0x8001_0010u32.to_le_bytes());
        f.extend([0x05, 0x74, 0x00, 0x7f]); // another register, ignored
        f.extend([0x07, 0, 0, 0, 0]); // workspace
        f.extend(cpe_load(0x8001_0000, &[1, 2, 3, 4]));
        f.extend(cpe_load(0x8001_0004, &[5, 6])); // contiguous: merged
        f.extend(cpe_load(0x8002_0000, &[7]));
        f.extend([0x02, 0, 0, 1, 0x80]); // run address, ignored
        f.push(0x00);
        let img = parse(&f).expect("parse CPE");
        assert_eq!(img.pc, 0x8001_0010);
        assert_eq!((img.gp, img.sp), (0, 0x807f_ff00));
        assert_eq!(
            img.segments,
            vec![
                Segment {
                    addr: 0x8001_0000,
                    data: vec![1, 2, 3, 4, 5, 6]
                },
                Segment {
                    addr: 0x8002_0000,
                    data: vec![7]
                },
            ]
        );
    }

    #[test]
    fn cpe_value_widths_and_errors() {
        // A 24-bit PC value.
        let mut f = b"CPE\x01".to_vec();
        f.extend([0x06, 0x90, 0x00, 0x33, 0x22, 0x11, 0x00]);
        assert_eq!(parse(&f).expect("parse").pc, 0x0011_2233);
        // No end chunk.
        let mut g = b"CPE\x01".to_vec();
        g.extend([0x03, 0x90, 0x00, 0, 0, 1, 0x80]);
        assert!(matches!(parse(&g), Err(ExeError::Truncated(_))));
        // Load chunk longer than the file.
        let mut h = b"CPE\x01".to_vec();
        h.extend(cpe_load(0x8001_0000, &[1, 2, 3]));
        h.truncate(h.len().saturating_sub(1));
        assert!(matches!(parse(&h), Err(ExeError::Truncated(_))));
        // Unknown chunk, and no entry point.
        assert!(matches!(parse(b"CPE\x01\x09"), Err(ExeError::Cpe(_))));
        assert!(matches!(parse(b"CPE\x01\x00"), Err(ExeError::Cpe(_))));
    }

    /// A PSF around `exe`: `reserved` bytes of reserved area, then the
    /// zlib-compressed program, then `tags` (with `[TAG]` if non-empty).
    fn build_psf(exe: &[u8], reserved: usize, tags: &str) -> Vec<u8> {
        let z = miniz_oxide::deflate::compress_to_vec_zlib(exe, 6);
        let mut f = PSF_MAGIC.to_vec();
        f.extend_from_slice(&u32::try_from(reserved).expect("r").to_le_bytes());
        f.extend_from_slice(&u32::try_from(z.len()).expect("n").to_le_bytes());
        f.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        f.resize(f.len().saturating_add(reserved), 0xaa);
        f.extend_from_slice(&z);
        if !tags.is_empty() {
            f.extend_from_slice(b"[TAG]");
            f.extend_from_slice(tags.as_bytes());
        }
        f
    }

    /// A PS-EXE with `text` at `t_addr`, `t_size` exactly `text.len()`,
    /// `s_addr`/`s_size` as given, and `region` at 0x71.
    fn psf_exe(text: &[u8], t_addr: u32, pc: u32, s_addr: u32, s_size: u32, region: u8) -> Vec<u8> {
        let mut e = build_ps_exe(text, t_addr, pc, 0x8003_0000, s_addr).expect("build");
        e.truncate(PS_EXE_HEADER_SIZE.saturating_add(text.len()));
        let mut put = |off: usize, v: &[u8]| {
            e.get_mut(off..off.saturating_add(v.len()))
                .expect("hdr")
                .copy_from_slice(v);
        };
        put(0x1c, &u32::try_from(text.len()).expect("len").to_le_bytes());
        put(0x34, &s_size.to_le_bytes());
        put(0x71, &[region]);
        e
    }

    fn write(dir: &Path, name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::write(&p, data).expect("write");
        p
    }

    #[test]
    fn psf_single_file() {
        let dir = tempfile::tempdir().expect("tmp");
        let exe = psf_exe(
            &[1, 2, 3, 4, 5],
            0x8001_0000,
            0x8001_0004,
            0x801f_0000,
            0x100,
            b'E',
        );
        let p = write(dir.path(), "a.psf", &build_psf(&exe, 7, "title=x\n"));
        let psf = load_psf(&p).expect("psf");
        // sp is s_addr alone; t_size bytes exactly, no padding.
        assert_eq!(
            (psf.image.pc, psf.image.gp, psf.image.sp),
            (0x8001_0004, 0x8003_0000, 0x801f_0000)
        );
        assert_eq!(
            psf.image.segments,
            vec![Segment {
                addr: 0x8001_0000,
                data: vec![1, 2, 3, 4, 5]
            }]
        );
        assert_eq!(psf.region, Some(Region::Pal));
        assert!(psf.warnings.is_empty());
        assert_eq!(load(&p).expect("load"), psf.image);
        assert!(matches!(
            parse(&build_psf(&exe, 0, "")),
            Err(ExeError::Psf(_))
        ));

        // s_addr 0: default stack, and no tags at all is fine.
        let exe = psf_exe(&[1], 0x8001_0000, 0x8001_0000, 0, 0x100, 0);
        let p = write(dir.path(), "b.psf", &build_psf(&exe, 0, ""));
        let psf = load_psf(&p).expect("psf");
        assert_eq!(psf.image.sp, DEFAULT_STACK);
        assert_eq!(psf.region, None);
    }

    #[test]
    fn minipsf_takes_pc_and_sp_from_its_lib_and_overlays_it() {
        let dir = tempfile::tempdir().expect("tmp");
        let lib = psf_exe(&[0x11; 16], 0x8001_0000, 0x8001_0008, 0x801f_f000, 0, b'J');
        write(
            dir.path(),
            "libs/drv.psflib",
            &build_psf(&lib, 0, "_lib2=../extra.psflib\n"),
        );
        let extra = psf_exe(&[0x33; 2], 0x8004_0000, 0x8004_0000, 0x8010_0000, 0, 0);
        write(dir.path(), "extra.psflib", &build_psf(&extra, 0, ""));
        // The minipsf's header pc/sp are placeholders and must lose.
        let mini = psf_exe(&[0x22; 4], 0x8001_0004, 0x8001_0000, 0x8000_1000, 0, b'E');
        let p = write(
            dir.path(),
            "song.minipsf",
            &build_psf(&mini, 0, "_lib=libs/drv.psflib\r\nrefresh=60\n"),
        );
        let psf = load_psf(&p).expect("psf");
        assert_eq!((psf.image.pc, psf.image.sp), (0x8001_0008, 0x801f_f000));
        let order: Vec<(u32, usize)> = psf
            .image
            .segments
            .iter()
            .map(|s| (s.addr, s.data.len()))
            .collect();
        // lib, then its _lib2 (resolved from libs/), then the minipsf.
        assert_eq!(
            order,
            vec![(0x8001_0000, 16), (0x8004_0000, 2), (0x8001_0004, 4)]
        );
        // refresh=60 first, then each exe's region byte: J, (none), E.
        assert_eq!(psf.region, Some(Region::Pal));
        assert!(psf.warnings.is_empty(), "{:?}", psf.warnings);
    }

    #[test]
    fn numbered_libs_load_after_in_order_until_a_gap() {
        let dir = tempfile::tempdir().expect("tmp");
        for (n, addr) in [(2u32, 0x8002_0000u32), (3, 0x8003_0000), (5, 0x8005_0000)] {
            let e = psf_exe(&[0x55], addr, addr, addr, 0, 0);
            write(dir.path(), &format!("l{n}.psflib"), &build_psf(&e, 0, ""));
        }
        let top = psf_exe(&[0x66], 0x8001_0000, 0x8001_0000, 0, 0, 0);
        let p = write(
            dir.path(),
            "t.minipsf",
            &build_psf(
                &top,
                0,
                "_lib3=l3.psflib\n_lib2=l2.psflib\n_lib5=l5.psflib\n",
            ),
        );
        let psf = load_psf(&p).expect("psf");
        let addrs: Vec<u32> = psf.image.segments.iter().map(|s| s.addr).collect();
        assert_eq!(addrs, vec![0x8001_0000, 0x8002_0000, 0x8003_0000]);
        assert_eq!((psf.image.pc, psf.image.sp), (0x8001_0000, DEFAULT_STACK));
    }

    #[test]
    fn missing_or_bad_lib_is_skipped_and_the_minipsf_exe_is_first() {
        let dir = tempfile::tempdir().expect("tmp");
        write(dir.path(), "junk.psflib", b"not a psf");
        let mini = psf_exe(&[1], 0x8001_0000, 0x8001_0000, 0x801f_0000, 0, 0);
        let p = write(
            dir.path(),
            "m.minipsf",
            &build_psf(&mini, 0, "_lib=gone.psflib\n_lib2=junk.psflib\n"),
        );
        let psf = load_psf(&p).expect("psf");
        assert_eq!((psf.image.pc, psf.image.sp), (0x8001_0000, 0x801f_0000));
        assert_eq!(psf.warnings.len(), 2, "{:?}", psf.warnings);
    }

    #[test]
    fn lib_chain_stops_at_depth_ten_and_top_refresh_wins() {
        let dir = tempfile::tempdir().expect("tmp");
        // A lib that names itself: Redux loads it until depth 10.
        let e = psf_exe(&[7], 0x8001_0000, 0x8001_0000, 0, 0, 0);
        write(
            dir.path(),
            "self.psflib",
            &build_psf(&e, 0, "_lib=self.psflib\nrefresh=60\n"),
        );
        let top = psf_exe(&[8], 0x8002_0000, 0x8002_0000, 0, 0, 0);
        let p = write(
            dir.path(),
            "top.minipsf",
            &build_psf(&top, 0, "refresh=50\n_lib=self.psflib\n"),
        );
        let psf = load_psf(&p).expect("psf");
        // depth 0 is top.minipsf, depths 1..=9 the lib: 9 lib loads + top.
        assert_eq!(psf.image.segments.len(), 10);
        assert_eq!(psf.image.pc, 0x8001_0000);
        assert_eq!(psf.region, Some(Region::Pal));
        assert_eq!(psf.warnings.len(), 1);
    }

    #[test]
    fn psf_tag_parsing_and_errors() {
        let tags = psf_tags(b"[TAG]a=1\r\nb= x = y \n\nnoequals\na=2\n_LIB=z");
        assert_eq!(tags.get("a").map(String::as_str), Some("2"));
        assert_eq!(tags.get("b").map(String::as_str), Some(" x = y "));
        assert_eq!(tags.get("_LIB").map(String::as_str), Some("z"));
        assert!(!tags.contains_key("_lib"));
        assert_eq!(tags.len(), 3);
        assert!(psf_tags(b"[tag]a=1").is_empty());

        let dir = tempfile::tempdir().expect("tmp");
        let mut bad = build_psf(&[0; 8], 0, "");
        bad.truncate(bad.len() - 1);
        let p = write(dir.path(), "trunc.psf", &bad);
        assert!(matches!(load_psf(&p), Err(ExeError::Truncated(_))));
        let mut bad = build_psf(&psf_exe(&[1], 0x8001_0000, 0x8001_0000, 0, 0, 0), 0, "");
        if let Some(b) = bad.get_mut(20) {
            *b ^= 0xff;
        }
        let p = write(dir.path(), "corrupt.psf", &bad);
        assert!(load_psf(&p).is_err());
        // Not a PS-EXE inside: nothing loads, so there is no entry point.
        let p = write(dir.path(), "empty.psf", &build_psf(b"hello", 0, ""));
        assert!(matches!(load_psf(&p), Err(ExeError::Psf(_))));
    }
}
