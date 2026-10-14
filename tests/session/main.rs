//! Session behaviour against the simulated monitor.
#![cfg(test)]

// The interpreter and debug unit serve tests/gdb.
#[allow(dead_code)]
mod sim;

mod crash;

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use psxmon::exe;
use psxmon::pcdrv::{PcdrvServer, Quota};
use psxmon::proto::*;
use psxmon::session::{LoadOptions, Session, deadline_after};
use psxmon::{MemTransport, Transport};
use sim::*;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

const BIOS: u32 = 0xbf38df5e;

async fn attach(
    cfg: SimConfig,
    program: Box<dyn Program>,
) -> (Session<MemTransport>, Arc<Mutex<SimStats>>) {
    let (host, stats) = sim::start(cfg, program);
    let mut s = Session::new(host);
    assert!(
        s.ping(Duration::from_secs(2), &[]).await.expect("ping"),
        "no PONG"
    );
    assert_eq!(s.version, Some(PROTO_VER));
    (s, stats)
}

fn lock(stats: &Arc<Mutex<SimStats>>) -> MutexGuard<'_, SimStats> {
    stats.lock().expect("sim stats lock")
}

fn len32(data: &[u8]) -> u32 {
    u32::try_from(data.len()).expect("test data fits u32")
}

/// Code-like bytes that compress but not trivially.
fn program_text(len: usize) -> Vec<u8> {
    let mut x: u32 = 7;
    (0..len)
        .map(|i| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let [_, _, _, noise] = x.to_le_bytes();
            let [low, ..] = (i % 16).to_le_bytes();
            if (i / 512) % 3 == 0 {
                0
            } else if (i / 64) % 2 == 0 {
                low
            } else {
                noise
            }
        })
        .collect()
}

async fn run_until_stop(
    s: &mut Session<MemTransport>,
    secs: u64,
    pcdrv: Option<&mut PcdrvServer>,
) -> psxmon::RunResult {
    s.run_until_stop(deadline_after(Duration::from_secs(secs)), pcdrv)
        .await
        .expect("run")
}

async fn load_run_exit(lz4: bool) {
    let text = program_text(100_000);
    let file = exe::build_ps_exe(&text, 0x8001_0000, 0x8001_0000, 0x8009_0000, 0x801f_0000)
        .expect("build PS-EXE");
    let img = exe::parse(&file).expect("parse PS-EXE");
    let seg = img.segments.first().expect("one segment").clone();
    let exit_at = img.pc.checked_add(0x100).expect("small");
    let prog = CheckAndExit {
        addr: seg.addr,
        expect: seg.data.clone(),
        pc: img.pc,
        gp: img.gp,
        sp: img.sp,
        code: 42,
        exit_at,
        started: false,
    };
    let (mut s, stats) = attach(SimConfig::default(), Box::new(prog)).await;
    assert_eq!(s.caps, CAP_LZ4);
    assert_eq!(s.bios, Some(BIOS));
    let opts = LoadOptions {
        lz4,
        ..Default::default()
    };
    let st = s.load(seg.addr, &seg.data, &opts).await.expect("load");
    assert_eq!(st.lz4_bytes.is_some(), lz4);
    s.run(img.pc, img.gp, img.sp).await.expect("RUN");
    let r = run_until_stop(&mut s, 5, None).await;
    assert_eq!(r.exit_code, Some(42));
    let stop = r.stop.expect("stopped");
    assert_eq!(stop.reason, STOP_EXIT);
    assert_eq!(stop.epc, exit_at);
    assert_eq!(s.take_text(), b"target: hello\n");
    let st = lock(&stats);
    if lz4 {
        assert!(st.lz4_frames >= 2, "lz4 frames {}", st.lz4_frames);
        assert_eq!(st.plain_load_frames, 0);
        assert!(
            st.max_match > 0 && st.max_match <= 128,
            "max match {}",
            st.max_match
        );
    } else {
        assert_eq!(st.lz4_frames, 0);
        assert_eq!(st.plain_load_frames, seg.data.len().div_ceil(8192));
    }
    assert!(st.errors_sent.is_empty(), "{:?}", st.errors_sent);
}

#[tokio::test]
async fn load_run_exit_plain() {
    load_run_exit(false).await;
}

#[tokio::test]
async fn load_run_exit_lz4() {
    load_run_exit(true).await;
}

#[tokio::test]
async fn lz4_falls_back_to_plain_without_cap() {
    let cfg = SimConfig {
        caps: 0,
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
    assert_eq!(s.caps, 0);
    let st = s
        .load(0x8001_0000, &[0u8; 20000], &LoadOptions::default())
        .await
        .expect("load");
    assert_eq!(st.lz4_bytes, None);
    assert_eq!(lock(&stats).plain_load_frames, 3);
}

/// A monitor that answers the first LZ4 slice with EBADCMD (a System 573
/// build above 518400 baud) gets the whole load again as plain LOAD, and
/// plain LOAD for the rest of the session.
#[tokio::test]
async fn lz4_refused_on_first_slice_reloads_raw() {
    let text = program_text(100_000);
    let addr = 0x8001_0000;
    let exit_at = addr + 0x100;
    let prog = CheckAndExit {
        addr,
        expect: text.clone(),
        pc: addr,
        gp: 0,
        sp: 0x801f_0000,
        code: 42,
        exit_at,
        started: false,
    };
    let cfg = SimConfig {
        caps: CAP_LZ4 | CAP_PIPELINE,
        refuse_lz4_from: Some(0),
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(prog)).await;
    let st = s
        .load(addr, &text, &LoadOptions::default())
        .await
        .expect("load falls back to raw");
    assert_eq!(st.lz4_bytes, None);
    assert!(s.lz4_refused);
    let (refused, plain) = {
        let st = lock(&stats);
        assert_eq!(st.lz4_frames, 0);
        assert!(st.lz4_refused >= 1, "refused {}", st.lz4_refused);
        assert!(
            st.errors_sent.iter().all(|&e| e == E_BADCMD),
            "{:?}",
            st.errors_sent
        );
        assert_eq!(st.errors_sent.len(), st.lz4_refused);
        (st.lz4_refused, st.plain_load_frames)
    };
    assert_eq!(plain, text.len().div_ceil(8192));
    // The raw load wrote the data: the program finds it and exits 42.
    s.run(addr, 0, 0x801f_0000).await.expect("RUN");
    let r = run_until_stop(&mut s, 5, None).await;
    assert_eq!(r.exit_code, Some(42));
    // The next load goes raw at once.
    let st = s
        .load(addr, &text, &LoadOptions::default())
        .await
        .expect("second load");
    assert_eq!(st.lz4_bytes, None);
    let st = lock(&stats);
    assert_eq!(st.lz4_refused, refused);
    assert_eq!(st.plain_load_frames, plain * 2);
}

/// EBADCMD for a later LZ4 slice is an error: part of the load is already
/// written, so it is not retried raw.
#[tokio::test]
async fn lz4_refused_mid_stream_is_an_error() {
    let cfg = SimConfig {
        refuse_lz4_from: Some(1),
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
    let e = s
        .load(0x8001_0000, &program_text(100_000), &LoadOptions::default())
        .await
        .expect_err("mid-stream refusal fails the load");
    assert!(e.to_string().contains("EBADCMD"), "{e}");
    assert!(!e.to_string().contains("offset 0"), "{e}");
    assert!(!s.lz4_refused);
    let st = lock(&stats);
    assert_eq!((st.lz4_frames, st.lz4_refused), (1, 1));
    assert_eq!(st.plain_load_frames, 0);
}

/// Run a load with a progress callback and return what it reported.
async fn load_progress(caps: u16, data: &[u8]) -> (Vec<(usize, usize)>, Option<usize>) {
    let cfg = SimConfig {
        caps,
        ..Default::default()
    };
    let (mut s, _stats) = attach(cfg, Box::new(Hang)).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    s.progress = Some(Box::new(move |sent, total| {
        log.lock().expect("progress log").push((sent, total));
    }));
    let st = s
        .load(0x8001_0000, data, &LoadOptions::default())
        .await
        .expect("load");
    let v = seen.lock().expect("progress log").clone();
    (v, st.lz4_bytes)
}

#[tokio::test]
async fn progress_counts_plain_chunks_to_the_total() {
    let (v, lz4) = load_progress(0, &program_text(20000)).await;
    assert_eq!(lz4, None);
    assert_eq!(v, [(8192, 20000), (16384, 20000), (20000, 20000)]);
}

#[tokio::test]
async fn progress_counts_lz4_bytes_on_the_wire() {
    let (v, lz4) = load_progress(CAP_LZ4, &program_text(100_000)).await;
    let comp = lz4.expect("sent as LZ4");
    assert!(v.len() > 1, "{v:?}");
    assert!(v.iter().all(|&(_, total)| total == comp), "{v:?}");
    assert!(v.windows(2).all(|w| w[0].0 < w[1].0), "{v:?}");
    assert_eq!(v.last(), Some(&(comp, comp)));
}

#[tokio::test]
async fn progress_is_silent_for_write_mem() {
    let cfg = SimConfig::default();
    let (mut s, _stats) = attach(cfg, Box::new(Hang)).await;
    let calls = Arc::new(Mutex::new(0u32));
    let log = Arc::clone(&calls);
    s.progress = Some(Box::new(move |_, _| {
        *log.lock().expect("calls") += 1;
    }));
    s.write_mem(0x8001_0000, &[1u8; 20000])
        .await
        .expect("write");
    assert_eq!(*calls.lock().expect("calls"), 0);
}

async fn farmjob(lz4: bool, size: usize) {
    let dir = tempfile::tempdir().expect("tempdir");
    let input: Vec<u8> = b"abcdefghijklmnopqrstuvwxyz\n"
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect();
    std::fs::write(dir.path().join("IN.TXT"), &input).expect("write IN.TXT");
    let (mut s, _stats) = attach(SimConfig::default(), Box::new(Farmjob::new())).await;
    // A stand-in body so the load path runs too.
    let body = program_text(30_000);
    let opts = LoadOptions {
        lz4,
        ..Default::default()
    };
    s.load(0x8001_0000, &body, &opts).await.expect("load");
    let mut server = PcdrvServer::new(dir.path(), Quota::default()).expect("PCDRV server");
    s.run(0x8001_0000, 0, 0x801f_fff0).await.expect("RUN");
    let r = run_until_stop(&mut s, 10, Some(&mut server)).await;
    assert_eq!(r.exit_code, Some(len32(&input)));
    let out = std::fs::read(dir.path().join("OUT.TXT")).expect("OUT.TXT written");
    assert_eq!(out, input.to_ascii_uppercase());
    let text = String::from_utf8(s.take_text()).expect("ASCII console text");
    assert_eq!(text, format!("farmjob: start\nfarmjob: {size} bytes\n"));
}

#[tokio::test]
async fn pcdrv_farmjob_20000_plain() {
    farmjob(false, 20000).await;
}

#[tokio::test]
async fn pcdrv_farmjob_20000_lz4() {
    farmjob(true, 20000).await;
}

#[tokio::test]
async fn pcdrv_farmjob_small_and_exact_chunk() {
    farmjob(true, 19).await;
    farmjob(true, 8192).await;
}

#[tokio::test]
async fn run_features_word_only_when_asked() {
    for features in [None, Some(0), Some(FEAT_WATCHDOG)] {
        let (mut s, stats) = attach(SimConfig::default(), Box::new(Farmjob::new())).await;
        s.run_with_features(0x8001_0000, 0, 0x801f_fff0, features)
            .await
            .expect("RUN");
        let mut want = vec![0x0000, 0x8001, 0x0000, 0x0000, 0xfff0, 0x801f];
        want.extend(features);
        assert_eq!(lock(&stats).runs, vec![want]);
    }
}

#[tokio::test]
async fn pcdrv_without_server_fails_calls() {
    let (mut s, _) = attach(SimConfig::default(), Box::new(Farmjob::new())).await;
    s.run(0x8001_0000, 0, 0x801f_fff0).await.expect("RUN");
    let r = run_until_stop(&mut s, 5, None).await;
    assert_eq!(r.exit_code, Some(0xbad));
}

#[tokio::test]
async fn pcdrv_jail_refuses_escape() {
    let outer = tempfile::tempdir().expect("tempdir");
    let base = outer.path().join("jail");
    std::fs::create_dir(&base).expect("jail dir");
    let probe = JailProbe {
        name: b"..\\escaped.txt",
        done: false,
    };
    let (mut s, _) = attach(SimConfig::default(), Box::new(probe)).await;
    let mut server = PcdrvServer::new(&base, Quota::default()).expect("PCDRV server");
    s.run(0x8001_0000, 0, 0x801f_fff0).await.expect("RUN");
    let r = run_until_stop(&mut s, 5, Some(&mut server)).await;
    assert_eq!(r.exit_code, Some(u32::MAX));
    assert!(!outer.path().join("escaped.txt").exists());
}

#[tokio::test]
async fn legacy_exit_reason_maps_to_exit_code() {
    let cfg = SimConfig {
        legacy_exit: true,
        ..Default::default()
    };
    let prog = CheckAndExit {
        addr: 0x8001_0000,
        expect: vec![],
        pc: 0x8001_0000,
        gp: 0,
        sp: 0x801f_fff0,
        code: 7,
        exit_at: 0x8001_0100,
        started: false,
    };
    let (mut s, _) = attach(cfg, Box::new(prog)).await;
    s.run(0x8001_0000, 0, 0x801f_fff0).await.expect("RUN");
    let r = run_until_stop(&mut s, 5, None).await;
    assert_eq!(r.exit_code, Some(7));
    let stop = r.stop.expect("stopped");
    assert_eq!(stop.reason, STOP_EXIT);
    assert_eq!(stop.a, 7);
}

#[tokio::test]
async fn set_baud_short_pong_keeps_caps_and_bios() {
    let (mut s, stats) = attach(SimConfig::default(), Box::new(Hang)).await;
    assert_eq!((s.caps, s.bios), (CAP_LZ4, Some(BIOS)));
    let rate = s.negotiate_rate(9).await.expect("SET_BAUD");
    assert_eq!(rate, 230400);
    assert_eq!(s.transport().baud_rate(), 230400);
    assert_eq!(lock(&stats).rate, 230400);
    // The two window PONGs carried only [proto_ver].
    assert_eq!((s.caps, s.bios), (CAP_LZ4, Some(BIOS)));
    assert!(s.ping(Duration::from_secs(1), &[]).await.expect("ping"));
    let data = program_text(20000);
    s.write_mem(0x8002_0000, &data).await.expect("WRITE_MEM");
    assert_eq!(
        s.read_mem(0x8002_0000, len32(&data))
            .await
            .expect("READ_MEM"),
        data
    );
}

#[tokio::test]
async fn set_baud_falls_back_when_new_rate_is_silent() {
    let cfg = SimConfig {
        unreachable_rate: true,
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
    let rate = s.negotiate_rate(9).await.expect("SET_BAUD");
    assert_eq!(rate, 115200);
    assert_eq!(s.transport().baud_rate(), 115200);
    assert_eq!(lock(&stats).rate, 115200);
    assert_eq!((s.caps, s.bios), (CAP_LZ4, Some(BIOS)));
}

#[tokio::test]
async fn attach_finds_a_monitor_left_at_230400() {
    // An earlier run's SET_BAUD left the monitor at 230400; the host asks
    // for 115200 first.
    let cfg = SimConfig {
        start_rate: Some(230400),
        ..Default::default()
    };
    let (host, _stats) = sim::start(cfg, Box::new(Hang));
    let mut s = Session::new(host);
    let rates = [115200, 230400];
    let t0 = Instant::now();
    let found = s
        .attach_at(
            &rates,
            Duration::from_millis(600),
            Duration::from_millis(600),
        )
        .await
        .expect("attach");
    assert_eq!(found, Some(230400));
    assert!(
        t0.elapsed() >= Duration::from_millis(600),
        "115200 was tried first"
    );
    assert_eq!(s.transport().baud_rate(), 230400);
    assert_eq!((s.caps, s.bios), (CAP_LZ4, Some(BIOS)));
    // And the link works at that rate.
    let data = program_text(10000);
    s.write_mem(0x8002_0000, &data).await.expect("WRITE_MEM");
    assert_eq!(
        s.read_mem(0x8002_0000, len32(&data))
            .await
            .expect("READ_MEM"),
        data
    );
    // Nothing answers at rates the monitor is not on.
    let (host, _) = sim::start(
        SimConfig {
            start_rate: Some(57600),
            ..Default::default()
        },
        Box::new(Hang),
    );
    let mut s = Session::new(host);
    let none = s
        .attach_at(
            &rates,
            Duration::from_millis(300),
            Duration::from_millis(300),
        )
        .await;
    assert_eq!(none.expect("attach runs"), None);
}

#[tokio::test]
async fn memory_regs_and_errors() {
    let (mut s, stats) = attach(SimConfig::default(), Box::new(Hang)).await;
    // Across several DATA frames, an odd length, and len 0.
    let data = program_text(3 * 8192 + 5);
    s.write_mem(0x8003_0001, &data).await.expect("WRITE_MEM");
    assert_eq!(
        s.read_mem(0x8003_0001, len32(&data))
            .await
            .expect("READ_MEM"),
        data
    );
    assert_eq!(
        s.read_mem(0x8003_0001, 0).await.expect("READ_MEM 0"),
        Vec::<u8>::new()
    );
    // No halted context yet.
    assert!(
        s.get_regs()
            .await
            .expect("GET_REGS")
            .iter()
            .all(|&r| r == 0)
    );
    let e = s
        .set_reg(2, 1)
        .await
        .expect_err("SET_REG needs a halted context");
    assert!(e.to_string().contains("EBADSTATE"), "{e}");
    let e = s.cont().await.expect_err("CONT needs a halted context");
    assert!(e.to_string().contains("EBADSTATE"), "{e}");
    // A corrupted command frame is answered with ECKSUM.
    let mut bad = psxmon::frame::encode_frame(GET_REGS, &[]).expect("frame");
    if let Some(last) = bad.last_mut() {
        *last ^= 0x40;
    }
    s.transport().write_all(&bad).await.expect("write");
    let deadline = deadline_after(Duration::from_secs(1));
    let f = s
        .wait_frame(&[ERROR], deadline)
        .await
        .expect("wait")
        .expect("ERROR frame");
    assert_eq!(f.words, vec![E_CKSUM]);
    // STEP is reserved.
    s.send(STEP, &[]).await.expect("send");
    let deadline = deadline_after(Duration::from_secs(1));
    let f = s
        .wait_frame(&[ERROR], deadline)
        .await
        .expect("wait")
        .expect("ERROR frame");
    assert_eq!(f.words, vec![E_BADCMD]);
    assert_eq!(
        lock(&stats).errors_sent,
        vec![E_BADSTATE, E_BADSTATE, E_CKSUM, E_BADCMD]
    );
}

#[tokio::test]
async fn timeout_when_target_never_stops() {
    let (mut s, _) = attach(SimConfig::default(), Box::new(Hang)).await;
    s.run(0x8001_0000, 0, 0x801f_fff0).await.expect("RUN");
    let t0 = Instant::now();
    let deadline = deadline_after(Duration::from_millis(300));
    let r = s.run_until_stop(deadline, None).await.expect("run");
    assert_eq!(r.stop, None);
    assert_eq!(r.exit_code, None);
    assert!(t0.elapsed() >= Duration::from_millis(300));
}

#[tokio::test]
async fn elf_and_cpe_images_load_and_run() {
    // A CPE whose load chunks are contiguous goes out as one segment.
    let text = program_text(5000);
    let (first, second) = text.split_at(3000);
    let mut cpe = b"CPE\x01\x08\x00\x03\x90\x00".to_vec();
    cpe.extend(0x8001_0000u32.to_le_bytes());
    for (addr, part) in [(0x8001_0000u32, first), (0x8001_0bb8, second)] {
        cpe.push(0x01);
        cpe.extend(addr.to_le_bytes());
        cpe.extend(len32(part).to_le_bytes());
        cpe.extend(part);
    }
    cpe.push(0x00);
    let img = exe::parse(&cpe).expect("parse CPE");
    assert_eq!(img.segments.len(), 1);
    let prog = CheckAndExit {
        addr: 0x8001_0000,
        expect: text.clone(),
        pc: 0x8001_0000,
        gp: 0,
        sp: exe::DEFAULT_STACK_ELF_CPE,
        code: 5,
        exit_at: 0x8001_2000,
        started: false,
    };
    let (mut s, _) = attach(SimConfig::default(), Box::new(prog)).await;
    for seg in &img.segments {
        s.load(seg.addr, &seg.data, &LoadOptions::default())
            .await
            .expect("load");
    }
    s.run(img.pc, img.gp, img.sp).await.expect("RUN");
    assert_eq!(run_until_stop(&mut s, 5, None).await.exit_code, Some(5));
}

/// The RAM probe on 2, 4 and 8 MiB, with the words 2, 4 and 6 MiB above
/// the sentinel made equal to it by chance, and the sentinel restored.
#[tokio::test]
async fn ram_probe_finds_installed_size() {
    const MIB: usize = 1 << 20;
    for size in [2 * MIB, 4 * MIB, 8 * MIB] {
        for chance in [false, true] {
            let cfg = SimConfig {
                ram_size: size,
                ..Default::default()
            };
            let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
            let v: u32 = 0x1234_5678;
            s.write_mem(0xa000_0000, &v.to_le_bytes())
                .await
                .expect("seed");
            if chance {
                for off in [0x20_0000u32, 0x40_0000, 0x60_0000] {
                    s.write_mem(0xa000_0000 + off, &v.to_le_bytes())
                        .await
                        .expect("seed mirror");
                }
            }
            let mark = lock(&stats).cmds.len();
            let got = s.probe_ram().await.expect("probe");
            assert_eq!(
                got,
                u32::try_from(size).expect("fits"),
                "{size} chance={chance}"
            );
            let back = s.read_mem(0xa000_0000, 4).await.expect("read back");
            assert_eq!(back, v.to_le_bytes(), "sentinel restored");
            // Once per session.
            let n = lock(&stats).cmds.len();
            assert_eq!(s.probe_ram().await.expect("again"), got);
            assert_eq!(lock(&stats).cmds.len(), n, "no second probe");
            let writes = lock(&stats).cmds[mark..n]
                .iter()
                .filter(|&&c| c == WRITE_MEM)
                .count();
            // 8 MiB with nothing equal above the sentinel needs no flip.
            let flips = if size == 8 * MIB && !chance { 0 } else { 2 };
            assert_eq!(writes, flips, "{size} chance={chance}");
        }
    }
}

/// A first DRAM bank smaller than the window (DRAM_CTRL 0x888): nothing
/// mirrors, and nothing is probed above it.
#[tokio::test]
async fn ram_probe_skips_a_small_bank() {
    let cfg = SimConfig {
        ram_size_reg: 0x888,
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
    let mark = lock(&stats).cmds.len();
    assert_eq!(s.probe_ram().await.expect("probe"), 8 << 20);
    assert_eq!(lock(&stats).cmds[mark..], [READ_MEM]);
}

#[tokio::test]
async fn progress_counts_pipelined_chunks_per_ack() {
    let (v, lz4) = load_progress(CAP_PIPELINE, &program_text(40000)).await;
    assert_eq!(lz4, None);
    assert_eq!(
        v,
        [
            (8192, 40000),
            (16384, 40000),
            (24576, 40000),
            (32768, 40000),
            (40000, 40000)
        ]
    );
    let (v, lz4) = load_progress(CAP_LZ4 | CAP_PIPELINE, &program_text(200_000)).await;
    let comp = lz4.expect("sent as LZ4");
    assert!(v.len() > PIPELINE_DEPTH, "{v:?}");
    assert!(v.iter().all(|&(_, total)| total == comp), "{v:?}");
    assert!(v.windows(2).all(|w| w[0].0 < w[1].0), "{v:?}");
    assert_eq!(v.last(), Some(&(comp, comp)));
}

/// Frames in flight at once with CAP_PIPELINE.
const PIPELINE_DEPTH: usize = 4;

/// A hand-driven monitor on the device end of `dev`: PONGs every PING with
/// CAP_PIPELINE, and answers every other frame with what `reply` returns for
/// its type and how many of that type came before (None: no answer).
fn scripted<F>(mut dev: tokio::io::DuplexStream, reply: F) -> Arc<Mutex<Vec<u16>>>
where
    F: Fn(u16, usize) -> Option<(u16, Vec<u16>)> + Send + 'static,
{
    use psxmon::frame::{Event, Parser, encode_frame, u32_words};
    use tokio::io::AsyncReadExt;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut parser = Parser::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = match dev.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            parser.feed(&buf[..n]);
            while let Some(ev) = parser.next_event() {
                let Event::Frame(f) = ev else { continue };
                let out = if f.ty == PING {
                    let mut p = vec![PROTO_VER, CAP_PIPELINE];
                    p.extend(u32_words(&[BIOS]));
                    Some((PONG, p))
                } else {
                    let nth = {
                        let mut s = log.lock().expect("script log");
                        let nth = s.iter().filter(|&&t| t == f.ty).count();
                        s.push(f.ty);
                        nth
                    };
                    reply(f.ty, nth)
                };
                if let Some((ty, words)) = out {
                    let wire = encode_frame(ty, &words).expect("frame");
                    if dev.write_all(&wire).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    seen
}

async fn attach_scripted<F>(reply: F) -> (Session<MemTransport>, Arc<Mutex<Vec<u16>>>)
where
    F: Fn(u16, usize) -> Option<(u16, Vec<u16>)> + Send + 'static,
{
    let (host, dev, _rate) = MemTransport::pair(115200);
    let seen = scripted(dev, reply);
    let mut s = Session::new(host);
    assert!(
        s.ping(Duration::from_secs(2), &[]).await.expect("ping"),
        "no PONG"
    );
    assert_eq!(s.caps, CAP_PIPELINE);
    (s, seen)
}

/// The first WRITE_MEM of a pipelined write fails while three more are in
/// flight; their ACKs must not answer the SET_REG that follows (as in a
/// PCDRV read whose write_mem fails, then serve_pcdrv's set_reg).
#[tokio::test]
async fn failed_pipelined_write_leaves_no_stale_ack() {
    let (mut s, seen) = attach_scripted(|ty, nth| match ty {
        WRITE_MEM if nth == 0 => Some((ERROR, vec![E_BADADDR])),
        WRITE_MEM => Some((ACK, vec![])),
        _ => Some((ERROR, vec![E_BADSTATE])),
    })
    .await;
    let e = s
        .write_mem(0x8001_0000, &[0u8; 4 * 8192])
        .await
        .expect_err("first chunk fails");
    assert!(e.to_string().contains("WRITE_MEM at 0x80010000"), "{e}");
    let e = s
        .set_reg(2, 1)
        .await
        .expect_err("SET_REG is answered with ERROR, not a stale ACK");
    assert!(e.to_string().contains("EBADSTATE"), "{e}");
    assert_eq!(
        *seen.lock().expect("script log"),
        [WRITE_MEM, WRITE_MEM, WRITE_MEM, WRITE_MEM, SET_REG]
    );
}

/// When the replies of the frames still in flight cannot all be read back,
/// the session refuses further requests until a PING resynchronises it.
#[tokio::test]
async fn unaccounted_pipelined_replies_poison_the_session() {
    let (mut s, seen) = attach_scripted(|ty, nth| match ty {
        WRITE_MEM if nth == 0 => Some((ERROR, vec![E_BADADDR])),
        WRITE_MEM if nth == 1 => Some((ACK, vec![])),
        // The last two replies are lost.
        WRITE_MEM => None,
        _ => Some((ACK, vec![])),
    })
    .await;
    s.write_mem(0x8001_0000, &[0u8; 4 * 8192])
        .await
        .expect_err("first chunk fails");
    let e = s.set_reg(2, 1).await.expect_err("poisoned");
    assert!(e.to_string().contains("out of step"), "{e}");
    assert!(!seen.lock().expect("script log").contains(&SET_REG));
    assert!(s.ping(Duration::from_secs(2), &[]).await.expect("ping"));
    s.set_reg(2, 1).await.expect("SET_REG after resync");
}

/// Bytes lost inside a frame: the header claims STREAM_MAX_LEN words and
/// only four follow, so the monitor reads what the host sends next as that
/// frame's payload. One PING per slot would take minutes to get through;
/// the zeros sent after the first miss end the frame at once.
#[tokio::test]
async fn ping_resyncs_after_a_frame_cut_short() {
    let (mut s, stats) = attach(SimConfig::default(), Box::new(Hang)).await;
    let [len_lo, len_hi] = STREAM_MAX_LEN.to_le_bytes();
    let cut = [
        0x00, 0xaa, 0x55, 0x03, 0x00, len_lo, len_hi, // WRITE_MEM, LEN
        0x00, 0x00, 0x02, 0x80, 0x00, 0x20, 0x00, 0x00, // 0x80020000, 8 KiB
    ];
    s.transport().write_all(&cut).await.expect("write");
    assert!(
        s.ping(Duration::from_secs(3), &[]).await.expect("ping"),
        "no PONG after a frame cut short"
    );
    assert_eq!(lock(&stats).errors_sent, vec![E_CKSUM]);
    let data = program_text(300);
    s.write_mem(0x8002_0000, &data).await.expect("WRITE_MEM");
    assert_eq!(
        s.read_mem(0x8002_0000, len32(&data))
            .await
            .expect("READ_MEM"),
        data
    );
}

#[tokio::test]
async fn run_returns_after_the_ack_so_detach_can_exit() {
    // The --detach / --timeout 0 path calls `run` and exits without a
    // `run_until_stop`. `run` must return as soon as the RUN is acked, even
    // for a target that never stops.
    let (mut s, stats) = attach(SimConfig::default(), Box::new(Hang)).await;
    s.run(0x8001_0000, 0, 0x801f_fff0).await.expect("RUN acked");
    assert_eq!(
        lock(&stats).cmds.last(),
        Some(&RUN),
        "RUN was the last command"
    );
}

/// Run the psxmon binary's `run` against a sim behind a TCP port, with the
/// given extra arguments; the exit status, stderr, and whether it finished
/// within `secs`.
async fn cli_run(extra: &[&str], secs: u64) -> (Option<i32>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (host, _) = sim::start(SimConfig::default(), Box::new(Hang));
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("accept");
        let mut host = host;
        let _ = tokio::io::copy_bidirectional(&mut conn, &mut host).await;
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let exe_path = dir.path().join("hang.exe");
    let file =
        exe::build_ps_exe(&[0; 16], 0x8001_0000, 0x8001_0000, 0, 0x801f_0000).expect("PS-EXE");
    std::fs::write(&exe_path, file).expect("write PS-EXE");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_psxmon"));
    cmd.arg("run")
        .arg(&exe_path)
        .arg("--port")
        .arg(format!("tcp:127.0.0.1:{port}"))
        .args(extra)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn psxmon");
    let deadline = deadline_after(Duration::from_secs(secs));
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                use std::io::Read;
                let _ = e.read_to_string(&mut err);
            }
            return (status.code(), err);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return (None, String::new());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn cli_detach_exits_0_after_the_ack() {
    for args in [&["--detach"][..], &["--timeout", "0"][..]] {
        let (code, err) = cli_run(args, 20).await;
        assert_eq!(code, Some(0), "{args:?}: {err}");
        assert!(err.contains("detached"), "{args:?}: {err}");
    }
    // Control: without it, a target that never stops runs into --timeout.
    let (code, err) = cli_run(&["--timeout", "1"], 20).await;
    assert_eq!(code, Some(124), "{err}");
}

/// Every load ends in a line that stays on screen, without -v too, so a
/// user's report carries the measured rate.
#[tokio::test]
async fn cli_prints_a_load_summary_without_verbose() {
    // The PS-EXE's 16 bytes of code are padded to 2048.
    for (extra, lz4) in [
        (&["--detach"][..], true),
        (&["--detach", "--no-lz4"][..], false),
    ] {
        let (code, err) = cli_run(extra, 20).await;
        assert_eq!(code, Some(0), "{err}");
        let line = err
            .lines()
            .find(|l| l.starts_with("psxmon: loaded 2048 bytes"))
            .unwrap_or_else(|| panic!("{extra:?}: no summary in {err}"));
        assert!(
            line.contains(" ms: ") && line.contains("kB/s average") && line.contains("kB/s peak"),
            "{line}"
        );
        assert_eq!(line.contains("on the link with LZ4"), lz4, "{line}");
    }
}

/// Bytes on the wire of one full plain LOAD chunk, and of the PING that
/// `attach` sends first.
const LOAD_FRAME_BYTES: usize = 7 + 8 + 8192 + 4;
const PING_FRAME_BYTES: usize = 11;

/// One host byte lost inside the second of five pipelined LOAD chunks, as
/// on an FT232H cart: that chunk takes the next frame's first byte for its
/// checksum and fails ECKSUM, and the next chunk, missing its frame start,
/// gets no reply at all. psxmon resynchronises and resends from the failed
/// chunk on.
#[tokio::test]
async fn a_byte_lost_in_a_pipelined_load_is_resent() {
    let cfg = SimConfig {
        caps: CAP_PIPELINE,
        drop_host_bytes: vec![PING_FRAME_BYTES + LOAD_FRAME_BYTES + 3000],
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
    let data = program_text(4 * 8192 + 19);
    s.load_raw(0x8001_0000, &data).await.expect("LOAD resent");
    {
        let st = lock(&stats);
        assert_eq!(st.errors_sent, vec![E_CKSUM]);
        // 1 + the lost-and-failed pair + their resends + 3 after them.
        assert_eq!(st.plain_load_frames, 8, "{st:?}");
    }
    assert_eq!(
        s.read_mem(0x8001_0000, len32(&data))
            .await
            .expect("READ_MEM"),
        data
    );
}

/// The same loss in the last chunk: the monitor waits for one more byte
/// and never replies, so the resend follows the reply timeout.
#[tokio::test]
async fn a_byte_lost_in_the_last_chunk_is_resent() {
    let cfg = SimConfig {
        caps: CAP_PIPELINE,
        drop_host_bytes: vec![PING_FRAME_BYTES + 2 * LOAD_FRAME_BYTES + 5],
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
    let data = program_text(2 * 8192 + 19);
    s.load_raw(0x8001_0000, &data).await.expect("LOAD resent");
    assert_eq!(lock(&stats).errors_sent, vec![E_CKSUM]);
    assert_eq!(
        s.read_mem(0x8001_0000, len32(&data))
            .await
            .expect("READ_MEM"),
        data
    );
}

/// A byte lost inside an LZ4 slice: the monitor drops the stream, so the
/// whole block goes again from offset 0.
#[tokio::test]
async fn a_byte_lost_in_an_lz4_load_restarts_the_stream() {
    let cfg = SimConfig {
        caps: CAP_LZ4 | CAP_PIPELINE,
        drop_host_bytes: vec![PING_FRAME_BYTES + 8300],
        ..Default::default()
    };
    let (mut s, stats) = attach(cfg, Box::new(Hang)).await;
    let data = program_text(200_000);
    let st = s
        .load(0x8001_0000, &data, &LoadOptions::default())
        .await
        .expect("LZ4 LOAD resent");
    assert!(st.lz4_bytes.is_some(), "sent as LZ4");
    assert_eq!(lock(&stats).errors_sent.first(), Some(&E_CKSUM));
    assert_eq!(
        s.read_mem(0x8001_0000, len32(&data))
            .await
            .expect("READ_MEM"),
        data
    );
}

/// A link that damages every LOAD: the resends stop and the error stands.
#[tokio::test]
async fn resends_give_up_on_a_link_that_keeps_failing() {
    let (mut s, seen) = attach_scripted(|ty, _| match ty {
        LOAD => Some((ERROR, vec![E_CKSUM])),
        _ => Some((ACK, vec![])),
    })
    .await;
    let e = s
        .load_raw(0x8001_0000, &[0u8; 8192])
        .await
        .expect_err("keeps failing");
    assert!(e.to_string().contains("ECKSUM"), "{e}");
    let loads = seen
        .lock()
        .expect("script log")
        .iter()
        .filter(|&&t| t == LOAD)
        .count();
    assert_eq!(loads, 4, "the first try and three resends");
}
