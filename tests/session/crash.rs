//! Crash reports for programs that fault, run on the simulator's R3000.

use psxmon::crash::{self, Symbols};
use psxmon::exe::Symbol;

use super::*;

const ENTRY: u32 = 0x8001_0000;
const STACK: u32 = 0x801f_ff00;

fn words(code: &[u32]) -> Vec<u8> {
    code.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn main_symbol() -> Symbols {
    Symbols::new(vec![Symbol {
        name: "main".into(),
        addr: ENTRY,
        size: 0x100,
    }])
}

/// Run `code` at ENTRY until it faults; the stop and the report.
async fn fault_report(code: &[u32], stack: &[u32]) -> (psxmon::Stop, String) {
    let (mut s, _) = attach(SimConfig::default(), Box::new(Interp::default())).await;
    s.write_mem(ENTRY, &words(code))
        .await
        .expect("WRITE_MEM code");
    s.write_mem(STACK, &words(stack))
        .await
        .expect("WRITE_MEM stack");
    s.run(ENTRY, 0, STACK).await.expect("RUN");
    let r = run_until_stop(&mut s, 5, None).await;
    let stop = r.stop.expect("a stop");
    assert_eq!(stop.reason, STOP_FAULT, "{stop:?}");
    let report = crash::gather(&mut s, stop).await.report(&main_symbol());
    (stop, report)
}

fn has(report: &str, line: &str) {
    assert!(
        report.lines().any(|l| l.contains(line)),
        "no line with {line:?} in:\n{report}"
    );
}

// lui a0, 0x8010
const LUI_A0_8010: u32 = 0x3c04_8010;

#[tokio::test]
async fn adel_misaligned_load() {
    // lw t0, 1(a0)
    let (stop, r) = fault_report(&[LUI_A0_8010, 0x8c88_0001], &[]).await;
    assert_eq!((stop.a, stop.b, stop.epc), (4, 0x8010_0001, ENTRY + 4));
    has(&r, "cause:   AdEL (ExcCode 4): address error on a load");
    has(&r, "address: 0x80100001 (BadVaddr)");
    has(&r, "pc:      0x80010004 <main+0x4>  lw      t0,1(a0)");
    has(&r, "access:  4-byte load from 0x80100001");
    has(&r, "   a0 80100000");
    has(&r, "  bad 80100001");
    assert!(!r.contains("delay slot"), "{r}");
}

#[tokio::test]
async fn ades_misaligned_store() {
    // sh t0, 3(a0)
    let (stop, r) = fault_report(&[LUI_A0_8010, 0xa488_0003], &[]).await;
    assert_eq!((stop.a, stop.b), (5, 0x8010_0003));
    has(&r, "cause:   AdES (ExcCode 5)");
    has(&r, "address: 0x80100003 (BadVaddr)");
    has(&r, "sh      t0,3(a0)");
    has(&r, "access:  2-byte store to 0x80100003");
}

#[tokio::test]
async fn dbe_load_from_nothing() {
    // lui a0, 0x1fa0; lw t0, 16(a0)
    let (stop, r) = fault_report(&[0x3c04_1fa0, 0x8c88_0010], &[]).await;
    assert_eq!((stop.a, stop.b), (7, 0));
    has(&r, "cause:   DBE (ExcCode 7): bus error on a load or store");
    has(&r, "access:  4-byte load from 0x1fa00010");
    // BadVaddr is not reported for a bus error.
    assert!(!r.contains("BadVaddr"), "{r}");
}

#[tokio::test]
async fn ri_reserved_opcode() {
    let (stop, r) = fault_report(&[0, 0xfc00_0000], &[]).await;
    assert_eq!((stop.a, stop.epc), (10, ENTRY + 4));
    has(&r, "cause:   RI (ExcCode 10): reserved instruction");
    has(&r, "pc:      0x80010004 <main+0x4>  .word 0xfc000000");
}

#[tokio::test]
async fn ov_add_overflow() {
    // lui a0, 0x7fff; ori a0, a0, 0xffff; addi v0, a0, 1
    let (stop, r) = fault_report(&[0x3c04_7fff, 0x3484_ffff, 0x2082_0001], &[]).await;
    assert_eq!((stop.a, stop.epc), (12, ENTRY + 8));
    has(&r, "cause:   Ov (ExcCode 12): arithmetic overflow");
    has(&r, "addi    v0,a0,1");
    has(&r, "operands: a0=0x7fffffff");
    // The destination is left alone.
    has(&r, "v0 00000000");
}

#[tokio::test]
async fn fault_in_a_delay_slot_names_the_branch() {
    // lui a0, 0x8010; jal 0x80010100; lw t0, 1(a0) in its delay slot
    let (stop, r) = fault_report(&[LUI_A0_8010, 0x0c00_4040, 0x8c88_0001], &[]).await;
    assert_eq!((stop.a, stop.epc), (4, ENTRY + 4));
    has(&r, "pc:      0x80010008 <main+0x8>  lw      t0,1(a0)");
    has(
        &r,
        "in the delay slot of the branch at 0x80010004 <main+0x4>  jal     0x80010100",
    );
    has(&r, "cause 80000010");
    has(&r, "  epc 80010004");
    // jal links before its delay slot runs.
    has(&r, "ra:      0x8001000c <main+0xc>");
}

#[tokio::test]
async fn ibe_and_misaligned_fetch_have_no_instruction() {
    // lui t9, 0x1fa0; jr t9; nop
    let (stop, r) = fault_report(&[0x3c19_1fa0, 0x0320_0008, 0], &[]).await;
    assert_eq!((stop.a, stop.epc), (6, 0x1fa0_0000));
    has(&r, "cause:   IBE (ExcCode 6)");
    has(&r, "pc:      0x1fa00000  (not readable)");

    // lui t9, 0x8001; ori t9, t9, 2; jr t9; nop
    let (stop, r) = fault_report(&[0x3c19_8001, 0x3739_0002, 0x0320_0008, 0], &[]).await;
    assert_eq!((stop.a, stop.b, stop.epc), (4, 0x8001_0002, 0x8001_0002));
    has(
        &r,
        "address: 0x80010002 <main+0x2> (BadVaddr) (instruction fetch)",
    );
    has(&r, "pc:      0x80010002 <main+0x2>  (not readable)");
}

#[tokio::test]
async fn stack_words_are_dumped_and_named() {
    let stack = [0x1234_5678, ENTRY + 0x20, 0, 0, 0, 0, 0, 7];
    let (_, r) = fault_report(&[0xfc00_0000], &stack).await;
    has(&r, "stack at 0x801fff00:");
    has(&r, "0x801fff00: 12345678");
    has(&r, "0x801fff04: 80010020 <main+0x20>");
    has(&r, "0x801fff1c: 00000007");
}
