# psxmon

Host tool for the PS1 debug monitor. The monitor is part of
[nugget](https://github.com/pcsx-redux/nugget), in
[`monitor/`](https://github.com/pcsx-redux/nugget/tree/main/monitor). The
release images are built from the nugget submodule here. psxmon speaks wire
protocol version 2, described in
[`monitor/PROTOCOL.md`](https://github.com/pcsx-redux/nugget/blob/main/monitor/PROTOCOL.md).
It talks to the monitor through a serial port, or through the DTL-H2700's
ISA card (ATCONS). With it you can upload and run a program, debug it with
gdb, stream its console text, serve its PCDRV file I/O from a host
directory, and read or write target memory.

A library (`psxmon`) holds the protocol and the session logic. The `psxmon`
binary is a thin command line on top of it.

## Commands

    psxmon run <file> --port DEV [--baud 115200] [--fast-reload RELOAD]
                      [--lz4 | --no-lz4] [--max-match 128] [--pcdrv DIR]
                      [--timeout SECS] [-v]
    psxmon gdb [<file>] --port DEV [--baud 115200] [--fast-reload RELOAD]
                        [--listen 127.0.0.1:3333] [--no-lz4] [--pcdrv DIR]
                        [--real-step] [-v]
    psxmon ping --port DEV [--baud 115200]
    psxmon dump <addr> <len> -o FILE --port DEV
    psxmon write <addr> <file> --port DEV
    psxmon h2700-reset [--mode 7] [--port atcons[:BASE]] [--no-connect]
                       [--console SECS]
    psxmon patch-h2700 <stock> <monitor> -o FILE
    psxmon mkdisc <exe> -o FILE.bin [--license FILE] [--no-pad]

`--port DEV` is the serial port the monitor is on (see below), or
`PSXMON_PORT` when `--port` is left out. `--port tcp:HOST:PORT` (or
`tcp://HOST:PORT`) connects to the monitor's byte stream over TCP, for
example PCSX-Redux's SIO1 server. `--port atcons` (or `atcons:BASE`,
default base 0x1340) uses the DTL-H2700's ISA card instead; see below.
TCP and ATCONS have no line rate: `--baud` is not used on them, and
`--fast-reload` is an error.
Addresses and lengths take decimal
or `0x` hex.

- `run` loads a program, starts it, and copies its console text to stdout.
  It serves `break 0, 0x101..0x107` PCDRV calls from `--pcdrv DIR`, jailed
  to that directory. Without `--pcdrv`, every PCDRV call fails with -1. The
  run ends when the program executes `break 4, 0`, with its exit code in
  `a0`.
- Programs can be PS-EXE, ELF, CPE or PSF, told apart by their magic. An ELF
  loads its PT_LOAD segments at their physical addresses, minus the header
  sections, and starts at `e_entry` with gp from `_gp`. A CPE loads its load
  chunks and starts at register 0x90. ELF and CPE get sp 0x807FFF00, the top
  of 8 MB, which a 2 MB console mirrors to the top of its RAM.
- PSF (version 0x01) and MiniPSF load as PCSX-Redux loads them: `_lib`
  first, then the file's own PS-EXE, then `_lib2`, `_lib3`, ..., with
  library paths relative to the file naming them. pc and sp (`s_addr`,
  0x801FFFF0 if zero) come from the first PS-EXE loaded, so a MiniPSF
  starts at its library's entry point. Missing libraries are skipped with a
  warning.
- LZ4 is used when the monitor advertises it and it shrinks the upload. The
  compressor caps every match at `--max-match` bytes, because the monitor
  decodes while it receives and cannot pause the sender inside a frame.
- `--fast-reload 9` switches SIO1 to 230400 baud after attaching (SET_BAUD
  with its two-PING confirmation). If the new rate does not answer, psxmon
  falls back to the old one. The monitor keeps the new rate, so later
  commands need `--baud 230400`.
- If the monitor does not answer at `--baud`, psxmon tries 115200, 230400
  and the `--fast-reload` rate, in that order. It says on stderr which rate
  answered.
- `ping` prints the protocol version, the capability bits, and the BIOS
  checksum with its name from a table of retail BIOS images.
- `patch-h2700` builds a flash image for the H2700 from the OpenBIOS
  monitor ELF and STOCK, either a dump of the cart's own 512 KiB flash or
  the FLASH27 kit's `H2700.IMG` (patched in place, same length, only its
  embedded flash touched): the monitor goes into the code cave at
  0xbfc40000 and the stock entry jump is pointed at its hook. It refuses
  anything that is not one of those two unpatched shapes. With the
  reset-mode switch at 7 the cart boots the monitor; any other mode boots
  the stock BIOS. See "Flashing a DTL-H2700" below for writing the result
  to real hardware.
- `mkdisc` builds a bootable disc image with the PS-EXE as `PSX.EXE`: a
  Mode 2 `.bin` identical to PCSX-Redux's `exe2iso`, and a `.cue` beside it.
  Sectors 0-15 hold `--license` (an SDK file in 2336-byte sectors or a raw
  image), or zeros without it. `--no-pad` leaves out the 150 blank sectors
  after the volume.

## The port

`DEV` is the host end of the link: a USB serial adapter on the console's
serial port for the SIO1 images, the FT232H's own serial port for an FT232H
image (whose `--baud` is ignored), or a TCP address.

    psxmon ping --port /dev/ttyUSB0              # Linux, USB adapter
    psxmon ping --port /dev/cu.usbserial-A10K1Y  # macOS
    psxmon ping --port COM3                      # Windows
    psxmon ping --port COM14                     # Windows, COM10 and above too
    PSXMON_PORT=/dev/ttyUSB0 psxmon ping         # Linux or macOS
    $env:PSXMON_PORT = "COM14"; psxmon ping      # Windows PowerShell

On Windows the name is the one Device Manager lists under "Ports (COM &
LPT)". psxmon adds the `\\.\` device prefix itself, so `COM10` and above
need nothing special; a name that already starts with `\` (`\\.\COM14`)
is used as is. On macOS use the `/dev/cu.*` node; `/dev/tty.*` waits for
carrier detect. On Linux the user needs access to the
device, usually through the `dialout` or `uucp` group.

For PCSX-Redux, turn on its SIO1 server in raw mode and connect to it:

    psxmon run prog.ps-exe --port tcp:127.0.0.1:6699

The same form reaches a serial-to-TCP bridge (ser2net or similar) in raw
mode; the bridge sets the line rate.

## Flashing a DTL-H2700

Rewriting the cart's own flash needs Sony's FLASH27 kit
(`pssn/bin/FLASH27` in the PS1 SDK), which this repo has no license to
carry a copy of. It runs on an MS-DOS PC with the DTL-H2700 on its ISA
bus, at the I/O base `FLASH.BAT` is given:

    flash 1340

`FLASH.BAT` runs `psxcons -p0x1340,0 auto`, which runs the kit's AUTO
script: dip-switch mode 2, reset, load and run `H2700.img` on the board
(`down2` then `call`), then `mode27 flash` and another reset to commit
it. Per `README_E.TXT`, "Make sure that DEXBIOS is in the 'Remove' state
as it is executed."

`H2700.IMG` is itself a small PS-X EXE (a flash programmer) carrying the
stock 512 KiB flash image as its payload. `patch-h2700` takes it directly,
patching the embedded payload and leaving the programmer bytes around it
alone; write the result to a new file, then replace the kit's own copy
before running `FLASH.BAT`:

    psxmon patch-h2700 H2700.IMG openbios-atcons-h2700.elf -o H2700.patched.img
    cp H2700.patched.img /path/to/FLASH27/H2700.IMG
    cd /path/to/FLASH27 && flash 1340

`patch-h2700` also still takes a raw 512 KiB dump of the cart's own flash,
when that is what is on hand; it refuses anything that is neither shape.

After flashing, `psxmon h2700-reset` (`--mode 7`, the default) boots the
monitor from the cave; any other `--mode` boots the stock BIOS, same as
before the flash was patched.

## DTL-H2700 (ATCONS)

On the DTL-H2700 the monitor runs from the code cave of the cart's flash
(`patch-h2700`) and talks over the ISA card's two channels: frames on the
16-bit word channel, the OpenBIOS console on the byte channel. psxmon drives
the card with port I/O, so this needs x86 Linux and root (or
`CAP_SYS_RAWIO` on the binary: `setcap cap_sys_rawio+ep psxmon`). On other
systems `--port atcons` fails with an error.

    sudo psxmon h2700-reset
    sudo psxmon run prog.cpe --port atcons --pcdrv ./pc

- `h2700-reset` resets the PS1 into `--mode` (7, the default, boots the
  monitor; other modes the stock BIOS), then opens the card's host side the
  way the SDK tools connect. In mode 7 it copies the boot's console text to
  stdout until the monitor's HELLO, and prints the HELLO.
- Attaching reads a HELLO still waiting in the word channel, then PINGs.
- There is no line rate (`--baud` is ignored, `--fast-reload` is an error)
  and no STOP: a running program stops only on its own.
- psxmon polls the card from a thread and spins while data moves, so a
  transfer keeps one CPU busy.

## Debugging with gdb

`psxmon gdb` is a GDB remote server (RSP over TCP) on top of the monitor.
Use it with `gdb-multiarch` or any `mips` gdb:

    psxmon gdb farmjob.ps-exe --port /dev/ttyUSB0 --pcdrv ./pc
    gdb-multiarch farmjob.elf -ex 'set architecture mips:3000' \
        -ex 'target remote 127.0.0.1:3333'

- With a program, psxmon loads it (LZ4 as with `run`) and leaves it halted
  on its first instruction, with the registers RUN gives it. A fresh monitor
  has no halted context, so this is done by planting `break 0x3ff, 0` at the
  entry, RUNning, and putting the original word back once it has stopped.
  Without a program, gdb attaches to whatever the monitor has halted.
- One gdb connection is served. On `detach` or `kill` the target is left
  halted where it is (it cannot be stopped again once running, so this
  keeps it attachable: run `psxmon gdb` without a program to attach again).
  When the program exits (`break 4, 0`) gdb sees the process exit, and
  psxmon exits with the code as `run` does. gdb's `W` packet carries only
  the low 8 bits of the code; psxmon prints the full code on stderr.
- Console text goes to psxmon's stdout, and while the target runs also to
  gdb as `O` packets, which gdb prints as the program's output (with
  `--batch`, on its stderr). Text printed while the target is halted
  reaches gdb at the next `continue` or `step`. PCDRV calls are served from
  `--pcdrv` while the target runs, exactly as with `run`; gdb never sees
  them.
- Software breakpoints are gdb's own: it writes `break` instructions into
  RAM itself.
- Hardware breakpoints (`hbreak`, or `break` in ROM): the monitor's one
  cop0 exec breakpoint, kept for ROM. One at a time; `hbreak` in RAM is
  refused (use `break` for a software breakpoint instead).
- Watchpoints (`watch`, `rwatch`, `awatch`): the one cop0 data breakpoint.
  The length must be a power of two and the address aligned to it. The
  unit compares the address the CPU issues, so a word store that covers a
  watched byte at another address does not trigger it.
- Breakpoints and the watch match an address in all three segments (the
  compare mask leaves out bits 29-31), and in RAM every mirror of it: the
  BIOS maps 8 MiB of addresses to RAM, over which 2 MiB repeats four
  times and 4 MiB twice, so the mask also leaves out the bits between the
  installed size and 8 MiB. psxmon finds the installed size the first time
  it arms a breakpoint in RAM, by flipping the word at physical 0 and
  reading it back 2, 4 and 6 MiB up (the word is put back), and skips
  that when the program has shrunk the first DRAM bank below 8 MiB
  (DRAM_CTRL at 0x1f801060), where nothing repeats. A hardware stop disarms the whole
  debug unit, so psxmon re-arms it with SET_BP before every CONT, and turns
  it off after every other stop so the monitor's own memory accesses cannot
  trip it.
- Single step: the target description says `<osabi>none</osabi>`, so gdb
  sends `vCont;s` rather than stepping with breakpoints of its own. A step
  runs the instruction at PC, and for a branch or jump its delay slot too.
  psxmon simulates most steps on the host (`src/stepsim.rs`): ALU, shift,
  mult/div and HI/LO instructions, branches and jumps, and aligned loads
  and stores to RAM (first 2 MiB), scratchpad, and loads from the BIOS,
  which go through READ_MEM and WRITE_MEM. The registers stay on the host
  and are written back with SET_REG (only the changed ones) before the
  target next runs and when gdb detaches. Anything else is stepped on the
  target: psxmon plants `break 0x3ff, 0` at the successor in RAM, or lends
  the exec breakpoint to a successor in ROM, continues, and restores
  everything at the stop. That covers coprocessor instructions, `syscall`
  and `break`, overflowing `add`/`addi`/`sub`, unaligned accesses, I/O and
  other memory, a successor PC outside RAM and BIOS, accesses meeting the
  watch, the ROM breakpoint on a stepped instruction, and SR with IsC, SwC,
  RE or a user-mode bit (KUc or KUp) set. A simulated step takes no interrupt (a stepped wait for a
  flag an interrupt handler sets never ends; use `continue`).
  `--real-step` or `PSXMON_STEP_SIM=0` steps everything on the target.
- Ctrl-C stops a running target at its next interrupt when the monitor
  reports the `stop` capability (`psxmon ping` lists it). A target that has
  interrupts off, or never unmasks one, does not stop; nor does
  any target under a monitor without the capability (older monitors,
  ATCONS on the DTL-H2700), where psxmon ignores the interrupt and keeps
  waiting for a breakpoint, watch, fault or exit. `psxmon run` is
  unchanged.
- Faults are reported as signals: address errors and bus errors as
  SIGBUS, reserved instruction and coprocessor unusable as SIGILL,
  overflow as SIGFPE. The monitor cannot deliver a signal, so continuing
  re-executes the faulting instruction unless the PC is changed.
- Limits: a `break` in a branch delay slot (a gdb breakpoint there, or a
  program's own) is reported by the monitor as a hardware stop with the PC
  on the branch (see PROTOCOL.md, section 13). With `--real-step`, a step
  of a branch to itself is reported done without running it. The R3000A has no FPU; gdb's
  FP registers read as 0 and writes to them are dropped.

## Exit status

`psxmon run` prints the target's full exit code on stderr. The process exit
status is that code when it is between 0 and 123, and 123 for any larger
code. Other statuses: 124 means the target did not stop before `--timeout`,
125 means a host, link or protocol error, and 126 means the target stopped
without exiting (a fault or another breakpoint).

## Release files

Each [release](https://github.com/pcsx-redux/psxmon/releases/latest) carries
psxmon for three hosts and the monitor images, built from the nugget
submodule. The links fetch the latest release.

| File | What it is | Link | How to use it | Run on hardware |
|---|---|---|---|---|
| [`psxmon-linux-x86_64`](https://github.com/pcsx-redux/psxmon/releases/latest/download/psxmon-linux-x86_64) | psxmon, Linux x86_64 | - | `chmod +x`, run | yes |
| [`psxmon-windows-x86_64.exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/psxmon-windows-x86_64.exe) | psxmon, Windows x86_64 | - | run from a terminal | v0.1.0 fails ([#6](https://github.com/pcsx-redux/psxmon/issues/6)) |
| [`psxmon-macos-arm64`](https://github.com/pcsx-redux/psxmon/releases/latest/download/psxmon-macos-arm64) | psxmon, macOS arm64 | - | `chmod +x`, run | not run |
| [`monitor-sio1.ps-exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-sio1.ps-exe) | monitor on the retail BIOS | SIO1 | load it with any PS-EXE loader | not recorded |
| [`monitor-sio1.zip`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-sio1.zip) | disc image of the above (`.bin` + `.cue`) | SIO1 | burn it, boot it | as the `.ps-exe` |
| [`monitor-sio1-cart.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-sio1-cart.rom) | monitor on the retail BIOS, cartridge | SIO1 | flash a cartridge; boots into the monitor | yes |
| [`monitor-ft232h-psx232h-a20.ps-exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-psx232h-a20.ps-exe) | monitor on the retail BIOS | FT232H, psx232h, A0 on A20 | load it with any PS-EXE loader | no |
| [`monitor-ft232h-psx232h-a20.zip`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-psx232h-a20.zip) | disc image of the above | FT232H, psx232h, A0 on A20 | burn it, boot it | as the `.ps-exe` |
| [`monitor-ft232h-psx232h-a0.ps-exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-psx232h-a0.ps-exe) | monitor on the retail BIOS | FT232H, psx232h, A0 on A0 | load it with any PS-EXE loader | no |
| [`monitor-ft232h-psx232h-a0.zip`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-psx232h-a0.zip) | disc image of the above | FT232H, psx232h, A0 on A0 | burn it, boot it | as the `.ps-exe` |
| [`monitor-ft232h-picodev-usb.ps-exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-picodev-usb.ps-exe) | monitor on the retail BIOS | FT232H, Pico-Dev, USB channel | load it with any PS-EXE loader | reported working |
| [`monitor-ft232h-picodev-usb.zip`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-picodev-usb.zip) | disc image of the above | FT232H, Pico-Dev, USB channel | burn it, boot it | as the `.ps-exe` |
| [`monitor-ft232h-picodev-uart.ps-exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-picodev-uart.ps-exe) | monitor on the retail BIOS | FT232H, Pico-Dev, UART channel | load it with any PS-EXE loader | no |
| [`monitor-ft232h-picodev-uart.zip`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-picodev-uart.zip) | disc image of the above | FT232H, Pico-Dev, UART channel | burn it, boot it | as the `.ps-exe` |
| [`monitor-ft232h-piodev-lite.ps-exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-piodev-lite.ps-exe) | monitor on the retail BIOS | FT232H, PIO-Dev-Lite | load it with any PS-EXE loader | no |
| [`monitor-ft232h-piodev-lite.zip`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-piodev-lite.zip) | disc image of the above | FT232H, PIO-Dev-Lite | burn it, boot it | as the `.ps-exe` |
| [`monitor-ft232h-orion.ps-exe`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-orion.ps-exe) | monitor on the retail BIOS | FT232H-style link, Orion cart | load it with any PS-EXE loader | SCPH-1001, SCPH-7502 |
| [`monitor-ft232h-orion.zip`](https://github.com/pcsx-redux/psxmon/releases/latest/download/monitor-ft232h-orion.zip) | disc image of the above | FT232H-style link, Orion cart | burn it, boot it | as the `.ps-exe` |
| [`openbios-sio1-cart.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-sio1-cart.rom) | OpenBIOS with the monitor, cartridge | SIO1 | flash a cartridge; OpenBIOS takes over at boot | Redux only |
| [`openbios-sio1.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-sio1.rom) | OpenBIOS with the monitor, 512 KiB BIOS ROM | SIO1 | program a replacement BIOS chip | Redux only |
| [`openbios-ft232h-psx232h-a20.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-ft232h-psx232h-a20.rom) | OpenBIOS with the monitor, 512 KiB BIOS ROM | FT232H, psx232h, A0 on A20 | program a replacement BIOS chip | no |
| [`openbios-ft232h-psx232h-a0.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-ft232h-psx232h-a0.rom) | OpenBIOS with the monitor, 512 KiB BIOS ROM | FT232H, psx232h, A0 on A0 | program a replacement BIOS chip | no |
| [`openbios-ft232h-picodev-usb.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-ft232h-picodev-usb.rom) | OpenBIOS with the monitor, 512 KiB BIOS ROM | FT232H, Pico-Dev, USB channel | program a replacement BIOS chip | no |
| [`openbios-ft232h-picodev-uart.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-ft232h-picodev-uart.rom) | OpenBIOS with the monitor, 512 KiB BIOS ROM | FT232H, Pico-Dev, UART channel | program a replacement BIOS chip | no |
| [`openbios-ft232h-piodev-lite.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-ft232h-piodev-lite.rom) | OpenBIOS with the monitor, 512 KiB BIOS ROM | FT232H, PIO-Dev-Lite | program a replacement BIOS chip | no |
| [`openbios-ft232h-orion.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-ft232h-orion.rom) | OpenBIOS with the monitor, 512 KiB BIOS ROM | FT232H-style link, Orion cart | program a replacement BIOS chip | no |
| [`openbios-ft232h-piodev-lite-cart.rom`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-ft232h-piodev-lite-cart.rom) | OpenBIOS with the monitor, cartridge | FT232H, PIO-Dev-Lite | flash the PIO-Dev-Lite; OpenBIOS takes over at boot | no |
| [`openbios-atcons-h2700.elf`](https://github.com/pcsx-redux/psxmon/releases/latest/download/openbios-atcons-h2700.elf) | OpenBIOS with the monitor, for the DTL-H2700 | ATCONS | `psxmon patch-h2700`, flash, reset mode 7; psxmon has no ATCONS link yet ([#3](https://github.com/pcsx-redux/psxmon/issues/3)) | yes |

## Build

    cargo build --release
    cargo test

The toolchain is stable Rust (`rust-toolchain.toml`). CI runs `cargo fmt`,
`cargo clippy` with the lint set in `Cargo.toml`, the tests, and release
builds for Linux, Windows and macOS.

The tests run the session against a simulated monitor
(`tests/session/sim.rs`). The simulator speaks the byte-stream protocol with
2 MiB of RAM, registers, SET_BAUD, and either a scripted target that makes
PCDRV and exit breaks or a small R3000 interpreter with a ROM and the cop0
debug unit. `tests/gdb` drives `psxmon gdb` against it in raw RSP; with
`PSXMON_GDB_E2E=1` it also runs `gdb-multiarch --batch` against it.

## Discord

PCSX-Redux's server, for psxmon, the monitor and nugget:

[![Discord](https://discord.com/api/guilds/567975889879695361/widget.png?style=banner2)](https://discord.gg/KG5uCqw)

The PSX.Dev server, for PlayStation 1 development, hacking and reverse
engineering in general:

[![Discord](https://discord.com/api/guilds/642647820683444236/widget.png?style=banner2)](https://discord.gg/QByKPpH)

## License

MIT, see `LICENSE`.
