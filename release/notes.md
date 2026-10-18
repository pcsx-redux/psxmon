psxmon binaries for Linux (x86_64), Windows (x86_64) and macOS (arm64), and the monitor images built from the nugget revision named below.

Monitor on the retail BIOS kernel:
- `monitor-sio1.ps-exe`, `monitor-sio1.zip`: load or boot it, talk to it over the serial port. The zip is the disc image, a `.bin` and its `.cue`.
- `monitor-sio1-cart.rom`: flash cartridge image; the console boots straight into the monitor.
- `monitor-ft232h-<board>.ps-exe`, `.zip` (disc image): FT232H on the expansion port, one image per board, since the link addresses are fixed at build time. Boards: `psx232h-a20`, `psx232h-a0`, `picodev-usb`, `picodev-uart`, `piodev-lite`, `orion`, `powerreplay`. The `piodev-lite` addresses are read off its schematic.

OpenBIOS with the monitor:
- `openbios-sio1-cart.rom`: flash cartridge image; OpenBIOS takes over from the retail BIOS at boot and runs the monitor on the serial port.
- `openbios-sio1.rom`, `openbios-ft232h-<board>.rom`: 512 KiB BIOS ROM images, for a console with a replaced BIOS chip.
- `openbios-ft232h-piodev-lite-cart.rom`: flash image for the PIO-Dev-Lite; OpenBIOS takes over at boot and runs the monitor over the cart's FT232H.
- `openbios-atcons-h2700.elf`: for the H2700 dev board. `psxmon patch-h2700 stock.bin openbios-atcons-h2700.elf -o flash.bin` puts it into a dump of the board's own flash, or the same command with the FLASH27 kit's `H2700.IMG` in place of `stock.bin` patches that directly; reset mode 7 boots the monitor, any other mode the stock BIOS.

Run on real hardware, in earlier builds: `monitor-sio1-cart.rom`, `monitor-sio1.ps-exe`, and `openbios-sio1-cart.rom` on a SCPH-1001 with a Power Replay cart. Run in PCSX-Redux only: the OpenBIOS SIO1 ROM. The H2700 image ran on the board in its v0.1.0 form; this build's monitor has not. Reported working on hardware by a user: a Pico-Dev FT232H image (`monitor-ft232h-picodev-usb`), and the Orion cart image (`monitor-ft232h-orion`) on a SCPH-1001 and a SCPH-7502. Not run anywhere: every other FT232H image.

The disc images carry no license sectors, so they boot on consoles that boot burned discs.
