#!/bin/sh
# Builds the monitor images a psxmon release carries, from the nugget
# submodule, into $1 (default: dist). Needs mipsel-none-elf-gcc on PATH, as in
# the ghcr.io/grumpycoders/pcsx-redux-build container.
#
# Names are monitor-<link>[-<board>].<ext> for the monitor running on the
# retail BIOS kernel, and openbios-<link>-<target>.<ext> for OpenBIOS with the
# monitor built in:
#   monitor-sio1.ps-exe             PS-EXE, SIO1 (serial port)
#   monitor-sio1-cart.rom           flash cartridge image, SIO1
#   monitor-ft232h-<board>.ps-exe   PS-EXE, FT232H on the expansion port;
#                                   boards in nugget monitor/hosts/ft232h-boards.mk
#   monitor-ft232h-<board>.rom      flash cartridge image of the same, for
#                                   boards that decode the FTDI clear of the
#                                   flash
#   openbios-sio1-cart.rom          OpenBIOS replacing the retail one from a
#                                   flash cartridge, monitor on SIO1
#   openbios-sio1.rom               OpenBIOS as the console's BIOS ROM, SIO1
#   openbios-ft232h-<board>.rom     same, FT232H on the expansion port
#   openbios-ft232h-<board>-cart.rom  OpenBIOS from a flash cartridge that also
#                                   carries the FT232H, for boards that decode
#                                   it clear of the flash
#   openbios-atcons-h2700.elf       OpenBIOS for the H2700 code cave; turn it
#                                   into a flash image with psxmon patch-h2700
# Disc images of the PS-EXEs come from psxmon mkdisc, zipped as .bin + .cue,
# in the release workflow.
set -eu

out=$(realpath -m "${1:-dist}")
nugget=$(realpath "$(dirname "$0")/../nugget")
jobs=$(nproc)
mkdir -p "$out"

retail="$nugget/monitor/hosts/retail"
cart="$nugget/monitor/hosts/cart"

clean() {
    make -C "$retail" clean >/dev/null
    make -C "$cart" clean >/dev/null
}

clean
make -C "$retail" -j"$jobs"
cp "$retail/monitor-retail.ps-exe" "$out/monitor-sio1.ps-exe"

clean
make -C "$cart" -j"$jobs"
cp "$cart/monitor-cart.rom" "$out/monitor-sio1-cart.rom"

for board in psx232h-a20 psx232h-a0 picodev-usb picodev-uart piodev-lite orion powerreplay; do
    clean
    make -C "$retail" -j"$jobs" MONITOR_LINK=FT232H MONITOR_FT232H_BOARD="$board"
    cp "$retail/monitor-retail.ps-exe" "$out/monitor-ft232h-$board.ps-exe"
done
clean

# Cart images of the FT232H monitor, for boards whose FIFO is decoded clear
# of the cart's flash at 0x1f000000. The cart loader (rom.s) copies the PS-EXE
# into RAM before it runs, so the monitor's EXP1 setup never moves timing
# under code fetched from the flash.
for board in orion; do
    tmp=$(mktemp -d)
    mipsel-none-elf-gcc -march=mips1 -mabi=32 -EL -c -o "$tmp/rom.o" \
        "-DPSEXE=\"$out/monitor-ft232h-$board.ps-exe\"" -x assembler-with-cpp "$cart/rom.s"
    mipsel-none-elf-ld -EL -Ttext=0x1f000000 -e 0x1f000000 -o "$tmp/rom.elf" "$tmp/rom.o"
    mipsel-none-elf-objcopy -O binary -j .text "$tmp/rom.elf" "$out/monitor-ft232h-$board.rom"
    rm -rf "$tmp"
done

openbios() {
    make -C "$nugget/openbios" clean >/dev/null
    make -C "$nugget/openbios" -j"$jobs" MONITOR=1 "$@"
}

openbios BOOT=cart MONITOR_LINK=SIO1
cp "$nugget/openbios/openbios.bin" "$out/openbios-sio1-cart.rom"
openbios BOOT=rom MONITOR_LINK=SIO1
cp "$nugget/openbios/openbios.bin" "$out/openbios-sio1.rom"
for board in psx232h-a20 psx232h-a0 picodev-usb picodev-uart piodev-lite orion powerreplay; do
    openbios BOOT=rom MONITOR_LINK=FT232H MONITOR_FT232H_BOARD="$board"
    cp "$nugget/openbios/openbios.bin" "$out/openbios-ft232h-$board.rom"
done
# PIO-Dev-Lite: flash on /CS0 Y0, FT232H on Y1 at 0x1f200000. Link init only
# widens EXP1, the timing the flash runs at is unchanged.
for board in piodev-lite; do
    openbios BOOT=cart MONITOR_LINK=FT232H MONITOR_FT232H_BOARD="$board"
    cp "$nugget/openbios/openbios.bin" "$out/openbios-ft232h-$board-cart.rom"
done

openbios BOOT=cart
cp "$nugget/openbios/openbios.elf" "$out/openbios-atcons-h2700.elf"
make -C "$nugget/openbios" clean >/dev/null

ls -l "$out"
