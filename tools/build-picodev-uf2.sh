#!/bin/sh
# Builds Pico-Dev firmware that boots the psxmon monitor:
#   build-picodev-uf2.sh monitor-ft232h-picodev-usb.booty [PicoDev-psxmon.uf2]
#
# Clones johnbaumann/PicoDev at the commit below, replaces its boot payload
# with the given .booty file from a psxmon release, and builds the UF2 with
# the Raspberry Pi Pico SDK. Needs git, cmake, make, the Arm GNU toolchain
# (arm-none-eabi, on PATH or in PICO_TOOLCHAIN_PATH) and the Pico SDK with its
# tinyusb submodule, in PICO_SDK_PATH. Tested with SDK 2.3.1 and Arm GNU
# 14.2.rel1. Set PICODEV_DIR to keep the clone and build tree there.
set -eu

PICODEV_URL=${PICODEV_URL:-https://github.com/johnbaumann/PicoDev}
PICODEV_COMMIT=d21127930788df4db1b4ec6fe9594741ca844093
PAYLOAD_LINE='.incbin "../payload/unirom_r.booty"'

die() {
    echo "build-picodev-uf2: $*" >&2
    exit 1
}

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: $0 payload.booty [out.uf2]"
abs() {
    case $1 in /*) echo "$1" ;; *) echo "$PWD/$1" ;; esac
}
[ -f "$1" ] || die "$1: not found"
payload=$(abs "$1")
out=$(abs "${2:-PicoDev-psxmon.uf2}")
[ "$(head -c 16 "$payload")" = "Licensed by Sony" ] || die "$1: not a booty payload"

for tool in git cmake make; do
    command -v "$tool" >/dev/null || die "$tool not found"
done
[ -n "${PICO_SDK_PATH:-}" ] || die "PICO_SDK_PATH is not set; point it at a Pico SDK checkout"
[ -f "$PICO_SDK_PATH/pico_sdk_init.cmake" ] || die "PICO_SDK_PATH=$PICO_SDK_PATH is not a Pico SDK"
[ -f "$PICO_SDK_PATH/lib/tinyusb/src/tusb.h" ] ||
    die "the Pico SDK has no tinyusb; run git submodule update --init in $PICO_SDK_PATH"
if [ -n "${PICO_TOOLCHAIN_PATH:-}" ]; then
    [ -x "$PICO_TOOLCHAIN_PATH/bin/arm-none-eabi-gcc" ] || die "no arm-none-eabi-gcc in PICO_TOOLCHAIN_PATH/bin"
else
    command -v arm-none-eabi-gcc >/dev/null || die "arm-none-eabi-gcc not found; install the Arm GNU toolchain"
fi

src=${PICODEV_DIR:-$(mktemp -d)}
mkdir -p "$src"
cd "$src"
# The tree gets force-checked-out and its build directory removed, so only
# reuse one this script made.
if [ ! -e .build-picodev-uf2 ]; then
    [ -z "$(ls -A)" ] || die "$src is not empty and was not made by this script"
    git init -q
    : > .build-picodev-uf2
fi
git fetch -q --depth 1 "$PICODEV_URL" "$PICODEV_COMMIT" ||
    die "cannot fetch $PICODEV_COMMIT from $PICODEV_URL"
git -c advice.detachedHead=false checkout -q --force FETCH_HEAD
[ "$(git rev-parse HEAD)" = "$PICODEV_COMMIT" ] || die "checked out $(git rev-parse HEAD), not $PICODEV_COMMIT"

# The firmware includes its payload from src/payload.s.
[ "$(grep -cxF "$PAYLOAD_LINE" src/payload.s)" = 1 ] ||
    die "src/payload.s no longer includes payload/unirom_r.booty; the PicoDev layout changed"
cp "$payload" payload/psxmon.booty
sed 's|payload/unirom_r\.booty|payload/psxmon.booty|' src/payload.s > src/payload.s.new
mv src/payload.s.new src/payload.s
[ "$(grep -cxF '.incbin "../payload/psxmon.booty"' src/payload.s)" = 1 ] || die "could not point src/payload.s at the payload"

# payload.s names the payload relative to the build directory.
rm -rf build
cmake -S . -B build -DPICO_SDK_PATH="$PICO_SDK_PATH"
cmake --build build -j"$(nproc 2>/dev/null || echo 4)"
[ -f build/PicoDev.uf2 ] || die "the build made no build/PicoDev.uf2"
cp build/PicoDev.uf2 "$out"
echo "$out"
