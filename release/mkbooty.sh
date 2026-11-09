#!/bin/sh
# Turns a PS-EXE into a booty payload for the Pico-Dev: mkbooty.sh in.ps-exe out.booty
# Needs mipsel-none-elf-gcc on PATH, as in the ghcr.io/grumpycoders/pcsx-redux-build
# container.
#
# Same layout as ps1-packer -booty, without the compression. The device
# answers every expansion port read with the next byte of the payload, so the
# file is the byte stream the console reads, in order:
#   - the license string the BIOS checks, then the address of the pre-boot
#     entry,
#   - straight-line code the BIOS runs from the expansion port, which writes
#     stage 2 into RAM at 0x24 one word at a time, arms a cop0 breakpoint on
#     0x80030000 and returns,
#   - the PS-EXE's text section, which stage 2 copies to its load address
#     with word reads of the port once the BIOS unpacks the shell, before it
#     sets the stack and enters the program through FlushCache.
set -eu

in=$1
out=$(realpath -m "$2")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

word() {
    od -An -v -t u4 -j "$1" -N 4 "$in" | tr -d ' '
}

[ "$(head -c 8 "$in")" = "PS-X EXE" ] || { echo "$in: not a PS-EXE" >&2; exit 1; }
pc=$(word 0x10)
taddr=$(word 0x18)
tsize=$(word 0x1c)
sp=$(word 0x30)
words=$(( (tsize + 3) / 4 ))
[ "$words" -gt 0 ] && [ "$words" -le 65535 ] || { echo "$in: text size $tsize out of range" >&2; exit 1; }

as() {
    mipsel-none-elf-gcc -march=mips1 -mabi=32 -EL -c -x assembler -o "$tmp/$1.o" "$tmp/$1.s"
}

# Stage 2, at 0x24. Entry is the debug vector at 0x40.
cat > "$tmp/stage2.s" <<EOF
    .set noreorder
    .set noat
    .text
    .global copy, entry
copy:
    lw    \$a3, 0(\$a1)
    addiu \$a2, \$a2, -1
    sw    \$a3, 0(\$a0)
    bnez  \$a2, copy
    addiu \$a0, \$a0, 4
    j     0xa0
    li    \$t1, 0x44
entry:
    mtc0  \$0, \$7
    li    \$a0, $taddr
    li    \$ra, $pc
    li    \$sp, $sp
    move  \$fp, \$sp
    lui   \$a1, 0xbf00
    j     copy
    ori   \$a2, \$0, $words
EOF
as stage2
mipsel-none-elf-ld -EL -Ttext=0x24 -e entry -o "$tmp/stage2.elf" "$tmp/stage2.o"
[ "$(mipsel-none-elf-nm "$tmp/stage2.elf" | awk '$3 == "entry" { print $1 }')" = 00000040 ] ||
    { echo "stage 2 entry is not at 0x40" >&2; exit 1; }
mipsel-none-elf-objcopy -O binary -j .text "$tmp/stage2.elf" "$tmp/stage2.bin"
[ "$(wc -c < "$tmp/stage2.bin")" -le $((0x80 - 0x24)) ] ||
    { echo "stage 2 runs into the exception vector at 0x80" >&2; exit 1; }

# The code the BIOS runs from the port. No branches: every fetch eats a byte.
{
    printf '    .set noreorder\n    .set noat\n    .text\n'
    printf '    .ascii "Licensed by Sony Computer Entertainment Inc."\n'
    printf '    .byte 0, 0, 0, 0x1f\n'
    printf '    mtc0 $0, $7\n    li $t2, -1\n    lui $t1, 0x8003\n    lui $t0, 0xeb80\n'
    printf '    mtc0 $t2, $11\n    mtc0 $t2, $9\n    mtc0 $t1, $5\n    mtc0 $t1, $3\n    mtc0 $t0, $7\n'
    addr=$((0x24))
    last=
    for w in $(od -An -v -t u4 "$tmp/stage2.bin"); do
        [ -n "$last" ] && printf '%s\n' "$last"
        if [ "$w" -eq 0 ]; then
            last="    sw \$0, $addr(\$0)"
        else
            printf '    lui $t0, %d\n' $((w >> 16))
            [ $((w & 0xffff)) -ne 0 ] && printf '    ori $t0, $t0, %d\n' $((w & 0xffff))
            last="    sw \$t0, $addr(\$0)"
        fi
        addr=$((addr + 4))
    done
    printf '    jr $ra\n%s\n' "$last"
} > "$tmp/header.s"
as header
mipsel-none-elf-objcopy -O binary -j .text "$tmp/header.o" "$tmp/header.bin"

dd if="$in" of="$tmp/text.bin" bs=2048 skip=1 status=none
head -c $((words * 4)) "$tmp/text.bin" > "$tmp/body.bin"
[ "$(wc -c < "$tmp/body.bin")" -eq $((words * 4)) ] || { echo "$in: shorter than its text size" >&2; exit 1; }
cat "$tmp/header.bin" "$tmp/body.bin" > "$out"
