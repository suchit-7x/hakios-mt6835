#!/bin/bash
# Build fbdiag.img: fbdiag in front of Android's kernel (stock air boot.img or backup boot_a).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

LLD=$(which ld.lld || echo "$ROOT/xnu-deps/host/zig/zig ld.lld")
CFLAGS="--target=aarch64-linux-gnu -ffreestanding -nostdlib -fno-builtin -mgeneral-regs-only -mstrict-align -O2 -Wall -Wextra"

# Ensure font8x16.h exists
if [ ! -f "$HERE/font8x16.h" ]; then
    echo "Generating font8x16.h from air-linux-kernel..."
    python3 -c '
import re
content = open("'"$ROOT"'/../air-linux-kernel/lib/fonts/font_8x16.c").read()
bytes_list = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]{2}", content)]
out = ["/* Generated from air-linux-kernel font_8x16.c: ASCII 0x20-0x7e, 8x16 */", "static const unsigned char font8x16[95][16] = {"]
for i in range(32, 127):
    char_bytes = bytes_list[i*16:(i+1)*16]
    row_str = ", ".join(f"0x{b:02x}" for b in char_bytes)
    c_name = chr(i) if 32 < i < 127 and chr(i) not in "\\\"" else f"0x{i:02x}"
    out.append(f"    {{ {row_str} }}, /* {c_name} */")
out.append("};")
open("'"$HERE"'/font8x16.h", "w").write("\n".join(out) + "\n")
'
fi

echo "Compiling fbdiag_start.S and fbdiag.c for MT6835 (aarch64)..."
clang $CFLAGS -c "$HERE/fbdiag_start.S" -o "$HERE/fbdiag_start.o"
clang $CFLAGS -c "$HERE/fbdiag.c" -o "$HERE/fbdiag.o"
$LLD -T "$HERE/link.ld" --oformat binary "$HERE/fbdiag_start.o" "$HERE/fbdiag.o" -o "$HERE/fbdiag.bin"

BOOT=${ANDROID_BOOT:-"$HOME/firmware/air/boot.img"}
if [ ! -f "$BOOT" ]; then
    BOOT="$ROOT/backup/boot_a_magisk.img"
fi

echo "Chaining fbdiag in front of Android kernel: $BOOT -> $HERE/fbdiag.img"
python3 "$ROOT/tools/chainboot.py" "$BOOT" "$HERE/fbdiag.bin" "$HERE/fbdiag.img"
echo "fbdiag.img built successfully at $HERE/fbdiag.img"
