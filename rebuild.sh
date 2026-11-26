#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/out" ]; then
    WORKSPACE_DIR="$SCRIPT_DIR"
elif [ -d "$SCRIPT_DIR/../out" ]; then
    WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    WORKSPACE_DIR="$SCRIPT_DIR"
fi
OUT_DIR="$WORKSPACE_DIR/out"
TOOLS_DIR="$WORKSPACE_DIR/hackios-mt6835/tools"

echo "=== HakiOS MT6835 (REDMI 13C 5G / air) Build System ==="

# Step 1: Patch kernel diagnostics
echo "[1/4] Patching XNU kernel diagnostics & init path..."
if [ -f "$TOOLS_DIR/patch_kernel_diagnostics.py" ]; then
    python3 "$TOOLS_DIR/patch_kernel_diagnostics.py"
else
    python3 "$OUT_DIR/patch_kernel_diagnostics.py"
fi

# Step 2: Build FAT32 MBR ramdisk
echo "[2/4] Building EDK2-compliant FAT32 MBR ramdisk (air_ramdisk.img)..."
if [ -f "$WORKSPACE_DIR/hakios-xnu-kernel/userland/root.apfs" ]; then
    cp "$WORKSPACE_DIR/hakios-xnu-kernel/userland/root.apfs" "$OUT_DIR/root.apfs"
fi
if [ -f "$TOOLS_DIR/build_air_ramdisk.py" ]; then
    python3 "$TOOLS_DIR/build_air_ramdisk.py"
else
    python3 "$OUT_DIR/build_air_ramdisk.py"
fi

# Step 3: Package vendor_boot
echo "[3/4] Packaging patched vendor_boot_b.img..."
if [ -f "$TOOLS_DIR/build_vendor_boot.py" ]; then
    python3 "$TOOLS_DIR/build_vendor_boot.py"
else
    python3 "$OUT_DIR/build_vendor_boot.py"
fi

# Step 4: Repack UEFI & generate boot-air-shimed.img
echo "[4/4] Repacking UEFI & generating boot-air-shimed.img..."
if [ -f "$TOOLS_DIR/repack_uefi.py" ]; then
    python3 "$TOOLS_DIR/repack_uefi.py"
else
    python3 "$OUT_DIR/repack_uefi.py"
fi

echo ""
echo "=== Build Complete ==="
echo "Artifacts generated in $OUT_DIR:"
echo "  - vendor_boot_b.img : $(stat -c %s "$OUT_DIR/vendor_boot_b.img") bytes"
echo "  - boot-air-shimed.img: $(stat -c %s "$OUT_DIR/boot-air-shimed.img") bytes"
echo ""
echo "To flash to slot _b and reboot:"
echo "  fastboot flash vendor_boot_b $OUT_DIR/vendor_boot_b.img && \\"
echo "  fastboot flash boot_b $OUT_DIR/boot-air-shimed.img && \\"
echo "  fastboot reboot"
