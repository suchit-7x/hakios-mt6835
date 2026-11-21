#!/usr/bin/env python3
"""
repack_uefi.py: Repack EDK2 UEFI kernel and boot image for REDMI 13C 5G (air / MT6835)

Fixes KeypadDeviceDxe inverted volume key scan codes, recompresses FVMAIN with
EDK2-compliant LZMA (with explicit 64-bit uncompressed size and no EOPM marker),
updates FFS headers/checksums, and generates boot_air_all.img.
"""

import argparse
import gzip
import hashlib
import io
import lzma
import os
import struct
import subprocess
import sys
import tempfile

GUID_FVMAIN = bytes.fromhex("93fd219e729c154c8c4be77f1db2d792")
GUID_LZMA   = bytes.fromhex("98584eee143959429d6edc7bd79403cf")

OPCODE_MOV_W9_2 = bytes.fromhex("49008052")  # mov w9, #2 (SCAN_DOWN)
OPCODE_MOV_W9_1 = bytes.fromhex("29008052")  # mov w9, #1 (SCAN_UP)
OPCODE_MOV_W0_1 = bytes.fromhex("20008052")  # mov w0, #1 (SCAN_UP)
OPCODE_MOV_W0_2 = bytes.fromhex("40008052")  # mov w0, #2 (SCAN_DOWN)

def ensure_edk2_lzma(script_dir):
    bin_path = os.path.join(script_dir, "edk2_lzma", "edk2_lzma_compress")
    if not os.path.exists(bin_path):
        src_dir = os.path.join(script_dir, "edk2_lzma")
        if os.path.exists(os.path.join(src_dir, "Makefile")):
            print(f"[+] Building edk2_lzma_compress in {src_dir}...")
            subprocess.run(["make", "-C", src_dir], check=True)
    if not os.path.exists(bin_path):
        # Fallback to system /tmp
        if os.path.exists("/tmp/edk2_lzma_compress"):
            return "/tmp/edk2_lzma_compress"
        raise FileNotFoundError(f"edk2_lzma_compress not found at {bin_path}")
    return bin_path

def patch_keypad(fvmain: bytearray) -> bytearray:
    kpd_base = 0x684e4
    off1 = kpd_base + 0x914
    off2 = kpd_base + 0xae0
    off3 = kpd_base + 0x34a0  # VA 0x48a0: static EFI_KEY_DATA for Volume Down

    # Volume Up: emits SCAN_UP (0x0001)
    fvmain[off1:off1+4] = OPCODE_MOV_W9_1  # mov w9, #1 (SCAN_UP)

    # Volume Down: state tracker sets SCAN_DOWN (0x0002)
    fvmain[off2:off2+4] = OPCODE_MOV_W0_2  # mov w0, #2 (SCAN_DOWN)

    # Volume Down: static EFI_KEY_DATA pushed on release (at VA 0x48a0): SCAN_DOWN (0x0002)
    print(f"[+] Patching Volume Down EFI_KEY_DATA at {hex(off3)}: {fvmain[off3:off3+2].hex()} -> 0200 (SCAN_DOWN)")
    fvmain[off3:off3+2] = bytes.fromhex("0200")

    return fvmain

def repack_uefi(uefi_raw: bytearray, edk2_lzma_bin: str) -> bytearray:
    # 1. Locate FVMAIN FFS file (at 0xe000)
    ffs_off = uefi_raw.find(GUID_FVMAIN)
    if ffs_off == -1:
        ffs_off = 0xe000
    print(f"[+] FVMAIN FFS file located at {hex(ffs_off)}")

    sec_off = ffs_off + 24
    assert uefi_raw[sec_off+3] == 0x02, "Expected GUID-defined section"
    lzma_guid = uefi_raw[sec_off+4:sec_off+20]
    assert lzma_guid == GUID_LZMA, f"Expected LZMA GUID, got {lzma_guid.hex()}"

    stream_off = sec_off + 24
    import lzma
    print(f"[+] Decompressing FVMAIN LZMA stream starting at {hex(stream_off)}...")
    fvmain = bytearray(lzma.decompress(uefi_raw[stream_off:stream_off + 0x200000]))
    print(f"[+] Decompressed FVMAIN size: {len(fvmain)} bytes ({hex(len(fvmain))})")

    # 2. Patch Keypad opcodes
    fvmain = patch_keypad(fvmain)

    # 3. Compress with edk2_lzma_compress
    with tempfile.NamedTemporaryFile(delete=False) as f_in, tempfile.NamedTemporaryFile(delete=False) as f_out:
        f_in.write(fvmain)
        f_in.close()
        f_out.close()
        try:
            cmd = [edk2_lzma_bin, f_in.name, f_out.name]
            subprocess.run(cmd, check=True)
            with open(f_out.name, "rb") as f:
                comp_lzma = f.read()
        finally:
            os.unlink(f_in.name)
            os.unlink(f_out.name)

    print(f"[+] Recompressed LZMA stream: {len(comp_lzma)} bytes, header: {comp_lzma[:13].hex()}")

    # 4. Update Section and FFS File headers
    uefi = bytearray(uefi_raw)
    uefi[stream_off : stream_off + len(comp_lzma)] = comp_lzma

    sec_size = 24 + len(comp_lzma)
    struct.pack_into("<I", uefi, sec_off, sec_size)
    uefi[sec_off + 3] = 0x02  # GUID-defined section

    file_size = 24 + sec_size
    uefi[ffs_off + 20] = file_size & 0xFF
    uefi[ffs_off + 21] = (file_size >> 8) & 0xFF
    uefi[ffs_off + 22] = (file_size >> 16) & 0xFF
    uefi[ffs_off + 23] = 0xF8  # File State

    # Recompute FFS checksum
    hdr = bytearray(uefi[ffs_off : ffs_off + 24])
    hdr[16] = 0
    hdr[17] = 0
    s = sum(hdr[:23]) % 256
    calc_chk = (0x100 - s) % 256
    uefi[ffs_off + 16] = calc_chk
    uefi[ffs_off + 17] = 0xAA

    # Pad free space with 0xFF to 4 MiB FD boundary
    free_start = (ffs_off + file_size + 7) & ~7
    for i in range(free_start, len(uefi)):
        uefi[i] = 0xFF

    print(f"[+] Reassembled UEFI FD size: {len(uefi)} bytes (FFS checksum: 0x{calc_chk:02x})")
    return uefi

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    workspace_root = os.path.dirname(repo_root)

    default_uefi = os.path.join(workspace_root, "out", "uefi_kernel.bin")
    default_ramdisk = os.path.join(workspace_root, "out", "air_ramdisk.img")
    default_boot = os.path.join(workspace_root, "out", "boot_air_all.img")

    parser = argparse.ArgumentParser(description="Repack UEFI and Android boot image for air (MT6835)")
    parser.add_argument("--uefi", default=default_uefi, help="Path to uncompressed 4 MiB uefi_kernel.bin")
    parser.add_argument("--ramdisk", default=default_ramdisk, help="Path to air_ramdisk.img")
    parser.add_argument("--template-boot", default=default_boot, help="Template boot image for header")
    parser.add_argument("--out", default=default_boot, help="Output boot_air_all.img path")
    args = parser.parse_args()

    edk2_lzma_bin = ensure_edk2_lzma(script_dir)

    print(f"[+] Reading UEFI kernel: {args.uefi}")
    with open(args.uefi, "rb") as f:
        uefi_raw = bytearray(f.read())

    patched_uefi = repack_uefi(uefi_raw, edk2_lzma_bin)

    # Save patched UEFI kernel FD
    uefi_out = os.path.join(workspace_root, "out", "uefi_kernel.bin")
    with open(uefi_out, "wb") as f:
        f.write(patched_uefi)
    print(f"[+] Saved patched UEFI kernel: {uefi_out}")

    # Extract and save patched KeypadDeviceDxe.pe
    kpd_pe_out = os.path.join(workspace_root, "out", "KeypadDeviceDxe.pe")
    # Decompress FVMAIN to get clean PE
    stream_off = 0xe000 + 24 + 24
    decomp_fv = lzma.decompress(patched_uefi[stream_off:stream_off + 0x200000])
    pe_data = decomp_fv[0x684e4 : 0x684e4 + 14848]
    with open(kpd_pe_out, "wb") as f:
        f.write(pe_data)
    print(f"[+] Saved patched KeypadDeviceDxe.pe: {kpd_pe_out}")

    # Gzip UEFI kernel
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(patched_uefi)
    gz_kernel = buf.getvalue()
    print(f"[+] Gzipped kernel size: {len(gz_kernel)} bytes")

    # Read ramdisk
    print(f"[+] Reading ramdisk: {args.ramdisk}")
    with open(args.ramdisk, "rb") as f:
        ramdisk_data = f.read()

    # Read header template
    header_src = args.template_boot
    if not os.path.exists(header_src):
        header_src = "/home/suchit-7x/.local/share/Trash/files/boot_air_all.img"
    with open(header_src, "rb") as f:
        orig_boot = f.read(4096)

    hdr = bytearray(orig_boot)
    struct.pack_into("<I", hdr, 8, len(gz_kernel))
    struct.pack_into("<I", hdr, 12, len(ramdisk_data))

    gz_pad_len = (len(gz_kernel) + 4095) & ~4095
    gz_padded = gz_kernel + b"\x00" * (gz_pad_len - len(gz_kernel))

    rd_pad_len = (len(ramdisk_data) + 4095) & ~4095
    rd_padded = ramdisk_data + b"\x00" * (rd_pad_len - len(ramdisk_data))

    final_boot = bytes(hdr) + gz_padded + rd_padded
    target_size = 64 * 1024 * 1024
    if len(final_boot) < target_size:
        final_boot += b"\x00" * (target_size - len(final_boot))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as f:
        f.write(final_boot)

    for extra_copy in ["/home/suchit-7x/boot_air_all.img", "/home/suchit-7x/firmware/air/boot_air_all.img"]:
        if os.path.exists(os.path.dirname(extra_copy)):
            with open(extra_copy, "wb") as f:
                f.write(final_boot)

    print(f"[+] Successfully generated boot image: {args.out} ({len(final_boot)} bytes)")
    print(f"[+] SHA256: {hashlib.sha256(final_boot).hexdigest()}")

if __name__ == "__main__":
    main()
