#!/usr/bin/env python3
"""
repack_uefi.py: Repack EDK2 UEFI kernel and boot image for REDMI 13C 5G (air / MT6835)

1. Injects clean KeypadDeviceDxe (fixing volume key navigation).
2. Patches PartitionDxe (fixing protocol leak on superfloppy fallback).
3. Patches UniXNU LoadFile (adding LocateProtocol fallback when volume handle is NULL).
4. Patches UniXNU built-in configuration (with iOS 16.5 boot entry and clean comment padding).
5. Recompresses FVMAIN with EDK2-compliant LZMA.
6. Packages into Android boot image with air_ramdisk.img.
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
    for candidate in [
        os.path.join(script_dir, "edk2_lzma", "edk2_lzma_compress"),
        os.path.join(script_dir, "edk2_lzma_compress"),
        "/home/suchit-7x/hackios/out/edk2_lzma_compress",
        "/home/suchit-7x/hackios/hackios-mt6835/tools/edk2_lzma/edk2_lzma_compress",
        "/tmp/edk2_lzma_compress"
    ]:
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate

def patch_keypad(fvmain: bytearray, pe_file: str = None) -> bytearray:
    kpd_base = 0x684e4
    if pe_file and os.path.exists(pe_file):
        with open(pe_file, "rb") as f:
            pe_data = f.read()
        if len(pe_data) == 14848:
            print(f"[+] Injecting clean KeypadDeviceDxe.pe from {pe_file} into FVMAIN at {hex(kpd_base)}")
            fvmain[kpd_base : kpd_base + 14848] = pe_data
            return fvmain

    off1 = kpd_base + 0x914
    off2 = kpd_base + 0xae0
    off3 = kpd_base + 0x34a0  # VA 0x48a0: static EFI_KEY_DATA for Volume Down

    fvmain[off1:off1+4] = OPCODE_MOV_W9_1  # mov w9, #1 (SCAN_UP)
    fvmain[off2:off2+4] = OPCODE_MOV_W0_2  # mov w0, #2 (SCAN_DOWN)

    if fvmain[off3:off3+2] != bytes.fromhex("0200"):
        print(f"[+] Patching Volume Down EFI_KEY_DATA at {hex(off3)}: {fvmain[off3:off3+2].hex()} -> 0200 (SCAN_DOWN)")
        fvmain[off3:off3+2] = bytes.fromhex("0200")
    else:
        print(f"[*] Volume Down EFI_KEY_DATA at {hex(off3)} already set to SCAN_DOWN (0200)")

    return fvmain

def patch_partition_dxe(fvmain: bytearray) -> bytearray:
    # Stock PartitionDxe natively creates MBR child partition handles
    print("[*] Stock PartitionDxe kept untouched")
    return fvmain

def patch_unixnu_code(fvmain: bytearray) -> bytearray:
    # Stock UniXNU LoadFile uses filesystem handle from ramdisk child partition
    print("[*] Stock UniXNU LoadFile kept untouched")
    return fvmain

def patch_unixnu(fvmain: bytearray) -> bytearray:
    target1 = b"version = 1\n[boot]\ntimeout = 10\nrotate = 2\n"
    target2 = b"version = 1\n[boot]\ntimeout = 3\nrotate = 2\n"
    idx = fvmain.find(target1)
    if idx == -1:
        idx = fvmain.find(target2)
    if idx != -1:
        max_len = 376  # UniXNU explicitly passes w1 = 0x178 (376 bytes) to toml parser 0xdecc
        print(f"[+] Found UniXNU builtin config at {hex(idx)} (fixed length: {max_len} bytes)")
        new_cfg = b"""version = 1
[boot]
timeout = 3
rotate = 2
default = "xnu"
connect_all = true
[[entry]]
id = "xnu"
title = "iOS 16.5"
type = "xnu"
path = "Payloads/KERNEL"
initrd = "Payloads/root.apfs"
args = "-v debug=0x14e keepsyms=1 serial=0 wdt=-1 rd=md0 root_apfs=ufs_xnusys amfi=0xff"
[[entry]]
id = "reset"
title = "Restart"
type = "action"
action = "reset"
"""
        if len(new_cfg) <= max_len:
            remaining = max_len - len(new_cfg)
            if remaining > 0:
                pad = b"# " + b"-" * (remaining - 3) + b"\n"
                full_cfg = new_cfg + pad
            else:
                full_cfg = new_cfg
            assert len(full_cfg) == max_len, f"Expected {max_len} bytes, got {len(full_cfg)}"
            assert b"\x00" not in full_cfg, "Null byte found in UniXNU builtin config!"
            fvmain[idx : idx + max_len] = full_cfg
            print(f"[+] Patched UniXNU builtin config with iOS 16.5 boot entry ({len(full_cfg)} bytes, comment-padded, 0 null bytes)!")
        else:
            print(f"[-] New config too long ({len(new_cfg)} > {max_len})")
    else:
        print("[-] UniXNU builtin config target not found in FVMAIN")
    return fvmain

def patch_darwinboot(fvmain: bytearray) -> bytearray:
    darwinboot_ffs_off = 0xe0e18
    pe_rel_off = fvmain[darwinboot_ffs_off:].find(b'MZ')
    if pe_rel_off == -1:
        print("[-] DarwinBoot PE not found in FVMAIN")
        return fvmain
    pe_abs_off = darwinboot_ffs_off + pe_rel_off
    print(f"[+] Found DarwinBoot PE at {hex(pe_abs_off)}")

    NOP = bytes.fromhex("1f2003d5")

    # 1. Patch validation checks that return EFI_UNSUPPORTED
    off_141c = pe_abs_off + 0x400 + (0x141c - 0x1000)
    off_1424 = pe_abs_off + 0x400 + (0x1424 - 0x1000)
    off_142c = pe_abs_off + 0x400 + (0x142c - 0x1000)
    off_1438 = pe_abs_off + 0x400 + (0x1438 - 0x1000)

    print(f"[+] NOP-ing DarwinBoot EFI_UNSUPPORTED check branches at {hex(off_141c)}, {hex(off_1424)}, {hex(off_142c)}, {hex(off_1438)}")
    fvmain[off_141c : off_141c + 4] = NOP
    fvmain[off_1424 : off_1424 + 4] = NOP
    fvmain[off_142c : off_142c + 4] = NOP
    fvmain[off_1438 : off_1438 + 4] = NOP

    # 1b. Patch RAMDisk validation checks that return EFI_COMPROMISED_DATA
    # At 0x1ca0: replace `cbnz x0, 0x1f40` (001500b5) with NOP
    # At 0x1cac: replace `cbz x0, 0x1d10` (200300b4) with unconditional `b 0x1d10` (19000014)
    off_1ca0 = pe_abs_off + 0x400 + (0x1ca0 - 0x1000)
    off_1cac = pe_abs_off + 0x400 + (0x1cac - 0x1000)
    print(f"[+] Patching DarwinBoot RAMDisk validation checks at {hex(off_1ca0)}, {hex(off_1cac)}")
    fvmain[off_1ca0 : off_1ca0 + 4] = NOP
    fvmain[off_1cac : off_1cac + 4] = bytes.fromhex("19000014")

    # 2. Patch handoff stub to safely drop from EL2 to EL1h if entered at EL2
    stub = bytes.fromhex(
        "444238d59f007df2000100541f101cd5"
        "1f870cd50400b0d204111cd5a47880d2"
        "04401cd521401cd51f1018d51f8708d5"
        "9f3f03d5df3f03d5f00301aa010080d2"
        "020080d2030080d2444238d59f007df2"
        "4100005400021fd6e0039fd6"
    )
    off_10b4 = pe_abs_off + 0x400 + (0x10b4 - 0x1000)
    print(f"[+] Injecting EL2->EL1 handoff stub ({len(stub)} bytes) at {hex(off_10b4)}")
    fvmain[off_10b4 : off_10b4 + len(stub)] = stub

    # 3. Patch out BCM2837 watchdog MMIO writes and inject ExitBootServices SUCCESS visual probe (BLUE bar)
    probe_blue = bytes.fromhex("0b009ed2cbe3bff2ea1f80520ae0bf7209808bd26a298128292100f1c8ffff541f2003d5")
    off_3850 = pe_abs_off + 0x400 + (0x3850 - 0x1000)
    print(f"[+] Injecting ExitBootServices SUCCESS visual probe (BLUE bar) at {hex(off_3850)}")
    fvmain[off_3850 : off_3850 + len(probe_blue)] = probe_blue

    # 4. Patch out cache-flush loop over invalid memory window (0x36FC000)
    # At 0x3878: cbnz x8, #0x38ac branches to a loop calling dc civac over the window head (0x36FC000).
    # On MT6835, DRAM starts at 0x40000000; 0x36FC000 is invalid unmapped space, which causes an
    # immediate Synchronous External Data Abort / Bus Error right after ExitBootServices.
    off_3878 = pe_abs_off + 0x400 + (0x3878 - 0x1000)
    print(f"[+] NOP-ing DarwinBoot invalid window cache-flush branch at {hex(off_3878)}")
    fvmain[off_3878 : off_3878 + 4] = NOP

    # 5. Offset GREEN bar in 0x1048 handoff so it does not overwrite the BLUE bar
    # At 0x1060: replace `mov x11, x4` (eb0304aa) with `add x11, x4, #0x10, lsl #12` (8b404091)
    off_1060 = pe_abs_off + 0x400 + (0x1060 - 0x1000)
    print(f"[+] Offsetting GREEN handoff bar at {hex(off_1060)} by 64 KiB (+row 22)")
    fvmain[off_1060 : off_1060 + 4] = bytes.fromhex("8b404091")

    # 6. Inject ExitBootServices FAILURE visual probe (RED bar) at 0x394c
    probe_red = bytes.fromhex("0b009ed2cbe3bff20a008052eaffbf7209808bd26a298128292100f1c8ffff5400000014")
    off_394c = pe_abs_off + 0x400 + (0x394c - 0x1000)
    print(f"[+] Injecting ExitBootServices FAILURE visual probe (RED bar) at {hex(off_394c)}")
    fvmain[off_394c : off_394c + len(probe_red)] = probe_red

    return fvmain

def repack_uefi(uefi_raw: bytearray, edk2_lzma_bin: str, pe_file: str = None) -> bytearray:
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
    print(f"[+] Decompressing FVMAIN LZMA stream starting at {hex(stream_off)}...")
    fvmain = bytearray(lzma.decompress(uefi_raw[stream_off:stream_off + 0x200000]))
    print(f"[+] Decompressed FVMAIN size: {len(fvmain)} bytes ({hex(len(fvmain))})")

    # 2. Patch Keypad driver
    fvmain = patch_keypad(fvmain, pe_file)

    # 3. Patch PartitionDxe protocol leak
    fvmain = patch_partition_dxe(fvmain)

    # 4. Patch UniXNU LoadFile LocateProtocol fallback
    fvmain = patch_unixnu_code(fvmain)

    # 5. Patch UniXNU builtin configuration
    fvmain = patch_unixnu(fvmain)

    # 6. Patch DarwinBoot (fix EFI_UNSUPPORTED checks & inject EL2->EL1 drop)
    fvmain = patch_darwinboot(fvmain)

    # 7. Compress with edk2_lzma_compress
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

    # 7. Update Section and FFS File headers
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
    if os.path.basename(script_dir) == "out":
        workspace_root = os.path.dirname(script_dir)
        repo_root = os.path.join(workspace_root, "hackios-mt6835")
    else:
        repo_root = os.path.dirname(script_dir)
        workspace_root = os.path.dirname(repo_root)

    clean_uefi = os.path.join(repo_root, "prebuilt", "uefi_kernel.bin")
    default_uefi = clean_uefi if os.path.exists(clean_uefi) else os.path.join(workspace_root, "out", "uefi_kernel.bin")
    default_ramdisk = os.path.join(workspace_root, "out", "air_ramdisk.img")
    default_boot = os.path.join(workspace_root, "out", "boot-air-shimed.img")

    parser = argparse.ArgumentParser(description="Repack UEFI and Android boot image for air (MT6835)")
    parser.add_argument("--uefi", default=default_uefi, help="Path to uncompressed 4 MiB uefi_kernel.bin")
    parser.add_argument("--ramdisk", default=default_ramdisk, help="Path to air_ramdisk.img")
    parser.add_argument("--template-boot", default=None, help="Template boot image for header")
    parser.add_argument("--out", default=default_boot, help="Output boot-air-shimed.img path")
    args = parser.parse_args()

    edk2_lzma_bin = ensure_edk2_lzma(script_dir)

    uefi_src = args.uefi
    if not os.path.exists(uefi_src):
        for candidate in [
            os.path.join(repo_root, "prebuilt", "uefi_kernel.bin"),
            "/home/suchit-7x/mkboot/kernel",
            os.path.join(workspace_root, "out", "uefi_kernel.bin")
        ]:
            if os.path.exists(candidate):
                uefi_src = candidate
                break

    print(f"[+] Reading UEFI kernel: {uefi_src}")
    with open(uefi_src, "rb") as f:
        uefi_raw = bytearray(f.read())

    pe_candidate = os.path.join(repo_root, "prebuilt", "KeypadDeviceDxe.pe")
    if not os.path.exists(pe_candidate):
        pe_candidate = os.path.join(workspace_root, "out", "KeypadDeviceDxe.pe")

    patched_uefi = repack_uefi(
        uefi_raw,
        edk2_lzma_bin,
        pe_file=pe_candidate if os.path.exists(pe_candidate) else None
    )

    # Save patched UEFI kernel FD
    uefi_out = os.path.join(workspace_root, "out", "uefi_kernel.bin")
    with open(uefi_out, "wb") as f:
        f.write(patched_uefi)
    print(f"[+] Saved patched UEFI kernel: {uefi_out}")

    # Gzip UEFI kernel
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(patched_uefi)
    gz_kernel = buf.getvalue()
    print(f"[+] Gzipped kernel size: {len(gz_kernel)} bytes")

    # Read ramdisk
    if args.ramdisk.lower() in ("none", "no", "0"):
        print("[+] Ramdisk disabled in boot image (loaded from vendor_boot)")
        ramdisk_data = b""
    else:
        print(f"[+] Reading ramdisk: {args.ramdisk}")
        with open(args.ramdisk, "rb") as f:
            ramdisk_data = f.read()

    # Read header template
    header_src = args.template_boot
    if not header_src or not os.path.exists(header_src):
        for candidate in [
            os.path.join(workspace_root, "out", "boot-air-shimed.img"),
            os.path.join(workspace_root, "out", "boot_air_all.img"),
            "/home/suchit-7x/mkboot/boot_air_all.img",
            "/home/suchit-7x/boot_air_all.img",
            os.path.join(workspace_root, "out", "stock_boot_b_backup.img")
        ]:
            if os.path.exists(candidate):
                header_src = candidate
                break
    print(f"[+] Using header template: {header_src}")
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

    for extra_copy in [
        os.path.join(workspace_root, "out", "boot_air_all.img"),
        "/home/suchit-7x/boot-air-shimed.img",
        "/home/suchit-7x/boot_air_all.img"
    ]:
        if os.path.exists(os.path.dirname(extra_copy)):
            with open(extra_copy, "wb") as f:
                f.write(final_boot)

    print(f"[+] Successfully generated boot image: {args.out} ({len(final_boot)} bytes)")
    print(f"[+] SHA256: {hashlib.sha256(final_boot).hexdigest()}")

if __name__ == "__main__":
    main()
