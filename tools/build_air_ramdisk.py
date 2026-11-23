#!/usr/bin/env python3
"""
build_air_ramdisk.py: Build an EDK2-compliant MBR-partitioned 38 MiB FAT32 ramdisk image for air (MT6835).

EDK2's PartitionDxe and FatPkg (EnhancedFatDxe) enforce:
1. Valid MBR partition table at LBA 0 (signature 0x55 0xAA, partition type 0x0C FAT32 LBA).
   Partition 1 starts at LBA 2048 (1 MiB alignment) with 75,776 sectors (37 MiB).
2. Clusters >= 65,525 (CountOfClusters >= 0xfff5). A 37 MiB FAT32 partition with 1 sector/cluster
   gives ~74,500 clusters, comfortably meeting the FAT32 cluster threshold.
3. Canonical FAT32 directory structure with valid SFNs (8.3), valid LFN entries, and ATTR_ARCHIVE (0x20).
4. Clean BPB and FSInfo sectors verified with fsck.fat.
"""

import os
import struct
import subprocess
import hashlib
from pyfatfs.PyFatFS import PyFatFS

UNIXNU_TOML = b"""version = 1

[boot]
timeout = 3
rotate = 2
default = "xnu"
connect_all = true

[ui]
title = "UniXNU - iOS 16.5"
scale = 0
logo = true
layout = "auto"
portrait_below = 1000
console = "auto"

[[entry]]
id = "xnu"
title = "Boot iOS 16.5"
type = "xnu"
path = "Payloads/KERNEL"
initrd = "Payloads/root.apfs"
args = "-v debug=0x14e keepsyms=1 serial=0 -enable_kprintf_spam wdt=-1 rd=md0 root_apfs=ufs_xnusys cs_enforcement_disable=1 amfi_get_out_of_my_way=1 amfi=0xff"

[[entry]]
id = "exit"
title = "Return to firmware"
type = "action"
action = "exit"

[[entry]]
id = "reset"
title = "Restart"
type = "action"
action = "reset"
"""

def build_ramdisk():
    workspace = '/home/suchit-7x/hackios/out'
    kernel_path = os.path.join(workspace, 'mach.development.bcm2837')
    adt_path = os.path.join(workspace, 'KERNEL.adt')
    dtb_path = os.path.join(workspace, 'air.dtb')
    root_apfs_path = os.path.join(workspace, 'root.apfs')
    out_ramdisk = os.path.join(workspace, 'air_ramdisk.img')
    temp_part = os.path.join(workspace, 'temp_part.img')

    assert os.path.exists(kernel_path), f"Kernel missing: {kernel_path}"
    assert os.path.exists(adt_path), f"ADT missing: {adt_path}"
    assert os.path.exists(dtb_path), f"DTB missing: {dtb_path}"
    assert os.path.exists(root_apfs_path), f"Root APFS missing: {root_apfs_path}"

    with open(kernel_path, 'rb') as f: kernel_data = f.read()
    with open(adt_path, 'rb') as f: adt_data = f.read()
    with open(dtb_path, 'rb') as f: dtb_data = f.read()
    with open(root_apfs_path, 'rb') as f: root_apfs_data = f.read()

    print(f"[+] Loaded payload files:")
    print(f"    mach.development.bcm2837: {len(kernel_data)} bytes ({hashlib.sha256(kernel_data).hexdigest()[:16]}...)")
    print(f"    KERNEL.adt:              {len(adt_data)} bytes ({hashlib.sha256(adt_data).hexdigest()[:16]}...)")
    print(f"    air.dtb:                 {len(dtb_data)} bytes ({hashlib.sha256(dtb_data).hexdigest()[:16]}...)")
    print(f"    root.apfs:               {len(root_apfs_data)} bytes ({hashlib.sha256(root_apfs_data).hexdigest()[:16]}...)")

    if os.path.exists(temp_part):
        os.unlink(temp_part)

    # 1. Format raw 37 MiB FAT32 partition
    part_size_kib = 37888  # 37 MiB = 75,776 sectors of 512 bytes
    print(f"[+] Formatting FAT32 partition: {temp_part} ({part_size_kib} KiB / 37 MiB)...")
    cmd = ['mkfs.fat', '-F', '32', '-s', '1', '-n', 'UNIXNU', '-C', temp_part, str(part_size_kib)]
    subprocess.run(cmd, check=True)

    print("[+] Populating FAT32 partition using PyFatFS...")
    with PyFatFS(filename=temp_part) as fs:
        fs.makedirs("/EFI/UniXNU/Payloads")

        print("    -> /EFI/UniXNU/unixnu.toml")
        fs.writebytes("/EFI/UniXNU/unixnu.toml", UNIXNU_TOML)
        print("    -> /unixnu.toml")
        fs.writebytes("/unixnu.toml", UNIXNU_TOML)

        print("    -> /EFI/UniXNU/Payloads/KERNEL")
        fs.writebytes("/EFI/UniXNU/Payloads/KERNEL", kernel_data)
        print("    -> /EFI/UniXNU/Payloads/KERNEL.adt")
        fs.writebytes("/EFI/UniXNU/Payloads/KERNEL.adt", adt_data)
        print("    -> /EFI/UniXNU/Payloads/air.dtb")
        fs.writebytes("/EFI/UniXNU/Payloads/air.dtb", dtb_data)
        print("    -> /EFI/UniXNU/Payloads/root.apfs")
        fs.writebytes("/EFI/UniXNU/Payloads/root.apfs", root_apfs_data)

    print("[+] Setting ATTR_ARCHIVE (0x20) on regular files in FAT32 directory tables...")
    with open(temp_part, 'r+b') as f:
        img = bytearray(f.read())
        tot_sec = struct.unpack_from('<I', img, 32)[0]
        res_sec = struct.unpack_from('<H', img, 14)[0]
        fats = img[16]
        fat_sz = struct.unpack_from('<I', img, 36)[0]
        clus_size = struct.unpack_from('<H', img, 11)[0] * img[13]
        first_data_sec = res_sec + (fats * fat_sz)
        root_clus = struct.unpack_from('<I', img, 44)[0]

        def get_clus_offset(c):
            return (first_data_sec + (c - 2) * img[13]) * 512

        visited = set()
        queue = [root_clus]
        while queue:
            cur_clus = queue.pop(0)
            if cur_clus in visited or cur_clus < 2:
                continue
            visited.add(cur_clus)
            off = get_clus_offset(cur_clus)
            for i in range(0, clus_size, 32):
                ent = img[off + i : off + i + 32]
                if ent[0] == 0:
                    break
                if ent[0] == 0xe5:
                    continue
                attr = ent[11]
                if attr == 0x0f:  # LFN
                    continue
                child_clus = ent[26] | (ent[20] << 16)
                if attr & 0x10:   # Directory
                    sfn = ent[:11]
                    if sfn[:2] != b'. ' and sfn[:2] != b'..':
                        queue.append(child_clus)
                elif attr == 0x00: # Regular file without attributes
                    img[off + i + 11] = 0x20  # Set ATTR_ARCHIVE

        f.seek(0)
        f.write(img)

    print("[+] Running fsck.fat auto-repair to clean FSInfo and cluster chains...")
    subprocess.run(['fsck.fat', '-a', temp_part])
    subprocess.run(['fsck.fat', '-v', temp_part], check=True)

    part_bytes = os.path.getsize(temp_part)
    part_sectors = part_bytes // 512
    assert part_bytes % 512 == 0, "Partition size not sector-aligned!"
    print(f"[+] Clean FAT32 partition: {part_bytes} bytes ({part_sectors} sectors)")

    # 2. Build MBR sector (LBA 0) with Partition 1 starting at LBA 2048
    mbr = bytearray(512)
    # Partition 1 entry at 0x1BE (16 bytes)
    struct.pack_into("<BBBBBBBBII", mbr, 0x1be,
        0x80,             # Boot indicator (active/bootable)
        0x00, 0x20, 0x21, # Start CHS
        0x0c,             # Partition type 0x0C (FAT32 with LBA)
        0xfe, 0xff, 0xff, # End CHS
        2048,             # Starting LBA (1 MiB alignment)
        part_sectors      # Sector count
    )
    mbr[510] = 0x55
    mbr[511] = 0xaa

    # 3. Assemble full MBR disk: LBA 0 (MBR) + LBA 1..2047 (Padding) + LBA 2048.. (FAT32 partition)
    print(f"[+] Assembling full partitioned disk image: {out_ramdisk}...")
    with open(out_ramdisk, 'wb') as f_out:
        f_out.write(mbr)
        f_out.write(b"\x00" * (2047 * 512))  # 1 MiB alignment padding
        with open(temp_part, 'rb') as f_in:
            while chunk := f_in.read(1024 * 1024):
                f_out.write(chunk)
        f_out.write(b"\x00" * (2048 * 512))  # 1 MiB trailing slack (guarantees EndingLBA < LastLBA)

    if os.path.exists(temp_part):
        os.unlink(temp_part)

    total_disk_bytes = os.path.getsize(out_ramdisk)
    total_disk_sectors = total_disk_bytes // 512
    print(f"[+] Total MBR disk size: {total_disk_bytes} bytes ({total_disk_sectors} sectors / {total_disk_bytes // (1024*1024)} MiB)")

    # 4. Verify MBR partition table with fdisk
    out = subprocess.run(['fdisk', '-l', out_ramdisk], capture_output=True, text=True).stdout
    print(out)

    # 5. Verify filesystem at partition offset 1 MiB (1,048,576 bytes)
    with open(out_ramdisk, 'rb') as f:
        f.seek(1048576)
        sec0 = f.read(512)
    tot_sec = struct.unpack_from('<I', sec0, 32)[0]
    res_sec = struct.unpack_from('<H', sec0, 14)[0]
    fats = sec0[16]
    fat_sz = struct.unpack_from('<I', sec0, 36)[0]
    data_sec = tot_sec - (res_sec + fats * fat_sz)
    clusters = data_sec // sec0[13]
    print(f"[+] Partition FAT32 clusters: {clusters} (required >= 65525: {clusters >= 65525})")
    assert clusters >= 65525, "Cluster count too small!"

    with PyFatFS(filename=out_ramdisk, offset=1048576) as fs:
        assert fs.readbytes("/EFI/UniXNU/unixnu.toml") == UNIXNU_TOML
        assert hashlib.sha256(fs.readbytes("/EFI/UniXNU/Payloads/KERNEL")).hexdigest() == hashlib.sha256(kernel_data).hexdigest()
        assert hashlib.sha256(fs.readbytes("/EFI/UniXNU/Payloads/KERNEL.adt")).hexdigest() == hashlib.sha256(adt_data).hexdigest()
        assert hashlib.sha256(fs.readbytes("/EFI/UniXNU/Payloads/air.dtb")).hexdigest() == hashlib.sha256(dtb_data).hexdigest()
        assert hashlib.sha256(fs.readbytes("/EFI/UniXNU/Payloads/root.apfs")).hexdigest() == hashlib.sha256(root_apfs_data).hexdigest()

    print(f"[+] 100% VERIFIED MBR DISK: {out_ramdisk} ({total_disk_bytes} bytes)")
    print(f"[+] SHA256: {hashlib.sha256(open(out_ramdisk, 'rb').read()).hexdigest()}")

if __name__ == '__main__':
    build_ramdisk()
