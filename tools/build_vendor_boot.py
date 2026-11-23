#!/usr/bin/env python3
import struct, os, hashlib

def build_vendor_boot():
    src_vb = '/home/suchit-7x/firmware/air/vendor_boot.img'
    ramdisk_path = '/home/suchit-7x/hackios/out/air_ramdisk.img'
    out_vb = '/home/suchit-7x/hackios/out/vendor_boot_b.img'

    assert os.path.exists(src_vb), f"Missing {src_vb}"
    assert os.path.exists(ramdisk_path), f"Missing {ramdisk_path}"

    with open(ramdisk_path, 'rb') as f:
        ramdisk_data = f.read()

    rd_sz = len(ramdisk_data)
    print(f'[+] New ramdisk size: {rd_sz} bytes ({rd_sz / (1024*1024):.2f} MiB)')

    with open(src_vb, 'rb') as f:
        hdr = bytearray(f.read(4096))
        magic, v, ps, k_addr, rd_addr, orig_rd_sz = struct.unpack('<8sIIIII', hdr[:28])
        dtb_sz = struct.unpack('<I', hdr[2100:2104])[0]
        v4_tbl_sz = struct.unpack('<I', hdr[2116:2120])[0]
        bootconfig_sz = struct.unpack('<I', hdr[2124:2128])[0]

        orig_rd_pad = (orig_rd_sz + ps - 1) & ~(ps - 1)
        dtb_pad = (dtb_sz + ps - 1) & ~(ps - 1)
        tbl_pad = (v4_tbl_sz + ps - 1) & ~(ps - 1)
        bc_pad = (bootconfig_sz + ps - 1) & ~(ps - 1)

        f.seek(4096 + orig_rd_pad)
        dtb_data = f.read(dtb_sz)
        f.seek(4096 + orig_rd_pad + dtb_pad)
        tbl_data = f.read(v4_tbl_sz)
        f.seek(4096 + orig_rd_pad + dtb_pad + tbl_pad)
        bc_data = f.read(bootconfig_sz) if bootconfig_sz > 0 else b''

    # Update ramdisk size in header
    struct.pack_into('<I', hdr, 24, rd_sz)

    new_rd_pad = (rd_sz + ps - 1) & ~(ps - 1)
    rd_padded = ramdisk_data + b'\x00' * (new_rd_pad - rd_sz)
    dtb_padded = dtb_data + b'\x00' * (dtb_pad - dtb_sz)
    tbl_padded = tbl_data + b'\x00' * (tbl_pad - v4_tbl_sz)
    bc_padded = bc_data + b'\x00' * (bc_pad - bootconfig_sz) if bootconfig_sz > 0 else b''

    final_vb = bytes(hdr) + rd_padded + dtb_padded + tbl_padded + bc_padded

    target_sz = 67108864 # 64 MiB partition size
    if len(final_vb) < target_sz:
        final_vb += b'\x00' * (target_sz - len(final_vb))

    with open(out_vb, 'wb') as f:
        f.write(final_vb)

    print(f'[+] Successfully generated: {out_vb} ({len(final_vb)} bytes)')
    print(f'[+] SHA256: {hashlib.sha256(final_vb).hexdigest()}')

if __name__ == '__main__':
    build_vendor_boot()
