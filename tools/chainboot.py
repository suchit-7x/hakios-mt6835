#!/usr/bin/env python3
"""
Put a bare-metal program in front of Android's kernel in a boot image.
Supports Boot Image Header v2 and Header v4 (GKI/modern MediaTek like MT6835).

  chainboot.py <android-boot.img> <program.bin> <out.img> [payload.bin]

LK decompresses the kernel to RAM and enters it there. The new kernel is:
program.bin, padded to CHAIN_OFFSET, then Android's own (uncompressed) Image. The program runs
first and then moves the Image down over itself and starts it (mtkloader/fbdiag.c). An optional
payload (mtkloader's "XNUP") follows the Image, 16-aligned. The program's own arm64 header gets
the Image's length in res2 (0x28), the payload's offset in res3 (0x30) and a covering image_size.
"""
import gzip
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

CHAIN_OFFSET = 0x40000
BOOT_PARTITION_DEFAULT = 64 << 20


def pad(b, n):
    return b + b'\0' * (-len(b) % n)


def decompress_kernel(data):
    if data[:4] == b'\x02!L\x18':  # LZ4 legacy magic (0x184C2102)
        with tempfile.NamedTemporaryFile(delete=False) as fin, tempfile.NamedTemporaryFile(delete=False) as fout:
            fin.write(data)
            fin.close()
            fout.close()
            try:
                subprocess.check_call(['magiskboot', 'decompress', fin.name, fout.name], stdout=subprocess.DEVNULL)
                decomp = open(fout.name, 'rb').read()
            finally:
                try: os.unlink(fin.name)
                except OSError: pass
                try: os.unlink(fout.name)
                except OSError: pass
            return decomp
    elif data[:2] == b'\x1f\x8b':  # gzip
        return gzip.decompress(data)
    else:
        return data


def repack_v4(src_boot, blob, out_img):
    out_abs = os.path.abspath(out_img)
    src_abs = os.path.abspath(src_boot)
    workdir = tempfile.mkdtemp(prefix='chainboot_v4_')
    try:
        subprocess.check_call(['magiskboot', 'unpack', src_abs], cwd=workdir, stdout=subprocess.DEVNULL)
        with open(os.path.join(workdir, 'kernel'), 'wb') as f:
            f.write(blob)
        subprocess.check_call(['magiskboot', 'repack', src_abs, out_abs], cwd=workdir, stdout=subprocess.DEVNULL)
    finally:
        shutil.rmtree(workdir)


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <android-boot.img> <program.bin> <out.img> [payload.bin]", file=sys.stderr)
        sys.exit(1)

    src, prog_path, out = sys.argv[1:4]
    payload = open(sys.argv[4], 'rb').read() if len(sys.argv) > 4 else b''
    d = open(src, 'rb').read()
    assert d[:8] == b'ANDROID!', 'not an Android boot image'
    hver = struct.unpack_from('<I', d, 40)[0]

    prog = bytearray(open(prog_path, 'rb').read())
    assert prog[0x38:0x3c] == b'ARM\x64', 'program has no arm64 header'
    assert len(prog) <= CHAIN_OFFSET, f'program too large ({len(prog)} > {CHAIN_OFFSET})'

    if hver == 4:
        ksize = struct.unpack_from('<I', d, 8)[0]
        page = 4096
        raw_kernel = d[page:page + ksize]
        image = decompress_kernel(raw_kernel)
        assert image[0x38:0x3c] == b'ARM\x64', 'Android kernel is not an arm64 Image'
        linux_image_size = struct.unpack_from('<Q', image, 0x10)[0]

        payload_off = CHAIN_OFFSET + len(pad(image, 16)) if payload else 0
        total = max(CHAIN_OFFSET + linux_image_size, payload_off + len(payload))
        struct.pack_into('<Q', prog, 0x08, 0) # text_offset = 0 for MT6835 / GKI
        struct.pack_into('<Q', prog, 0x10, (total + 0xfffff) & ~0xfffff)
        struct.pack_into('<Q', prog, 0x28, len(image))
        struct.pack_into('<Q', prog, 0x30, payload_off)

        blob = bytes(prog) + b'\0' * (CHAIN_OFFSET - len(prog)) + image
        if payload:
            blob = pad(blob, 16) + payload

        repack_v4(src, blob, out)
        out_size = os.path.getsize(out)
        print(f'{out}: {out_size} bytes [v4] (program {len(prog)}, Image {len(image)}, payload {len(payload)}, blob {len(blob)})')
        return

    elif hver == 2:
        ksize, _, rsize, _, ssize, _, _, page, _ = struct.unpack_from('<9I', d, 8)
        rdo_size = struct.unpack_from('<I', d, 1632)[0]
        dtb_size = struct.unpack_from('<I', d, 1648)[0]

        def pages(n):
            return (n + page - 1) // page * page

        off = page
        kernel = d[off:off + ksize]; off += pages(ksize)
        ramdisk = d[off:off + rsize]; off += pages(rsize)
        second = d[off:off + ssize]; off += pages(ssize)
        rdo = d[off:off + rdo_size]; off += pages(rdo_size)
        dtb = d[off:off + dtb_size]

        image = decompress_kernel(kernel)
        assert image[0x38:0x3c] == b'ARM\x64', 'Android kernel is not an arm64 Image'
        linux_image_size = struct.unpack_from('<Q', image, 0x10)[0]

        payload_off = CHAIN_OFFSET + len(pad(image, 16)) if payload else 0
        total = max(CHAIN_OFFSET + linux_image_size, payload_off + len(payload))
        struct.pack_into('<Q', prog, 0x08, 0) # text_offset = 0 for MT6835 / GKI
        struct.pack_into('<Q', prog, 0x10, (total + 0xfffff) & ~0xfffff)
        struct.pack_into('<Q', prog, 0x28, len(image))
        struct.pack_into('<Q', prog, 0x30, payload_off)
        blob = bytes(prog) + b'\0' * (CHAIN_OFFSET - len(prog)) + image
        if payload:
            blob = pad(blob, 16) + payload
        new_kernel = gzip.compress(blob, 9, mtime=0)

        hdr = bytearray(d[:page])
        struct.pack_into('<I', hdr, 8, len(new_kernel))
        sha = hashlib.sha1()
        for part in (new_kernel, ramdisk, second, rdo, dtb):
            sha.update(part)
            sha.update(struct.pack('<I', len(part)))
        hdr[576:608] = pad(sha.digest(), 32)

        img = bytes(hdr) + pad(new_kernel, page) + pad(ramdisk, page) + pad(second, page) + pad(rdo, page) + pad(dtb, page)
        boot_partition = len(d) if len(d) > (32 << 20) else (32 << 20)
        if len(img) > boot_partition:
            raise SystemExit(f'{out}: {len(img)} bytes, more than the {boot_partition} of the boot partition '
                             f'({len(img) - boot_partition} too many): the payload has to shrink')
        open(out, 'wb').write(img)
        print(f'{out}: {len(img)} bytes [v2] (program {len(prog)}, Image {len(image)}, payload {len(payload)}, kernel gz {len(new_kernel)})')
        return

    else:
        raise SystemExit(f'Unsupported header version: v{hver}')


if __name__ == '__main__':
    main()
