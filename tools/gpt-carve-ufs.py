#!/usr/bin/env python3
"""
gpt-carve-ufs.py: Carve 4 GiB from userdata partition for 'xnusys'
on UFS storage devices with 4096-byte logical sectors.
"""
import binascii
import struct
import sys
import uuid

SECTOR = 4096
SHRINK = "userdata"
NEW_NAME = "xnusys"
NEW_SECTORS = (4 * 1024 * 1024 * 1024) // SECTOR  # 4 GiB = 1,048,576 sectors
NEW_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")  # Linux filesystem data
ALIGN = (1 * 1024 * 1024) // SECTOR              # 1 MiB = 256 sectors

def crc32(b):
    return binascii.crc32(b) & 0xffffffff

def name_of(entry):
    return entry[56:128].decode("utf-16-le").rstrip("\0")

def parse_header(hdr):
    sig, rev, hsize, hcrc, _, mylba, altlba, first, last = struct.unpack_from("<8sIIIIQQQQ", hdr, 0)
    guid = hdr[56:72]
    entlba, nent, entsize, entcrc = struct.unpack_from("<QIII", hdr, 72)
    assert sig == b"EFI PART", f"Not a GPT header (signature {sig})"
    return dict(rev=rev, hsize=hsize, mylba=mylba, altlba=altlba, first=first, last=last,
                guid=guid, entlba=entlba, nent=nent, entsize=entsize, hcrc=hcrc, entcrc=entcrc)

def build_header(h, entries, mylba, altlba, entlba):
    out = bytearray(h["hsize"])
    struct.pack_into("<8sIIII", out, 0, b"EFI PART", h["rev"], h["hsize"], 0, 0)
    struct.pack_into("<QQQQ", out, 24, mylba, altlba, h["first"], h["last"])
    out[56:72] = h["guid"]
    struct.pack_into("<QIII", out, 72, entlba, h["nent"], h["entsize"], crc32(entries))
    struct.pack_into("<I", out, 16, crc32(bytes(out)))
    return bytes(out) + b"\0" * (SECTOR - len(out) % SECTOR if len(out) % SECTOR else 0)

def carve(pri_data: bytearray, sec_data: bytearray, total_sectors: int):
    # Parse primary header at LBA 1
    hdr_bytes = pri_data[SECTOR : 2 * SECTOR]
    h = parse_header(hdr_bytes)
    esz, nent = h["entsize"], h["nent"]
    
    ents_start = h["entlba"] * SECTOR
    ents_len = nent * esz
    ents = pri_data[ents_start : ents_start + ents_len]
    assert crc32(bytes(ents)) == h["entcrc"], "Entry array CRC mismatch"
    assert h["altlba"] == total_sectors - 1, f"Backup header at {h['altlba']}, total {total_sectors}"

    entries = [bytearray(ents[i * esz : (i + 1) * esz]) for i in range(nent)]
    used = [(name_of(e), *struct.unpack_from("<QQ", e, 32)) for e in entries if e[0:16] != b"\0" * 16]
    print(f"[+] Found {len(used)} existing partitions in table of {nent} entries")

    victim_idx = next(i for i, e in enumerate(entries) if name_of(e) == SHRINK)
    vstart, vend = struct.unpack_from("<QQ", entries[victim_idx], 32)
    vsize_gib = (vend - vstart + 1) * SECTOR / (1024**3)
    print(f"[+] Partition '{SHRINK}' (entry {victim_idx}): {vstart}..{vend} ({vsize_gib:.2f} GiB)")

    new_start = (vend + 1 - NEW_SECTORS) & ~(ALIGN - 1)
    new_end = vend
    assert new_start > vstart + ALIGN, "Not enough space in partition to shrink"

    # Extend entry array by 1 entry
    new_entry = bytearray(esz)
    entries.append(new_entry)
    free_idx = len(entries) - 1
    h["nent"] = len(entries)

    # Shrink userdata
    struct.pack_into("<QQ", entries[victim_idx], 32, vstart, new_start - 1)
    
    # Configure new partition (xnusys)
    e = entries[free_idx]
    e[0:16] = NEW_TYPE.bytes_le
    e[16:32] = uuid.uuid4().bytes_le
    struct.pack_into("<QQQ", e, 32, new_start, new_end, 0)
    e[56:128] = NEW_NAME.encode("utf-16-le").ljust(72, b"\0")

    shrunk_gib = (new_start - vstart) * SECTOR / (1024**3)
    new_gib = (new_end - new_start + 1) * SECTOR / (1024**3)
    print(f"[+] Shrunk '{SHRINK}': {vstart}..{new_start - 1} ({shrunk_gib:.2f} GiB)")
    print(f"[+] Created '{NEW_NAME}' (entry {free_idx}): {new_start}..{new_end} ({new_gib:.2f} GiB)")

    new_ents = b"".join(bytes(x) for x in entries)
    ents_padded_len = (len(new_ents) + SECTOR - 1) & ~(SECTOR - 1)
    new_ents_padded = new_ents + b"\0" * (ents_padded_len - len(new_ents))

    # Update primary GPT
    pri_out = bytearray(pri_data)
    pri_out[h["entlba"] * SECTOR : h["entlba"] * SECTOR + len(new_ents_padded)] = new_ents_padded
    pri_out[SECTOR : 2 * SECTOR] = build_header(h, new_ents, 1, total_sectors - 1, h["entlba"])

    # Update secondary GPT
    sec_out = bytearray(sec_data)
    h_sec = parse_header(sec_data[len(sec_data) - SECTOR : len(sec_data)])
    sec_entlba = h_sec["entlba"]
    sec_base_lba = total_sectors - (len(sec_data) // SECTOR)
    sec_entries_off = (sec_entlba - sec_base_lba) * SECTOR
    sec_out[sec_entries_off : sec_entries_off + len(new_ents_padded)] = new_ents_padded
    sec_out[len(sec_out) - SECTOR :] = build_header(h, new_ents, total_sectors - 1, 1, sec_entlba)

    return pri_out, sec_out

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: gpt-carve-ufs.py <primary.bin> <secondary.bin> <total-sectors>")
        sys.exit(1)
    
    pri_p, sec_p, tot = sys.argv[1], sys.argv[2], int(sys.argv[3])
    p_data = bytearray(open(pri_p, "rb").read())
    s_data = bytearray(open(sec_p, "rb").read())
    
    new_p, new_s = carve(p_data, s_data, tot)
    open(pri_p + ".new", "wb").write(new_p)
    open(sec_p + ".new", "wb").write(new_s)
    print(f"[+] Saved: {pri_p}.new and {sec_p}.new")
