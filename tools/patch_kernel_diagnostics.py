#!/usr/bin/env python3
import subprocess, os, struct

def assemble(code):
    with open('/tmp/asm_probe.s', 'w') as f:
        f.write('.text\n' + code + '\n')
    subprocess.check_call(['aarch64-linux-gnu-as', '/tmp/asm_probe.s', '-o', '/tmp/asm_probe.o'])
    raw = subprocess.check_output(['aarch64-linux-gnu-objcopy', '-O', 'binary', '/tmp/asm_probe.o', '/tmp/asm_probe.bin'])
    with open('/tmp/asm_probe.bin', 'rb') as f:
        return f.read()

def assemble_with_symbols(code):
    with open('/tmp/asm_sym.s', 'w') as f:
        f.write('.text\n' + code + '\n')
    subprocess.check_call(['aarch64-linux-gnu-as', '/tmp/asm_sym.s', '-o', '/tmp/asm_sym.o'])
    subprocess.check_output(['aarch64-linux-gnu-objcopy', '-O', 'binary', '/tmp/asm_sym.o', '/tmp/asm_sym.bin'])
    with open('/tmp/asm_sym.bin', 'rb') as f:
        bin_data = bytearray(f.read())
    nm_out = subprocess.check_output(['aarch64-linux-gnu-nm', '-t', 'd', '/tmp/asm_sym.o']).decode()
    symbols = {}
    for line in nm_out.strip().splitlines():
        parts = line.split()
        if len(parts) == 3:
            symbols[parts[2]] = int(parts[0])
    return bin_data, symbols

def calc_b(src, dst):
    diff = dst - src
    imm26 = (diff >> 2) & 0x03ffffff
    op = 0x14000000 | imm26
    return op.to_bytes(4, 'little')

def calc_bl(src, dst):
    diff = dst - src
    imm26 = (diff >> 2) & 0x03ffffff
    op = 0x94000000 | imm26
    return op.to_bytes(4, 'little')

def calc_adrp(pc, target_page, rd):
    pc_page = pc & ~0xfff
    target_page = target_page & ~0xfff
    diff_pages = (target_page - pc_page) >> 12
    immlo = diff_pages & 3
    immhi = (diff_pages >> 2) & 0x7ffff
    op = 0x90000000 | (immlo << 29) | (immhi << 5) | rd
    return op.to_bytes(4, 'little')

def main():
    out_dir = os.environ.get('OUT_DIR')
    if not out_dir:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(script_dir, '../../out')
        if os.path.isdir(candidate):
            out_dir = os.path.abspath(candidate)
        else:
            out_dir = '/home/suchit-7x/hackios/out'

    kernel_orig = os.path.join(out_dir, 'mach.development.bcm2837.orig')
    kernel_out = os.path.join(out_dir, 'mach.development.bcm2837')

    assert os.path.exists(kernel_orig), f"Missing {kernel_orig}"
    with open(kernel_orig, 'rb') as f:
        data = bytearray(f.read())

    print("[*] Applying clean XNU patches for REDMI 13C 5G (MT6835 / air)...")

    # 1. Kernel entry probe (PURPLE bar) at 0x41A4B4A8 (offset 0x4474a8)
    branch_entry = assemble('''
        b target
    .space 11148
    target:
    ''')[:4]
    entry_bytes = assemble('''
        nop
        mov x11, #0xf000
        movk x11, #0xff21, lsl #16
        mov w10, #0xff
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''') + branch_entry
    assert len(entry_bytes) == 40
    data[0x4474a8 : 0x4474a8 + 40] = entry_bytes
    print("[+] Injected PURPLE entry probe at 0x4474a8")

    # 2. Checkpoint 3 (YELLOW bar + TTBR0 1GB mapping of 0xC0000000..0xFFFFFFFF) at 0x41A4E2E4 (offset 0x44a2e4)
    branch_cp3 = assemble('''
        b target
    .space 16
    target:
    ''')[:4]
    cp3_body = assemble('''
        mov x10, #0x605
        movk x10, #0xc000, lsl #16
        str x10, [x25, #0x18]
        mov x11, #0xf000
        movk x11, #0xff22, lsl #16
        mov w10, #0xff00
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    cp3_bytes = cp3_body + branch_cp3 + bytes.fromhex('1f2003d5' * 4) # 44 + 4 + 16 = 64 bytes
    assert len(cp3_bytes) == 64
    data[0x44a2e4 : 0x44a2e4 + 64] = cp3_bytes
    print("[+] Injected YELLOW probe + TTBR0 mapping at 0x44a2e4")

    # 3. Checkpoint 4 (ORANGE bar, before MMU enable) at 0x41A4E3D8 (offset 0x44a3d8)
    branch_cp4 = assemble('''
        b target
    .space 24
    target:
    ''')[:4]
    cp4_body = assemble('''
        mov x11, #0xf000
        movk x11, #0xff23, lsl #16
        mov w10, #0xa500
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    cp4_bytes = cp4_body + branch_cp4 + bytes.fromhex('1f2003d5' * 6) # 32 + 4 + 24 = 60 bytes
    assert len(cp4_bytes) == 60
    data[0x44a3d8 : 0x44a3d8 + 60] = cp4_bytes
    print("[+] Injected ORANGE probe at 0x44a3d8")

    # 4. Checkpoint 5 (WHITE bar, after MMU enable) at 0x41A4E430 (offset 0x44a430)
    branch_cp5 = assemble('''
        b target
    .space 24
    target:
    ''')[:4]
    cp5_body = assemble('''
        mov x11, #0xf000
        movk x11, #0xff24, lsl #16
        mov w10, #0xffff
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    cp5_bytes = cp5_body + branch_cp5 + bytes.fromhex('1f2003d5' * 6) # 32 + 4 + 24 = 60 bytes
    assert len(cp5_bytes) == 60
    data[0x44a430 : 0x44a430 + 60] = cp5_bytes
    print("[+] Injected WHITE probe at 0x44a430")

    # 5. Exit start.s (CYAN bar + ADT injection) at 0x41A4B4D0 (offset 0x4474d0) and branch from 0x41A4E4A8 (offset 0x44a4a8)
    adt_path = os.path.join(out_dir, 'KERNEL.adt')
    with open(adt_path, 'rb') as f:
        adt_data = bytearray(f.read())
    assert len(adt_data) == 14048, f"Unexpected ADT length: {len(adt_data)}"

    # Pre-populate RAMDisk (phys_base=0x69500000, size=4 MiB) at offset 0x2984 in embedded ADT
    struct.pack_into('<Q', adt_data, 0x2984, 0x69500000)
    struct.pack_into('<Q', adt_data, 0x298c, 0x400000)
    print(f"[+] Embedded RAMDisk in ADT: phys_base=0x69500000, size=0x400000 (4 MiB)")

    data[0xb20000 : 0xb20000 + len(adt_data)] = adt_data
    print(f"[+] Embedded KERNEL.adt ({len(adt_data)} bytes) at file offset 0xb20000 (KVA 0xfffffff007f9c000)")

    cyan_bytes = assemble('''
        /* Paint Cyan bar at 0xff25_f000 */
        mov x11, #0xf000
        movk x11, #0xff25, lsl #16
        mov w10, #0xffff
        movk w10, #0xff00, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b

        /* 1. Retrieve DarwinBoot RAMDisk from old deviceTreeP at [x20, #0x60] */
        ldr x7, [x20, #0x60]        /* Bootloader deviceTreeP (physical address) */
        cbz x7, 2f
        mov x8, #0x0000
        movk x8, #0x4000, lsl #16   /* DRAM base threshold 0x40000000 */
        cmp x7, x8
        b.lo 2f
        mov x8, #0x2984             /* Exact offset of RAMDisk in KERNEL.adt */
        ldr x12, [x7, x8]           /* phys_base from DarwinBoot */
        add x8, x8, #8
        ldr x13, [x7, x8]           /* size from DarwinBoot */
        cbz x13, 2f
        /* Store dynamic RAMDisk (phys_base, size) into embedded ADT in KVA (0xfffffff007f9c000 + 0x2984) */
        mov x8, #0xc000
        movk x8, #0x07f9, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        mov x9, #0x2984
        add x8, x8, x9
        stp x12, x13, [x8]
    2:
        /* Inject embedded KERNEL.adt into boot_args at x20 */
        /* Exact KVA 0xfffffff007f9c000 */
        mov x8, #0xc000
        movk x8, #0x07f9, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        str x8, [x20, #0x60]

        mov w8, #0x36e0
        str w8, [x20, #0x68]

        /* Force boot_args->Video.v_display = 0 (Text Mode) and clean geometry */
        str xzr, [x20, #0x30]
        mov x8, #2944
        str x8, [x20, #0x38]
        mov x8, #720
        str x8, [x20, #0x40]
        mov x8, #1600
        str x8, [x20, #0x48]
        mov x8, #32
        str x8, [x20, #0x50]

        /* Return to arm_init in KVA */
        add x0, x20, x22
        sub x0, x0, x23
        ret
    ''')
    assert len(cyan_bytes) <= 512
    data[0x4474d0 : 0x4474d0 + len(cyan_bytes)] = cyan_bytes
    branch_to_cyan = assemble('''
    target:
    .space 12248
    _branch:
        b target
    ''')[12248:12252]
    data[0x44a4a8 : 0x44a4a8 + 4] = branch_to_cyan
    data[0x44a4ac : 0x44a4ac + 8] = bytes.fromhex('1f2003d5' * 2) # NOP out old sub and ret
    print("[+] Injected CYAN probe + ADT injection at 0x4474d0 and hooked start.s exit at 0x44a4a8")

    # Injected arm_init diagnostic probes in the NOP region:
    # 5a. Probe 2: arm_init entry boot_args memory clamp at file offset 0x447590
    probe2_body = assemble('''
        mov x8, #0x0000
        movk x8, #0xb000, lsl #16
        str x8, [x0, #24]         // boot_args->memSize = 0xb0000000 (2816 MB)
        str x8, [x0, #728]        // boot_args->memSizeActual = 0xb0000000 (2816 MB)
        mov x19, x0
    ''')
    b_back_probe2 = calc_b(0x447590 + len(probe2_body), 0x43c818)
    probe2 = probe2_body + b_back_probe2
    assert len(probe2) <= 48
    probe2_full = probe2 + (b'\x1f\x20\x03\xd5' * ((48 - len(probe2)) // 4))
    data[0x447590 : 0x447590 + 48] = probe2_full
    data[0x43c814 : 0x43c818] = calc_b(0x43c814, 0x447590)
    print("[+] Injected boot_args memSize=0xb0000000 clamp at arm_init entry (0x447590, hooked 0x43c814)")

    # 5b. Probe 3: PE_init_platform (MAGENTA before at 0xff27f000, LIME after at 0xff28f000) at file offset 0x4475c0
    probe3_part1 = assemble('''
        stp x29, x30, [sp, #-16]!
        mov x11, #0xf000
        movk x11, #0xff27, lsl #16
        mov w10, #0x00ff
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    bl_pe_init = calc_bl(0x4475c0 + len(probe3_part1), 0xa4ddf4)
    probe3_part2 = assemble('''
        mov x11, #0xf000
        movk x11, #0xff28, lsl #16
        mov w10, #0xff00
        movk w10, #0xff00, lsl #16
        mov x9, #0x5c00
    2:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 2b
        ldp x29, x30, [sp], #16
        ret
    ''')
    probe3 = probe3_part1 + bl_pe_init + probe3_part2
    assert len(probe3) == 80
    data[0x4475c0 : 0x4475c0 + len(probe3)] = probe3
    data[0x43ccd4 : 0x43ccd8] = calc_bl(0x43ccd4, 0x4475c0)
    print("[+] Injected MAGENTA/LIME probe around PE_init_platform (0x4475c0, hooked 0x43ccd4)")

    # 5c. Probe 4: After /chosen lookup (BLUE bar at 0xff29f000) at file offset 0x447610
    probe4_body = assemble('''
        mov x11, #0xf000
        movk x11, #0xff29, lsl #16
        mov w10, #0x00ff
        movk w10, #0xff00, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
        ldr x0, [sp, #56]
    ''')
    b_back_probe4 = calc_b(0x447610 + len(probe4_body), 0x43cd38)
    probe4 = probe4_body + b_back_probe4
    assert len(probe4) == 40
    data[0x447610 : 0x447610 + len(probe4)] = probe4
    data[0x43cd34 : 0x43cd38] = calc_b(0x43cd34, 0x447610)
    print("[+] Injected BLUE probe after /chosen lookup (0x447610, hooked 0x43cd34)")

    # 5d. Probe 5: arm_vm_init (ORANGE bar at 0xff2af000) at file offset 0x447640
    probe5_part1 = assemble('''
        stp x29, x30, [sp, #-16]!
        mov x11, #0xf000
        movk x11, #0xff2a, lsl #16
        mov w10, #0xa500
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    bl_vm_init = calc_bl(0x447640 + len(probe5_part1), 0x43e618)
    probe5_part2 = assemble('''
        ldp x29, x30, [sp], #16
        ret
    ''')
    probe5 = probe5_part1 + bl_vm_init + probe5_part2
    assert len(probe5) == 48
    data[0x447640 : 0x447640 + len(probe5)] = probe5
    data[0x43cf38 : 0x43cf3c] = calc_bl(0x43cf38, 0x447640)
    print("[+] Injected ORANGE probe before arm_vm_init (0x447640, hooked 0x43cf38)")

    # 5e. Probe 5b: Inside arm_vm_init before MMU alternate switch (PINK bar at 0xff2bf000) at file offset 0x447670
    part1_alt = assemble('''
        stp x29, x30, [sp, #-16]!
        mov x11, #0xf000
        movk x11, #0xff2b, lsl #16
        mov w10, #0x007f
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    bl_alt = calc_bl(0x447670 + len(part1_alt), 0x44ec54)
    part2_alt = assemble('''
        ldp x29, x30, [sp], #16
    ''')
    b_back_alt = calc_b(0x447670 + len(part1_alt) + 4 + len(part2_alt), 0x43f21c)
    probe5_alt = part1_alt + bl_alt + part2_alt + b_back_alt
    assert len(probe5_alt) <= 64
    data[0x447670 : 0x447670 + len(probe5_alt)] = probe5_alt
    data[0x43f218 : 0x43f21c] = calc_b(0x43f218, 0x447670)
    print("[+] Injected PINK probe before set_mmu_ttb_alternate at 0x447670 (hooked 0x43f218)")

    # 5f. Probe 5c: TTBR0 mapping persist + Cyan bar at 0xff2cf000 at file offset 0x4476b0
    part1_ttbr0 = assemble('''
        stp x29, x30, [sp, #-16]!
        ldr x10, [x19, #-8]
        mov x11, #0x605
        movk x11, #0xc000, lsl #16
        str x11, [x10, #0x18]
        ldr x8, [x19]
        and x0, x8, #0xffffffffffff
    ''')
    bl_set_mmu = calc_bl(0x4476b0 + len(part1_ttbr0), 0x44ec64)
    part2_ttbr0 = assemble('''
        tlbi vmalle1is
        dsb ish
        isb
        mov x11, #0xf000
        movk x11, #0xff2c, lsl #16
        mov w10, #0xffff
        movk w10, #0xff00, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
        ldp x29, x30, [sp], #16
    ''')
    b_back_ttbr0 = calc_b(0x4476b0 + len(part1_ttbr0) + 4 + len(part2_ttbr0), 0x43f240)
    probe_ttbr0 = part1_ttbr0 + bl_set_mmu + part2_ttbr0 + b_back_ttbr0
    assert len(probe_ttbr0) <= 96
    data[0x4476b0 : 0x4476b0 + len(probe_ttbr0)] = probe_ttbr0
    data[0x43f228 : 0x43f22c] = calc_b(0x43f228, 0x4476b0)
    data[0x43f22c : 0x43f240] = bytes.fromhex('1f2003d5' * 5)
    print("[+] Injected TTBR0 persistence + CYAN probe at 0x4476b0 (hooked 0x43f228)")

    # 5g. Probe 6: Return from arm_vm_init (YELLOW bar at 0xff2df000) at file offset 0x447710
    body_vm_exit = assemble('''
        mov x11, #0xf000
        movk x11, #0xff2d, lsl #16
        mov w10, #0xff00
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    b_back_vm_exit = calc_b(0x447710 + len(body_vm_exit), 0x43cf44)
    probe_vm_exit = body_vm_exit + b_back_vm_exit
    assert len(probe_vm_exit) <= 48
    data[0x447710 : 0x447710 + len(probe_vm_exit)] = probe_vm_exit
    data[0x43cf3c : 0x43cf40] = calc_b(0x43cf3c, 0x447710)
    data[0x43cf40 : 0x43cf44] = bytes.fromhex('1f2003d5')
    print("[+] Injected YELLOW probe at arm_vm_init return at 0x447710 (hooked 0x43cf3c)")

    # 5h. Probe 7: After serial_init (WHITE bar at 0xff2ef000) at file offset 0x447740
    body_serial_exit = assemble('''
        mov x19, x0
        mov x11, #0xf000
        movk x11, #0xff2e, lsl #16
        mov w10, #0xffff
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    b_back_serial_exit = calc_b(0x447740 + len(body_serial_exit), 0x43cf6c)
    probe_serial_exit = body_serial_exit + b_back_serial_exit
    assert len(probe_serial_exit) <= 48
    data[0x447740 : 0x447740 + len(probe_serial_exit)] = probe_serial_exit
    data[0x43cf60 : 0x43cf64] = calc_b(0x43cf60, 0x447740)
    data[0x43cf64 : 0x43cf6c] = bytes.fromhex('1f2003d5' * 2)
    print("[+] Injected WHITE probe after serial_init at 0x447740 (hooked 0x43cf60)")

    # 5i. Probe 8: Right before PE_create_console (PURPLE bar at 0xff2ff000) at file offset 0x447770
    body_before_console = assemble('''
        str wzr, [x8]
        mov x11, #0xf000
        movk x11, #0xff2f, lsl #16
        mov w10, #0x00ff
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    b_back_before_console = calc_b(0x447770 + len(body_before_console), 0x43d09c)
    probe_before_console = body_before_console + b_back_before_console
    assert len(probe_before_console) <= 48
    data[0x447770 : 0x447770 + len(probe_before_console)] = probe_before_console
    data[0x43d098 : 0x43d09c] = calc_b(0x43d098, 0x447770)
    print("[+] Injected PURPLE probe before PE_create_console at 0x447770 (hooked 0x43d098)")

    # 5j. Probe 9: Right after PE_create_console (LIME bar at 0xff30f000) at file offset 0x4477a0
    body_after_console = assemble('''
        mov x11, #0xf000
        movk x11, #0xff30, lsl #16
        mov w10, #0xff00
        movk w10, #0xff00, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    b_back_after_console = calc_b(0x4477a0 + len(body_after_console), 0x43d0a8)
    probe_after_console = body_after_console + b_back_after_console
    assert len(probe_after_console) <= 48
    data[0x4477a0 : 0x4477a0 + len(probe_after_console)] = probe_after_console
    data[0x43d0a0 : 0x43d0a4] = calc_b(0x43d0a0, 0x4477a0)
    data[0x43d0a4 : 0x43d0a8] = bytes.fromhex('1f2003d5')
    print("[+] Injected LIME probe after PE_create_console at 0x4477a0 (hooked 0x43d0a0)")

    # 5k. Probe 10: Early Panic on-screen text logger at file offset 0x447830
    panic_logger_code = '''
        // When _panic is called at 0xfffffff007a78bd8:
        // x0 = format string or filename
        // x30 = return address to caller (or __assert at 0xfffffff007a78c2c)
        // sp is stack pointer before sub sp, sp, #32

        mov x19, x0        // x19 = format / file
        mov x14, x30       // x14 = caller lr
        mov x21, sp        // x21 = incoming sp

        // Map FB base: 0xff1ef000 (boot_args->Video.v_baseAddr)
        mov x22, #0xf000
        movk x22, #0xff1e, lsl #16
        mov x23, #2944              // rowBytes

        // 1. Draw RED header bar (40 lines * 2944 = 117760 = 0x1cc00 bytes)
        mov x0, x22
        mov w1, #0x0000
        movk w1, #0xffff, lsl #16   // ARGB: Red
        mov w2, #0xcc00
        movk w2, #1, lsl #16
    1:  stp w1, w1, [x0], #8
        subs x2, x2, #8
        b.hi 1b

        // 2. Clear background black for 800 lines below header
        mov w2, #0x0000
        movk w2, #0x24, lsl #16     // 800 lines * 2944
    2:  stp xzr, xzr, [x0], #8
        subs x2, x2, #8
        b.hi 2b

        // iso_font address: 0xfffffff007a9be10
        mov x24, #0xbe10
        movk x24, #0x07a9, lsl #16
        movk x24, #0xfff0, lsl #32
        movk x24, #0xffff, lsl #48  // x24 = iso_font

        // Initial draw cursor in x20: line 60, col 200
        mov w1, #60
        madd x20, x1, x23, x22
        add x20, x20, #200

        // Check if called from panic_with_arm_saved_state (0xfffffff007a82f98)
        mov x8, #0x2f98
        movk x8, #0x07a8, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        cmp x14, x8
        b.eq is_saved_state

    is_panic:
        adr x1, str_panic_title
        bl draw_line_str
        adr x1, str_caller
        mov x2, x14
        bl draw_line_hex
        adr x1, str_msg
        mov x0, x20
        bl draw_string
        mov x1, x19
        bl draw_string
        bl advance_line

        // Variadic stack arguments:
        // [x21, #0] = arg 0 (path pointer or value)
        adr x1, str_arg0
        ldr x2, [x21, #0]
        bl draw_line_hex

        // If arg 0 is a valid pointer, also draw as string
        ldr x1, [x21, #0]
        lsr x8, x1, #48
        mov w9, #0xffff
        cmp w8, w9
        b.ne 1f
        adr x1, str_str0
        mov x0, x20
        bl draw_string
        ldr x1, [x21, #0]
        bl draw_string
        bl advance_line
    1:
        // [x21, #8] = arg 1 (errno)
        adr x1, str_arg1
        ldr x2, [x21, #8]
        bl draw_line_hex

        // [x21, #16] = arg 2 (source file)
        adr x1, str_arg2
        ldr x2, [x21, #16]
        bl draw_line_hex

        // [x21, #24] = arg 3 (line number)
        adr x1, str_arg3
        ldr x2, [x21, #24]
        bl draw_line_hex
        b hang

    is_saved_state:
        ldr x25, [x21, #0]     // reason string pointer
        ldr x26, [x21, #24]    // saved_state pointer (in callee-saved x26!)

        adr x1, str_exc_title
        bl draw_line_str

        adr x1, str_state_ptr
        mov x2, x26
        bl draw_line_hex

        // Verify x26 is a valid kernel pointer
        cbz x26, no_state
        lsr x8, x26, #48
        mov w9, #0xffff
        cmp w8, w9
        b.ne no_state

        // Read registers directly from saved_state:
        adr x1, str_fpc
        ldr x2, [x26, #264]   // PC
        bl draw_line_hex

        adr x1, str_flr
        ldr x2, [x26, #248]   // LR
        bl draw_line_hex

        adr x1, str_ffar
        ldr x2, [x26, #280]   // FAR
        bl draw_line_hex

        adr x1, str_fesr
        ldr w2, [x26, #288]   // ESR
        bl draw_line_hex

        adr x1, str_fsp
        ldr x2, [x26, #256]   // SP
        bl draw_line_hex

        // Print reason
        adr x1, str_reason
        mov x0, x20
        bl draw_string
        cbz x25, 1f
        lsr x8, x25, #48
        mov w9, #0xffff
        cmp w8, w9
        b.eq 2f
    1:  adr x1, str_null
        b 3f
    2:  mov x1, x25
    3:  bl draw_string
        bl advance_line
        b hang

    no_state:
        adr x1, str_null
        bl draw_line_str
        b hang

    hang:
        wfe
        b hang

    draw_line_hex:
        stp x29, x30, [sp, #-32]!
        str x2, [sp, #16]
        mov x0, x20
        bl draw_string
        ldr x1, [sp, #16]
        bl draw_hex
        ldp x29, x30, [sp], #32
        b advance_line

    draw_line_str:
        stp x29, x30, [sp, #-16]!
        mov x0, x20
        bl draw_string
        ldp x29, x30, [sp], #16
        b advance_line

    advance_line:
        mov w4, #30
        madd x20, x4, x23, x20
        mov x0, x20
        ret

    draw_string:
        stp x29, x30, [sp, #-16]!
        mov x9, x0
        mov x10, x0

        cbz x1, 2f
        lsr x8, x1, #48
        mov w4, #0xffff
        cmp w8, w4
        b.eq 1f
    2:  adr x1, str_null
    1:
    str_next:
        ldrb w2, [x1], #1
        cbz w2, str_done
        cmp w2, #10
        b.eq str_newline
        cmp w2, #32
        b.lo str_space
        cmp w2, #126
        b.hi str_space
        b str_draw_c

    str_newline:
        mov w4, #20
        madd x10, x4, x23, x10
        mov x9, x10
        b str_next

    str_space:
        mov w2, #32
    str_draw_c:
        add x3, x24, x2, lsl #4
        mov w4, #16
        mov x5, x9
    char_row:
        ldrb w6, [x3], #1
        mov w7, #8
    char_pix:
        sbfx w8, w6, #0, #1
        str w8, [x5], #4
        lsr w6, w6, #1
        subs w7, w7, #1
        b.ne char_pix
        sub x5, x5, #32
        add x5, x5, x23
        subs w4, w4, #1
        b.ne char_row

        add x9, x9, #32
        sub x6, x9, x10
        cmp x6, #2600
        b.lo str_next
        mov w4, #20
        madd x10, x4, x23, x10
        mov x9, x10
        b str_next

    str_done:
        mov x0, x9
        ldp x29, x30, [sp], #16
        ret

    draw_hex:
        stp x29, x30, [sp, #-48]!
        mov x12, x0
        mov x13, x1
        add x14, sp, #16
        mov w1, #0x7830
        strh w1, [x14], #2
        mov w11, #60
    hex_loop:
        lsr x1, x13, x11
        and w2, w1, #0xf
        add w2, w2, #'0'
        cmp w2, #'9'
        b.ls 1f
        add w2, w2, #7
    1:  strb w2, [x14], #1
        subs w11, w11, #4
        b.ge hex_loop
        strb wzr, [x14]
        mov x0, x12
        add x1, sp, #16
        bl draw_string
        ldp x29, x30, [sp], #48
        ret

    str_panic_title:  .asciz "*** PANIC ***"
    str_exc_title:    .asciz "*** EXCEPTION PANIC ***"
    str_caller:       .asciz "CALLER: "
    str_msg:          .asciz "MSG: "
    str_arg0:         .asciz "ARG0: "
    str_str0:         .asciz "STR0: "
    str_arg1:         .asciz "ERRNO: "
    str_arg2:         .asciz "ARG2: "
    str_arg3:         .asciz "ARG3: "
    str_reason:       .asciz "REASON: "
    str_state_ptr:    .asciz "STATE: "
    str_fpc:          .asciz "PC:  "
    str_flr:          .asciz "LR:  "
    str_ffar:         .asciz "FAR: "
    str_fesr:         .asciz "ESR: "
    str_fsp:          .asciz "SP:  "
    str_null:         .asciz "(null)"
    '''
    probe_panic = assemble(panic_logger_code)
    assert len(probe_panic) <= 976, f"probe_panic too large: {len(probe_panic)}"
    data[0x447830 : 0x447830 + len(probe_panic)] = probe_panic
    data[0xa74bd8 : 0xa74bdc] = calc_b(0xa74bd8, 0x447830)
    data[0xa74bdc : 0xa74be0] = bytes.fromhex('1f2003d5')
    print(f"[+] Injected early Panic text logger at 0x447830 ({len(probe_panic)} bytes, hooked 0xa74bd8)")

    # 5l. Preemption helpers for early boot (TPIDR_EL1 == NULL):
    # Place helpers at file offset 0x447c00 (KVA 0xfffffff00744bc00)
    preempt_helpers = assemble('''
    safe_disable_preemption:
        mrs x8, tpidr_el1
        cbz x8, 1f
        ldr w9, [x8, #0x1d0]
        add w9, w9, #1
        str w9, [x8, #0x1d0]
    1:  ret

    safe_enable_preemption:
        mrs x8, tpidr_el1
        cbz x8, 1f
        stp x29, x30, [sp, #-0x10]!
        mov x29, sp
        ldr w9, [x8, #0x1d0]
        cbz w9, 2f
        subs w9, w9, #1
        str w9, [x8, #0x1d0]
        b.ne 3f
        ldr x8, [x8, #0x1c8]
        ldrb w8, [x8, #0x4c]
        tbnz w8, #2, 4f
    3:  ldp x29, x30, [sp], #0x10
    1:  ret
    2:  ldp x29, x30, [sp], #0x10
        ret
    4:  ldp x29, x30, [sp], #0x10
        mov x8, #0x61c4
        movk x8, #0x0744, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        br x8

    safe_get_preemption_level:
        mrs x8, tpidr_el1
        mov w0, #0
        cbz x8, 1f
        ldr w0, [x8, #0x1d0]
    1:  ret

    safe_get_preemption_level_for_thread:
        mov w9, #0
        cbz x0, 1f
        ldr w9, [x0, #0x1d0]
    1:  mov w0, w9
        ret
    ''')
    assert len(preempt_helpers) <= 512, f"preempt_helpers too large: {len(preempt_helpers)}"
    data[0x447c00 : 0x447c00 + len(preempt_helpers)] = preempt_helpers

    # Hook _disable_preemption at 0xfffffff007445c2c (file offset 0x441c2c)
    data[0x441c2c : 0x441c30] = calc_b(0xfffffff007445c2c, 0xfffffff00744bc00)
    # Hook _disable_preemption_without_measurements at 0xfffffff007445c40 (file offset 0x441c40)
    data[0x441c40 : 0x441c44] = calc_b(0xfffffff007445c40, 0xfffffff00744bc00)
    # Hook _enable_preemption at 0xfffffff007445c54 (file offset 0x441c54)
    data[0x441c54 : 0x441c58] = calc_b(0xfffffff007445c54, 0xfffffff00744bc18)
    # Hook _get_preemption_level at 0xfffffff007445c9c (file offset 0x441c9c)
    data[0x441c9c : 0x441ca0] = calc_b(0xfffffff007445c9c, 0xfffffff00744bc70)
    # Hook _get_preemption_level_for_thread at 0xfffffff007445c94 (file offset 0x441c94)
    data[0x441c94 : 0x441c98] = calc_b(0xfffffff007445c94, 0xfffffff00744bc84)
    print(f"[+] Injected safe preemption helpers at 0x447c00 ({len(preempt_helpers)} bytes, hooked 0x441c2c, 0x441c40, 0x441c54, 0x441c9c, 0x441c94)")

    # 6. Master CPU & Topology fixes:
    # 6a. Statically initialize topology_cluster[0] at file offset 0x1b2558 (KVA 0xfffffff0071b6558)
    data[0x1b2558 : 0x1b255c] = (0).to_bytes(4, 'little')    # cluster_id = 0
    data[0x1b255c : 0x1b2560] = (0).to_bytes(4, 'little')    # cluster_type = CLUSTER_TYPE_SMP (0)
    data[0x1b2560 : 0x1b2564] = (8).to_bytes(4, 'little')    # num_cpus = 8
    data[0x1b2564 : 0x1b2568] = (0).to_bytes(4, 'little')    # first_cpu_id = 0
    data[0x1b2568 : 0x1b2570] = (0xff).to_bytes(8, 'little') # cpu_mask = 0xff

    # 6b. Statically initialize topology_info at file offset 0x1b25a0 (KVA 0xfffffff0071b65a0)
    data[0x1b25a0 : 0x1b25a4] = (1).to_bytes(4, 'little')    # version = 1
    data[0x1b25a4 : 0x1b25a8] = (8).to_bytes(4, 'little')    # num_cpus = 8
    data[0x1b25a8 : 0x1b25ac] = (7).to_bytes(4, 'little')    # max_cpu_id = 7
    data[0x1b25ac : 0x1b25b0] = (1).to_bytes(4, 'little')    # num_clusters = 1 (CRITICAL FIX FOR SCHED_CLUTCH!)
    data[0x1b25b0 : 0x1b25b4] = (0).to_bytes(4, 'little')    # max_cluster_id = 0
    data[0x1b25b4 : 0x1b25b8] = (0).to_bytes(4, 'little')    # max_die_id = 0
    data[0x1b25b8 : 0x1b25c0] = (0xfffffff0071b6198).to_bytes(8, 'little') # cpus ptr
    data[0x1b25c0 : 0x1b25c8] = (0xfffffff0071b6558).to_bytes(8, 'little') # clusters ptr
    data[0x1b25c8 : 0x1b25d0] = (0xfffffff0071b6198).to_bytes(8, 'little') # boot_cpu ptr
    data[0x1b25d0 : 0x1b25d8] = (0xfffffff0071b6558).to_bytes(8, 'little') # boot_cluster ptr
    data[0x1b25d8 : 0x1b25dc] = (0).to_bytes(4, 'little')    # chip_revision = 0
    data[0x1b25dc : 0x1b25e0] = (1).to_bytes(4, 'little')    # cluster_types = (1 << CLUSTER_TYPE_SMP) = 1
    data[0x1b25e0 : 0x1b25e4] = (8).to_bytes(4, 'little')    # cluster_type_num_cpus[0] = 8
    data[0x1b25ec : 0x1b25f0] = (1).to_bytes(4, 'little')    # cluster_type_num_clusters[0] = 1

    # 6c. Statically initialize cpu_data_entries at file offset 0x1b2198 (KVA 0xfffffff0071b6198)
    for c in range(8):
        c_off = 0x1b2198 + c * 0x78
        data[c_off : c_off + 4] = c.to_bytes(4, 'little')
        data[c_off + 4 : c_off + 8] = c.to_bytes(4, 'little')
        data[c_off + 8 : c_off + 12] = (0).to_bytes(4, 'little')
        data[c_off + 12 : c_off + 16] = (0).to_bytes(4, 'little')
        data[c_off + 16 : c_off + 20] = (0).to_bytes(4, 'little')
        data[c_off + 112 : c_off + 116] = (0).to_bytes(4, 'little')
        data[c_off + 116 : c_off + 120] = c.to_bytes(4, 'little')

    # 6c2. In _ml_parse_cpu_topology at 0xfffffff007450320 (file offset 0x44c320): Force return (protect static tables)
    data[0x44c320 : 0x44c324] = bytes.fromhex('c0035fd6') # ret

    # 6c3. In _ml_get_cluster_count at 0xfffffff00745124c (file offset 0x44d24c): Force return 1
    patch_ml_cluster = assemble('mov w0, #1\nret')
    data[0x44d24c : 0x44d24c + len(patch_ml_cluster)] = patch_ml_cluster

    # 6c4. In _ml_get_boot_cluster_type at 0xfffffff007451268 (file offset 0x44d268): Force return 0 (CLUSTER_TYPE_SMP)
    patch_ml_cluster_type = assemble('mov w0, #0\nret')
    data[0x44d268 : 0x44d268 + len(patch_ml_cluster_type)] = patch_ml_cluster_type

    # 6c. In arm_init at 0xfffffff007440dc4 (file offset 0x43cdc4):
    # Replace `bl _ml_get_boot_cpu_number` (4 bytes) with `mov w0, #0`
    patch_boot_cpu = assemble('mov w0, #0')
    assert len(patch_boot_cpu) == 4
    data[0x43cdc4 : 0x43cdc4 + 4] = patch_boot_cpu

    # 6d. In arm_init at 0xfffffff007440de0 (file offset 0x43cde0):
    # NOP out `tbnz w21, #0x1f, #0xfffffff007441328`
    data[0x43cde0 : 0x43cde4] = bytes.fromhex('1f2003d5')

    # 6e. In arm_init at 0xfffffff007440dec (file offset 0x43cdec):
    # NOP out `b.gt #0xfffffff007441328`
    data[0x43cdec : 0x43cdf0] = bytes.fromhex('1f2003d5')

    # 6f. In _ml_get_boot_cpu_number at 0xfffffff007451258 (file offset 0x44d258): Force return 0
    patch_ml_boot = assemble('mov w0, #0\nret')
    data[0x44d258 : 0x44d258 + len(patch_ml_boot)] = patch_ml_boot

    # 6g. In _ml_get_cpu_number_local at 0xfffffff007451314 (file offset 0x44d314): Force return 0
    patch_ml_local = assemble('mov w0, #0\nret')
    data[0x44d314 : 0x44d314 + len(patch_ml_local)] = patch_ml_local

    # 6h. In _ml_get_max_cpu_number at 0xfffffff007451390 (file offset 0x44d390): Force return 7
    patch_ml_max = assemble('mov w0, #7\nret')
    data[0x44d390 : 0x44d390 + len(patch_ml_max)] = patch_ml_max

    # 6i. In _cpu_number at 0xfffffff00743eb74 (file offset 0x43ab74): Safe early-boot handling for TPIDR_EL1 == 0
    patch_cpu_num = assemble('''
        mrs x8, TPIDR_EL1
        mov w0, #0
        cbz x8, 1f
        ldr x8, [x8, #456]
        cbz x8, 1f
        ldrsh w0, [x8]
    1:  ret
    ''')
    assert len(patch_cpu_num) == 28
    data[0x43ab74 : 0x43ab74 + len(patch_cpu_num)] = patch_cpu_num

    # 6j. In _serial_init at 0xfffffff007a52c38 (file offset 0xa4ec38): Force return 0 (skip serial switch)
    patch_serial = assemble('''
        mov w0, #0
        ret
    ''')
    assert len(patch_serial) == 8
    data[0xa4ec38 : 0xa4ec38 + len(patch_serial)] = patch_serial
    print("[+] Applied Master CPU and Topology fixes (arm_init, ml_get_boot_cpu_number, ml_get_cpu_number_local, ml_get_max_cpu_number, cpu_number, serial_init)")

    # 7. Entropy initialization fix:
    # 7a. PE_get_random_seed at 0xfffffff007a50148 (file offset 0xa4c148)
    patch_random_seed = assemble('''
        mov x8, #0x7b35
        movk x8, #0x46a9, lsl #16
        movk x8, #0x92df, lsl #32
        movk x8, #0x5a1c, lsl #48
        mov x9, #0x82f1
        movk x9, #0x3e74, lsl #16
        movk x9, #0xa5c8, lsl #32
        movk x9, #0x6d9b, lsl #48
        stp x8, x9, [x0]
        stp x8, x9, [x0, #16]
        stp x8, x9, [x0, #32]
        stp x8, x9, [x0, #48]
        mov w0, #0x40
        ret
    ''')
    assert len(patch_random_seed) <= 204
    data[0xa4c148 : 0xa4c148 + len(patch_random_seed)] = patch_random_seed
    print(f"[+] Injected pseudo-random generator into PE_get_random_seed at 0xa4c148 ({len(patch_random_seed)} bytes)")

    # 7b. NOP out b.ls at 0xfffffff00741b2d4 (file offset 0x4172d4)
    data[0x4172d4 : 0x4172d8] = bytes.fromhex('1f2003d5')
    print("[+] NOPed out panic branch in early_random_init at 0x4172d4")

    # 8. VM initialization fixes:
    # 8a. arm_vm_prot_init bypass for missing TrustCache / AuxKC in chosen/memory-map:
    # At 0xfffffff007441e30 (file offset 0x43de30):
    b_skip_tc = calc_b(0xfffffff007441e30, 0xfffffff007441fdc)
    data[0x43de30 : 0x43de34] = b_skip_tc
    print("[+] Patched arm_vm_prot_init at 0x43de30 to skip TrustCache/AuxKC and bypass assert line 1287")

    # 8b. pmap_bootstrap bypass for missing DT /defaults node (assert err == kSuccess at line 1989):
    # At 0xfffffff007423f2c (file offset 0x41ff2c):
    # Jump directly to 0xfffffff007423fa0 (mov w8, #0x800; str w8, [x24, #0x424])
    b_skip_pmap_defaults = calc_b(0xfffffff007423f2c, 0xfffffff007423fa0)
    data[0x41ff2c : 0x41ff30] = b_skip_pmap_defaults
    print("[+] Patched pmap_bootstrap at 0x41ff2c to default max_asids=2048 and bypass /defaults assert")

    # 8c. pmap_data_bootstrap bypass for missing DT /defaults node:
    # Helper 1 at 0xfffffff007436d68 (file offset 0x432d68): force return (PV pool tunables assert line 2107)
    data[0x432d68 : 0x432d6c] = bytes.fromhex('c0035fd6') # ret

    # Helper 2 at 0xfffffff007436ec4 (file offset 0x432ec4): return 0 (pmap-io-ranges assert line 3570)
    data[0x432ec4 : 0x432ecc] = bytes.fromhex('00008052c0035fd6') # mov w0, #0; ret

    # Helper 3 at 0xfffffff0074372d8 (file offset 0x4332d8): force return (pmap-io-ranges copy assert line 3661)
    data[0x4332d8 : 0x4332dc] = bytes.fromhex('c0035fd6') # ret
    print("[+] Patched pmap_data_bootstrap helpers at 0x432d68, 0x432ec4, 0x4332d8 to bypass /defaults asserts")

    # 8d. device_tree.c bounds check panics bypass:
    # Convert fatal panics on out-of-bounds / malformed DT pointers into clean error returns (-1 / NULL).
    # 1. DTFindEntry at 0xfffffff007a4e5d4 (file offset 0xa4a5d4): return -1
    off_dt_find = 0xfffffff007a4e5d4 - 0xfffffff007004000
    p_dt_find = assemble('mov w0, #-1') + calc_b(0xfffffff007a4e5d8, 0xfffffff007a4e578)
    data[off_dt_find : off_dt_find + len(p_dt_find)] = p_dt_find

    # 2. DTFindEntry property overflow at 0xfffffff007a4e5b0 (file offset 0xa4a5b0): return -1
    off_dt_find_ovf = 0xfffffff007a4e5b0 - 0xfffffff007004000
    p_dt_find_ovf = assemble('mov w0, #-1') + calc_b(0xfffffff007a4e5b4, 0xfffffff007a4e578)
    data[off_dt_find_ovf : off_dt_find_ovf + len(p_dt_find_ovf)] = p_dt_find_ovf

    # 3. DTLookupEntry at 0xfffffff007a4e838 (file offset 0xa4a838): return -1
    off_dt_lookup = 0xfffffff007a4e838 - 0xfffffff007004000
    p_dt_lookup = assemble('mov w0, #-1') + calc_b(0xfffffff007a4e83c, 0xfffffff007a4e7b8)
    data[off_dt_lookup : off_dt_lookup + len(p_dt_lookup)] = p_dt_lookup

    # 4. DTGetProperty at 0xfffffff007a4eb84 & 0xfffffff007a4eba8 (file offsets 0xa4ab84, 0xa4aba8): return -1
    off_dt_getprop1 = 0xfffffff007a4eb84 - 0xfffffff007004000
    off_dt_getprop2 = 0xfffffff007a4eba8 - 0xfffffff007004000
    data[off_dt_getprop1 : off_dt_getprop1 + 4] = calc_b(0xfffffff007a4eb84, 0xfffffff007a4eb00)
    data[off_dt_getprop2 : off_dt_getprop2 + 4] = calc_b(0xfffffff007a4eba8, 0xfffffff007a4eb00)

    # 5. DTIterateProperties at 0xfffffff007a4ed00 & 0xfffffff007a4ed24 (file offsets 0xa4ad00, 0xa4ad24): return 0
    off_dt_iter1 = 0xfffffff007a4ed00 - 0xfffffff007004000
    off_dt_iter2 = 0xfffffff007a4ed24 - 0xfffffff007004000
    data[off_dt_iter1 : off_dt_iter1 + 4] = calc_b(0xfffffff007a4ed00, 0xfffffff007a4ec44)
    data[off_dt_iter2 : off_dt_iter2 + 4] = calc_b(0xfffffff007a4ed24, 0xfffffff007a4ec44)

    # 6. DTGetFirstChild at 0xfffffff007a4ede8 & 0xfffffff007a4ee0c (file offsets 0xa4ade8, 0xa4ae0c): return NULL
    off_dt_child1 = 0xfffffff007a4ede8 - 0xfffffff007004000
    off_dt_child2 = 0xfffffff007a4ee0c - 0xfffffff007004000
    data[off_dt_child1 : off_dt_child1 + 4] = calc_b(0xfffffff007a4ede8, 0xfffffff007a4edc0)
    data[off_dt_child2 : off_dt_child2 + 4] = calc_b(0xfffffff007a4ee0c, 0xfffffff007a4edc0)

    # 7. DTGetNextChild at 0xfffffff007a4eeb8 (file offset 0xa4aeb8): return NULL
    off_dt_next = 0xfffffff007a4eeb8 - 0xfffffff007004000
    p_dt_next = assemble('mov x0, #0') + calc_b(0xfffffff007a4eebc, 0xfffffff007a4ee90)
    data[off_dt_next : off_dt_next + len(p_dt_next)] = p_dt_next

    # 8. Node validator at 0xfffffff007a4e9e4 (file offset 0xa4a9e4): return 0
    off_dt_valid = 0xfffffff007a4e9e4 - 0xfffffff007004000
    p_dt_valid = assemble('mov x0, #0') + calc_b(0xfffffff007a4e9e8, 0xfffffff007a4e9bc)
    data[off_dt_valid : off_dt_valid + len(p_dt_valid)] = p_dt_valid
    print("[+] Patched device_tree.c bounds panics (DTFindEntry, DTLookupEntry, DTGetProperty, DTIterateProperties, DTGetFirstChild, DTGetNextChild) to safe error returns")

    # 9. Video Console Text Mode & disableConsoleOutput fixes:
    # 9a. Force PE_create_console to call PE_initialize_console(&PE_state.video, kPETextMode):
    patch_pe_console = assemble('''
        mov w1, #2
        nop
    ''')
    assert len(patch_pe_console) == 8
    data[0xa4e27c : 0xa4e284] = patch_pe_console
    print("[+] Patched PE_create_console at 0xa4e27c to force kPETextMode")

    # 9b. Unconditionally clear disableConsoleOutput in arm_init:
    b_clear_dco = calc_b(0xfffffff007441078, 0xfffffff007441090)
    data[0x43d078 : 0x43d07c] = b_clear_dco
    print("[+] Patched arm_init at 0x43d078 to unconditionally clear disableConsoleOutput")

    # 9b2. arm_init direct DRAM setup & bypass /chosen lookups at 0xfffffff0074410f8 (offset 0x43d0f8):
    # Directly populate gDramBase = 0x40000000, gDramSize = 0x100000000 (4GB), paint TEAL probe (0xff31f000),
    # and fall through directly to early_random_cpu_init (0xfffffff007441174) & machine_startup.
    off_dram_init = 0xfffffff0074410f8 - 0xfffffff007004000
    target_dram_len = 0x43d174 - 0x43d0f8 # 124 bytes (31 instructions)
    p_dram_part1 = assemble('''
        mov x8, #0x0000
        movk x8, #0x4000, lsl #16
    ''')
    adrp_dram = calc_adrp(0xfffffff0074410f8 + len(p_dram_part1), 0xfffffff0071a0000, 9)
    p_dram_part2 = assemble('''
        str x8, [x9, #0x818]
        mov x8, #0x0000
        movk x8, #0xb000, lsl #16
        str x8, [x9, #0x820]
        mov x11, #0xf000
        movk x11, #0xff31, lsl #16
        mov w10, #0xff00
        movk w10, #0x00ff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
    ''')
    p_dram_code = p_dram_part1 + adrp_dram + p_dram_part2
    assert len(p_dram_code) <= target_dram_len
    p_dram_nops = (target_dram_len - len(p_dram_code)) // 4
    patch_dram_full = p_dram_code + (b'\x1f\x20\x03\xd5' * p_dram_nops)
    assert len(patch_dram_full) == target_dram_len
    data[off_dram_init : off_dram_init + target_dram_len] = patch_dram_full
    print("[+] Patched arm_init at 0x43d0f8 to directly set gDramBase=0x40000000, gDramSize=4GB & bypass chosen lookups")

    # 9c. Patch _vc_colors 32-bit alpha byte to 0xFF (file offset 0x5228):
    for i in range(8):
        c_off = 0x5228 + i * 16 + 8
        c_val = struct.unpack_from('<I', data, c_off)[0]
        c_new = c_val | 0xff000000
        data[c_off : c_off + 4] = struct.pack('<I', c_new)
    print("[+] Patched _vc_colors at 0x5228 to force alpha=0xFF for all 8 console colors")

    # 9d. In _gc_enable: NOP disableConsoleOutput = 1 (offset 0x412b48) and gc_enabled = 0 (offset 0x412b50)
    data[0x412b48 : 0x412b4c] = b'\x1f\x20\x03\xd5'
    data[0x412b50 : 0x412b54] = b'\x1f\x20\x03\xd5'
    print("[+] Patched _gc_enable at 0x412b48 and 0x412b50 to prevent disabling text console")

    # 10. Patch default init binary path from /sbin/launchd to /sbin/init
    launchd_str = b'/sbin/launchd\x00'
    init_str    = b'/sbin/init\x00\x00\x00\x00'
    assert data[0xfa234 : 0xfa234 + len(launchd_str)] == launchd_str, f"Unexpected data at 0xfa234: {data[0xfa234:0xfa234+len(launchd_str)]}"
    data[0xfa234 : 0xfa234 + len(init_str)] = init_str
    print("[+] Patched /sbin/launchd -> /sbin/init at file offset 0xfa234")

    # 11. Disable code signing enforcement & AMFI restrictions across kernel
    # 11a. Patch _code_signing_configuration at 0xfffffff0077f5f90 (file offset 0x7f1f90)
    # Force config = 0xff (ALLOW_ANY_SIGNATURE | ENFORCEMENT_DISABLED | GET_OUT_OF_MY_WAY | UNRESTRICTED_DEBUGGING)
    cs_patch = bytes.fromhex("400000b41f0000b9610000b4e81f8052280000b9c0035fd6")
    assert len(cs_patch) == 24
    data[0x7f1f90 : 0x7f1f90 + 24] = cs_patch
    print("[+] Patched _code_signing_configuration at 0x7f1f90 to force config=0xff")

    # 11b. Patch _cs_process_enforcement at 0xfffffff0077948fc (file offset 0x7908fc) -> return 0
    ret_zero = bytes.fromhex("00008052c0035fd6") # mov w0, #0; ret
    data[0x7908fc : 0x7908fc + 8] = ret_zero
    print("[+] Patched _cs_process_enforcement at 0x7908fc -> return 0")

    # 11c. Patch _cs_system_enforcement at 0xfffffff007794950 (file offset 0x790950) -> return 0
    data[0x790950 : 0x790950 + 8] = ret_zero
    print("[+] Patched _cs_system_enforcement at 0x790950 -> return 0")

    # 11d. Patch _cs_process_global_enforcement at 0xfffffff00779493c (file offset 0x79093c) -> return 0
    data[0x79093c : 0x79093c + 8] = ret_zero
    print("[+] Patched _cs_process_global_enforcement at 0x79093c -> return 0")

    # 11e. Statically zero out cs_system_enforcement_enable and cs_process_enforcement_enable
    data[0x1ce260 : 0x1ce268] = bytes.fromhex("0000000000000000")
    print("[+] Zeroed cs_system_enforcement_enable and cs_process_enforcement_enable at 0x1ce260")

    # 12. Mach-O Loader: Bypass LOAD_FAILURE checks in parse_machfile and load_segment
    # Check 1: !using_lcmain && validentry == 0 at 0xfffffff007848a6c (file offset 0x844a6c)
    assert data[0x844a6c : 0x844a70] == bytes.fromhex("40540054"), f"Unexpected at 0x844a6c: {data[0x844a6c:0x844a70].hex()}"
    data[0x844a6c : 0x844a70] = bytes.fromhex("1f2003d5") # nop
    print("[+] Patched parse_machfile check 1 (validentry check) at 0x844a6c -> nop")

    # Check 2: needs_dynlinker && !dlp at 0xfffffff0078495ac & 0xfffffff0078495b0 (file offset 0x8455ac & 0x8455b0)
    assert data[0x8455ac : 0x8455b0] == bytes.fromhex("89008052"), f"Unexpected at 0x8455ac: {data[0x8455ac:0x8455b0].hex()}"
    assert data[0x8455b0 : 0x8455b4] == bytes.fromhex("0801891a"), f"Unexpected at 0x8455b0: {data[0x8455b0:0x8455b4].hex()}"
    data[0x8455ac : 0x8455b0] = bytes.fromhex("09008052") # mov w9, #0
    data[0x8455b0 : 0x8455b4] = bytes.fromhex("1f2003d5") # nop
    print("[+] Patched parse_machfile check 2 (needs_dynlinker check) at 0x8455ac..0x8455b0 -> mov w9, #0; nop")

    # Check 3: thread_count == 0 at 0xfffffff007849600 (file offset 0x845600)
    assert data[0x845600 : 0x845604] == bytes.fromhex("03751e53"), f"Unexpected at 0x845600: {data[0x845600:0x845604].hex()}"
    data[0x845600 : 0x845604] = bytes.fromhex("03008052") # mov w3, #0
    print("[+] Patched parse_machfile check 3 (thread_count check) at 0x845600 -> mov w3, #0")

    # Check 4: PAGEZERO unprotect check at 0xfffffff00784af70 (file offset 0x846f70)
    assert data[0x846f70 : 0x846f74] == bytes.fromhex("97008052"), f"Unexpected at 0x846f70: {data[0x846f70:0x846f74].hex()}"
    data[0x846f70 : 0x846f74] = bytes.fromhex("07008052") # mov w23, #0
    print("[+] Patched load_segment check 4 (PAGEZERO unprotect) at 0x846f70 -> mov w23, #0")

    # Check 5: PAGEZERO min_offset check at 0xfffffff00784b000 (file offset 0x847000)
    assert data[0x847000 : 0x847004] == bytes.fromhex("97008052"), f"Unexpected at 0x847000: {data[0x847000:0x847004].hex()}"
    data[0x847000 : 0x847004] = bytes.fromhex("07008052") # mov w23, #0
    print("[+] Patched load_segment check 5 (PAGEZERO min_offset) at 0x847000 -> mov w23, #0")

    # Check 6: load_unixthread thread_count check at 0xfffffff00784b398 (file offset 0x847398)
    assert data[0x847398 : 0x84739c] == bytes.fromhex("80008052"), f"Unexpected at 0x847398: {data[0x847398:0x84739c].hex()}"
    data[0x847398 : 0x84739c] = bytes.fromhex("00008052") # mov w0, #0
    print("[+] Patched load_unixthread check 6 (thread_count check) at 0x847398 -> mov w0, #0")

    # 13. IOKit IOPlatformExpert: Bypass assert(gIOOptionsEntry != NULL) at line 1695
    # Location: 0xfffffff0079cec38 (file offset 0x9cac38)
    # Original: 680500b4 (cbz x8, #0xfffffff0079cece4)
    # Patch:    1f2003d5 (nop)
    assert data[0x9cac38 : 0x9cac3c] == bytes.fromhex("680500b4"), f"Unexpected at 0x9cac38: {data[0x9cac38:0x9cac3c].hex()}"
    data[0x9cac38 : 0x9cac3c] = bytes.fromhex("1f2003d5") # nop
    print("[+] Patched IOPlatformExpert assert (gIOOptionsEntry != NULL) at 0x9cac38 -> nop")

    # 14. Unblock ml_wait_max_cpus so kernel startup thread proceeds to bsd_init()
    # Location: 0xfffffff00744f870 (file offset 0x44b870)
    # Original: f657bda9f44f01a9fd7b02a9fd830091e83600b0088148b908040034e03600b0
    # Patch:
    #   mov w8, #1
    #   adrp x9, 0xfffffff007d22000
    #   str w8, [x9, #0x4dc]          ; max_cpus_initialized = 1 (MAX_CPUS_SET)
    #   adrp x8, 0xfffffff007ae0000
    #   ldr w0, [x8, #0x440]          ; load machine_info.max_cpus
    #   cbnz w0, #0xfffffff00744f88c  ; if non-zero, return it
    #   mov w0, #8                    ; default to 8 CPUs
    #   ret
    patch14_bytes = bytes.fromhex("28008052894600f028dd04b9883400b0004144b94000003500018052c0035fd6")
    orig14_bytes = bytes.fromhex("f657bda9f44f01a9fd7b02a9fd830091e83600b0088148b908040034e03600b0")
    assert data[0x44b870 : 0x44b870 + len(orig14_bytes)] == orig14_bytes, f"Unexpected at 0x44b870: {data[0x44b870:0x44b870+len(orig14_bytes)].hex()}"
    data[0x44b870 : 0x44b870 + len(patch14_bytes)] = patch14_bytes
    print("[+] Patched ml_wait_max_cpus at 0x44b870 to unblock startup thread & advance to bsd_init")

    # 15. Patch _current_percpu_base and _current_processor to safely handle early boot (TPIDR_EL1 == NULL/invalid)
    # 15a. _current_percpu_base at 0xfffffff00743e750 (file offset 0x43a750, 24 bytes)
    patch_percpu_bytes = assemble('''
        mrs x8, TPIDR_EL1
        mov x0, #0
        tbz x8, #63, 1f
        ldr x0, [x8, #0x1c0]
    1:  ret
        nop
    ''')
    orig_percpu_bytes = bytes.fromhex("fd7bbfa9fd0300913f46009400e040f9fd7bc1a8c0035fd6")
    assert data[0x43a750 : 0x43a750 + len(orig_percpu_bytes)] == orig_percpu_bytes, f"Unexpected at 0x43a750: {data[0x43a750:0x43a750+len(orig_percpu_bytes)].hex()}"
    assert len(patch_percpu_bytes) == len(orig_percpu_bytes)
    data[0x43a750 : 0x43a750 + len(patch_percpu_bytes)] = patch_percpu_bytes
    print("[+] Patched _current_percpu_base at 0x43a750 to safely handle early-boot / null TPIDR_EL1")

    # 15b. _current_processor at 0xfffffff00743a768 (file offset 0x43a768, 36 bytes)
    patch_processor_bytes = bytearray(assemble('''
        mrs x8, TPIDR_EL1
        mov x0, #0
        tbz x8, #63, 1f
        ldr x0, [x8, #0x1c0]
    1:  adrp x9, 0
        add x9, x9, #0x180
        add x0, x0, x9
        ret
        nop
    '''))
    # Correctly compute adrp to 0xfffffff007ad4000 (stock instruction is c93400d0)
    patch_processor_bytes[16 : 20] = calc_adrp(0xfffffff00743a768 + 16, 0xfffffff007ad4000, 9)
    assert patch_processor_bytes[16 : 20] == bytes.fromhex("c93400d0")
    orig_processor_bytes = bytes.fromhex("fd7bbfa9fd0300913946009408e040f9c93400d0290106910001098bfd7bc1a8c0035fd6")
    assert data[0x43a768 : 0x43a768 + len(orig_processor_bytes)] == orig_processor_bytes, f"Unexpected at 0x43a768: {data[0x43a768:0x43a768+len(orig_processor_bytes)].hex()}"
    assert len(patch_processor_bytes) == len(orig_processor_bytes)
    data[0x43a768 : 0x43a768 + len(patch_processor_bytes)] = patch_processor_bytes
    print("[+] Patched _current_processor at 0x43a768 (with verified adrp 0xfffffff007ad4000)")

    # 16. Protect el1_sp0_synchronous_vector_long from double-faulting on TPIDR_EL1 == 0 (CHECK_KERNEL_STACK):
    # At 0xfffffff007444028, change 'b.ne 0xfffffff0074440b0' (54000441) to unconditional 'b 0xfffffff0074440b0'.
    # This bypasses the thread stack check in early boot and directly dispatches to fleh_synchronous.
    orig_vec_bytes = bytes.fromhex("41040054") # b.ne 0xfffffff0074440b0
    assert data[0x444028 : 0x44402c] == orig_vec_bytes, f"Unexpected at 0x444028: {data[0x444028:0x44402c].hex()}"
    data[0x444028 : 0x44402c] = calc_b(0xfffffff007444028, 0xfffffff0074440b0)
    print("[+] Patched el1_sp0_synchronous_vector_long at 0x444028 to bypass early CHECK_KERNEL_STACK double-fault")

    # 17. Patch mdevlookup at 0xfffffff0074ad994 (file offset 0x4a9994) with auto-creation fallback:
    # If md0 has not been configured by /chosen/memory-map/RAMDisk, auto-create it using:
    #   kva = ml_static_ptovirt(0x69500000)
    #   mdevadd(0, kva >> 12, 0x400, 0)
    # Location for helper: 0x447cd0
    fb_code = '''
        cbnz w0, 1f
        stp x29, x30, [sp, #-16]!
        mov x0, #0x0000
        movk x0, #0x6950, lsl #16
        bl 0
        lsr x1, x0, #12
        mov x0, #0
        mov x2, #0x400
        mov w3, #0
        bl 0
        ldp x29, x30, [sp], #16
        ret
    1:  mov w0, #0xffffffff
        ret
    '''
    fb_bytes = bytearray(assemble(fb_code))
    fb_addr = 0x447cd0
    # First bl 0 at offset 16 -> target_ml_static_ptovirt (0x44db78)
    bl1_offset = 16
    fb_bytes[bl1_offset : bl1_offset + 4] = calc_bl(fb_addr + bl1_offset, 0x44db78)
    # Second bl 0 at offset 36 -> target_mdevadd (0x4a96a0)
    bl2_offset = 36
    fb_bytes[bl2_offset : bl2_offset + 4] = calc_bl(fb_addr + bl2_offset, 0x4a96a0)
    assert len(fb_bytes) == 56
    data[fb_addr : fb_addr + len(fb_bytes)] = fb_bytes

    # Hook mdevlookup at 0x4a9994: replace `mov w0, #0xffffffff` with branch to 0x447cd0
    orig_mdev_inst = bytes.fromhex("00008012") # mov w0, #0xffffffff
    assert data[0x4a9994 : 0x4a9998] == orig_mdev_inst, f"Unexpected at 0x4a9994: {data[0x4a9994:0x4a9998].hex()}"
    data[0x4a9994 : 0x4a9998] = calc_b(0x4a9994, fb_addr)
    print(f"[+] Injected mdevlookup auto-creation fallback at 0x{fb_addr:x} and hooked 0x4a9994")

    # 18. Patch _arm64_platform_error at 0xfffffff0074499b8 (file offset 0x4459b8) to safely absorb platform errors:
    orig_plat_bytes = bytes.fromhex("f44fbea9")
    assert data[0x4459b8 : 0x4459bc] == orig_plat_bytes, f"Unexpected at 0x4459b8: {data[0x4459b8:0x4459bc].hex()}"
    data[0x4459b8 : 0x4459bc] = bytes.fromhex("c0035fd6") # ret
    print("[+] Patched _arm64_platform_error at 0x4459b8 with ret to absorb platform errors")

    # 19. Patch _sleh_serror at 0xfffffff00744a6f0 (file offset 0x4466f0) to safely absorb asynchronous SErrors:
    orig_sleh_bytes = bytes.fromhex("ff8301d1")
    assert data[0x4466f0 : 0x4466f4] == orig_sleh_bytes, f"Unexpected at 0x4466f0: {data[0x4466f0:0x4466f4].hex()}"
    data[0x4466f0 : 0x4466f4] = bytes.fromhex("c0035fd6") # ret
    print("[+] Patched _sleh_serror at 0x4466f0 with ret to absorb SErrors")

    # 20. Fix video_scroll_up and video_scroll_down 4x buffer overrun bug:
    # At 0xfffffff007412fb4 (offset 0x40efb4), replace `lsl x2, x10, #2` with `mov x2, x10`
    # At 0xfffffff007412fcc (offset 0x40efcc), replace `lsl x2, x9, #2` with `mov x2, x9`
    orig_scroll_up = bytes.fromhex("42f57ed3")
    assert data[0x40efb4 : 0x40efb8] == orig_scroll_up, f"Unexpected at 0x40efb4: {data[0x40efb4:0x40efb8].hex()}"
    data[0x40efb4 : 0x40efb8] = bytes.fromhex("e2030aaa") # mov x2, x10

    orig_scroll_down = bytes.fromhex("22f57ed3")
    assert data[0x40efcc : 0x40efd0] == orig_scroll_down, f"Unexpected at 0x40efcc: {data[0x40efcc:0x40efd0].hex()}"
    data[0x40efcc : 0x40efd0] = bytes.fromhex("e20309aa") # mov x2, x9
    print("[+] Patched video_scroll_up and video_scroll_down to prevent 4x buffer overrun and scroll crashes")

    # 21. Patch _PE_slide_devicetree at 0xfffffff007a51da8 (file offset 0xa4dda8) to return immediately:
    # Since KERNEL.adt is embedded at a fixed static KVA in __BOOTDATA (0xfffffff007f9c000),
    # sliding deviceTreeHead with physical aperture offsets corrupts the DT pointer and breaks IODeviceTreeAlloc!
    orig_slide_bytes = bytes.fromhex("fd7bbfa9")
    assert data[0xa4dda8 : 0xa4ddac] == orig_slide_bytes, f"Unexpected at 0xa4dda8: {data[0xa4dda8:0xa4ddac].hex()}"
    data[0xa4dda8 : 0xa4ddac] = bytes.fromhex("c0035fd6") # ret
    print("[+] Patched _PE_slide_devicetree at 0xa4dda8 with ret to keep embedded deviceTreeHead at 0xfffffff007f9c000")

    # 22. Bypass waitForMatchingService hang in IOFindBSDRoot at 0xfffffff007a2a974 (file offset 0xa26974):
    # Early timer interrupts do not wake up sleeping threads; waiting 100ms for IOBSD matching hangs forever.
    # Replace `bl waitForMatchingService` (59a2fd97) with `mov x0, #0` (000080d2).
    # Since x0 is NULL, IOFindBSDRoot prints '!BSD\n' and immediately proceeds to BSD root mounting (md0).
    orig_wait_inst = bytes.fromhex("59a2fd97") # bl 0xfffffff0079932d8
    assert data[0xa26974 : 0xa26978] == orig_wait_inst, f"Unexpected at 0xa26974: {data[0xa26974:0xa26978].hex()}"
    data[0xa26974 : 0xa26978] = bytes.fromhex("000080d2") # mov x0, #0
    print("[+] Patched IOFindBSDRoot at 0xa26974 with mov x0, #0 to bypass waitForMatchingService timeout hang")

    # 23. Patch _redwood_mtk_ufs_init at 0xfffffff0074ced80 (file offset 0x4cad80) to auto-enable UFSHCI controller
    # and verify/establish UniPro link:
    # If Host Controller Enable (HCE, REG 0x34) is 0 at boot, write 1 to REG_HCE and wait for it to become 1.
    # If link is already UP (HCS bit 0 DEVICE_PRESENT == 1), branch directly to target_continue.
    # Otherwise issue UIC_CMD_DME_LINK_STARTUP (0x16) via REG_UICCMD (0x90) with UCCS (bit 10) / ULSS (bit 8) poll,
    # verify ARG2 and DEVICE_PRESENT, clear UECPA, and log status with Apple ARM64 ABI stack-passed variadic arguments.
    orig_hce_test = bytes.fromhex("f3000037") # tbnz w19, #0, 0xfffffff0074ced9c
    assert data[0x4cad80 : 0x4cad84] == orig_hce_test, f"Unexpected at 0x4cad80: {data[0x4cad80:0x4cad84].hex()}"

    hce_helper_code = r'''
        // Load ufs_mmio
        mov x8, #0x4010
        movk x8, #0x07e9, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        ldr x8, [x8]
        cbz x8, fail_mmio_null

        // Step 0: Check / Enable HCE
        mov w14, #0
        ldr w9, [x8, #0x34]
        tbnz w9, #0, hce_on
        mov w9, #1
        str w9, [x8, #0x34]
        dsb sy
        mov x10, #0x100000
    1:
        ldr w9, [x8, #0x34]
        tbnz w9, #0, hce_on
        subs x10, x10, #1
        b.ne 1b
        b fail_early

    hce_on:
        // Disable Auto-Hibernate immediately
        str wzr, [x8, #0x18]
        dsb sy

        mov w13, #2
    link_startup_loop:
        // Step 1: Wait for UCRDY (HCS bit 3)
        mov w14, #1
        mov x10, #0x100000
    wait_ucrdy:
        ldr w9, [x8, #0x30]
        tbnz w9, #3, ucrdy_ok
        subs x10, x10, #1
        b.ne wait_ucrdy
        b link_retry_or_fail

    ucrdy_ok:
        // Clear IS and error registers
        mvn w9, wzr
        str w9, [x8, #0x20]
        ldr w9, [x8, #0x38]
        ldr w9, [x8, #0x3c]

        str wzr, [x8, #0x94]
        str wzr, [x8, #0x98]
        str wzr, [x8, #0x9c]
        dsb sy

        // Issue DME_LINK_STARTUP (0x16)
        mov w9, #0x16
        str w9, [x8, #0x90]
        dsb sy

        // Step 2: Wait for UCCS (bit 10) or ULSS (bit 8)
        mov w14, #2
        mov x10, #0x200000
    wait_uccs:
        ldr w9, [x8, #0x20]
        tbnz w9, #10, uccs_ok
        tbnz w9, #8, uccs_ok
        subs x10, x10, #1
        b.ne wait_uccs
        b link_retry_or_fail

    uccs_ok:
        // Clear UECPA once due to LINERESET during LINK_STARTUP (Linux ufshcd.c line 4825)
        ldr w9, [x8, #0x38]

        // Clear IS
        mvn w9, wzr
        str w9, [x8, #0x20]
        dsb sy

        // Step 3: Check DEVICE_PRESENT (HCS bit 0)
        ldr w10, [x8, #0x30]
        tbnz w10, #0, link_startup_ok
        mov w14, #3
        b link_retry_or_fail

    link_startup_ok:
        subs w13, w13, #1
        b.ne link_startup_loop

        // Success print (Apple ARM64 ABI: stack-passed variadic arguments)
        ldr w1, [x8, #0x98]
        and w1, w1, #0xff
        ldr w2, [x8, #0x30]
        sub sp, sp, #32
        stp x29, x30, [sp, #16]
        str x1, [sp]
        str x2, [sp, #8]
        adr x0, str_success
    _bl_success:
        bl 0
        ldp x29, x30, [sp, #16]
        add sp, sp, #32
    _b_continue:
        b 0

    link_retry_or_fail:
        subs w13, w13, #1
        b.gt link_startup_loop

    fail_early:
        ldr w1, [x8, #0x98]
        sub sp, sp, #32
        stp x29, x30, [sp, #16]
        str x14, [sp]
        str x1, [sp, #8]
        adr x0, str_fail
    _bl_fail:
        bl 0
        ldp x29, x30, [sp, #16]
        add sp, sp, #32
    _b_fail:
        b 0

    fail_mmio_null:
        sub sp, sp, #16
        stp x29, x30, [sp]
        adr x0, str_fail_null
    _bl_fail_null:
        bl 0
        ldp x29, x30, [sp], #16
    _b_fail_null:
        b 0

    str_success:
        .asciz "ufs_mtk: link startup OK (arg2=0x%02x, hcs=0x%08x)\n"
        .align 2
    str_fail:
        .asciz "ufs_mtk: link startup FAILED step=%d (arg2=0x%02x)\n"
        .align 2
    str_fail_null:
        .asciz "ufs_mtk: link startup FAILED (NULL mmio)\n"
        .align 2
    '''
    hce_bytes, syms = assemble_with_symbols(hce_helper_code)
    hce_addr = 0x447d10
    printf_addr = 0x2ddbc0
    target_continue = 0x4cad9c
    target_fail = 0x4cee48  # clean function exit, bypasses misleading "host controller not enabled" print

    hce_bytes[syms['_bl_success'] : syms['_bl_success'] + 4] = calc_bl(hce_addr + syms['_bl_success'], printf_addr)
    hce_bytes[syms['_bl_fail'] : syms['_bl_fail'] + 4] = calc_bl(hce_addr + syms['_bl_fail'], printf_addr)
    hce_bytes[syms['_bl_fail_null'] : syms['_bl_fail_null'] + 4] = calc_bl(hce_addr + syms['_bl_fail_null'], printf_addr)
    hce_bytes[syms['_b_continue'] : syms['_b_continue'] + 4] = calc_b(hce_addr + syms['_b_continue'], target_continue)
    hce_bytes[syms['_b_fail'] : syms['_b_fail'] + 4] = calc_b(hce_addr + syms['_b_fail'], target_fail)
    hce_bytes[syms['_b_fail_null'] : syms['_b_fail_null'] + 4] = calc_b(hce_addr + syms['_b_fail_null'], target_fail)

    assert len(hce_bytes) <= 752
    data[hce_addr : hce_addr + len(hce_bytes)] = hce_bytes
    data[0x4cad80 : 0x4cad84] = calc_b(0x4cad80, hce_addr)
    print(f"[+] Injected UFSHCI auto-enable + DME_LINK_STARTUP hook at 0x4cad80 -> helper at 0x{hce_addr:x} ({len(hce_bytes)} bytes)")

    # 24. Fix UPIU_FLAG_READ in _mtk_ufs_read_hw at 0xfffffff0074cf1c0 (file offset 0x4cb1c0):
    # Stock binary had `mov w8, #8193` (0x2001, opcode 28008452), setting UPIU Command Flags = 0x20 (UPIU_FLAG_WRITE).
    # This caused UFSHCI OCS = 0x05 (OCS_PEER_COMM_FAILURE) because the SCSI command is READ(10) (0x28) and
    # UTRD Data Direction is IN (0x14000000).
    # Patch to `mov w8, #16385` (0x4001, opcode 28008852) to set UPIU_FLAG_READ = 0x40.
    orig_upiu_flag = bytes.fromhex("28008452")
    assert data[0x4cb1c0 : 0x4cb1c4] == orig_upiu_flag, f"Unexpected at 0x4cb1c0: {data[0x4cb1c0:0x4cb1c4].hex()}"
    data[0x4cb1c0 : 0x4cb1c4] = bytes.fromhex("28008852")
    print("[+] Patched UPIU_FLAG_READ at 0x4cb1c0: 0x2001 -> 0x4001 (UPIU_FLAG_READ = 0x40)")

    # 25. Patch _mtk_ufs_read_hw:
    # 25a. Wait for HCS.UTRLRDY before ringing Doorbell:
    # At 0x4cb288 (VA 0xfffffff0074cf288): replace `b.eq #0x4cb31c` with `b.eq #0x4cb318`
    orig_beq = bytes.fromhex("a0040054")
    assert data[0x4cb288 : 0x4cb28c] == orig_beq, f"Unexpected at 0x4cb288: {data[0x4cb288:0x4cb28c].hex()}"
    data[0x4cb288 : 0x4cb28c] = bytes.fromhex("80040054")

    # At 0x4cb318 (VA 0xfffffff0074cf318): replace `dsb sy; dsb sy` with poll loop:
    # ldr w10, [x8, #0x30]; tbz w10, #1, 0xfffffff0074cf318
    orig_dsbs = bytes.fromhex("9f3f03d59f3f03d5")
    assert data[0x4cb318 : 0x4cb320] == orig_dsbs, f"Unexpected at 0x4cb318: {data[0x4cb318:0x4cb320].hex()}"
    data[0x4cb318 : 0x4cb320] = bytes.fromhex("0a3140b9eaff0f36")
    print("[+] Patched _mtk_ufs_read_hw to poll HCS.UTRLRDY before ringing Doorbell")

    # 25b. Hook error path at 0x4cb3c4 to recovery_hook in code cave at 0x448810:
    orig_stp = bytes.fromhex("f32300a9")  # stp x19, x8, [sp]
    assert data[0x4cb3c4 : 0x4cb3c8] == orig_stp, f"Unexpected at 0x4cb3c4: {data[0x4cb3c4:0x4cb3c8].hex()}"

    recovery_hook_asm = r'''
        // Target VA: 0xfffffff00744c810 (file offset 0x448810)
        // Invoked from 0xfffffff0074cf3c4 when OCS != 0
        // Inputs: x19 = lba, w8 = ocs, x22 = utrd_buf, x25 = ufs_mmio_holder, sp has caller frame
        sub sp, sp, #48
        stp x29, x30, [sp, #32]
        stp x20, x21, [sp, #16]
        stp x23, x24, [sp]

        // Get ufs_mmio
        ldr x20, [x25, #0x10]       // x20 = ufs_mmio

        // Clear IS errors
        mvn w10, wzr
        str w10, [x20, #0x20]
        dsb sy

        // Read UECPA & UECDL to clear them
        ldr w3, [x20, #0x38]
        ldr w4, [x20, #0x3c]

        // Wait for UCRDY (HCS bit 3)
        mov x10, #0x100000
    rec_wait_ucrdy:
        ldr w11, [x20, #0x30]
        tbnz w11, #3, rec_ucrdy_ok
        subs x10, x10, #1
        b.ne rec_wait_ucrdy
        b rec_fail_timeout

    rec_ucrdy_ok:
        // Issue DME_LINK_STARTUP (0x16)
        str wzr, [x20, #0x94]
        str wzr, [x20, #0x98]
        str wzr, [x20, #0x9c]
        dsb sy
        mov w10, #0x16
        str w10, [x20, #0x90]
        dsb sy

        // Wait for UIC command completion (IS bit 10 or bit 8)
        mov x10, #0x200000
    rec_wait_uccs:
        ldr w11, [x20, #0x20]
        tbnz w11, #10, rec_uccs_ok
        tbnz w11, #8, rec_uccs_ok
        subs x10, x10, #1
        b.ne rec_wait_uccs
        b rec_fail_timeout

    rec_uccs_ok:
        // Clear UECPA once due to LINERESET during LINK_STARTUP
        ldr w11, [x20, #0x38]

        // Clear IS
        mvn w10, wzr
        str w10, [x20, #0x20]
        dsb sy

        // Reset OCS to 0x0f (OCS_INVALID) in utrd_buf
        mov w10, #0x0f
        strb w10, [x22, #8]
        dsb sy

        // Flush cache for utrd_buf
        mov x0, x22
        mov w1, #0x20
    _bl_flush:
        bl 0                        // FlushPoC_DcacheRegion(0xfffffff00743c324)

        // Wait for HCS.UTRLRDY before ringing Doorbell
        mov x10, #0x100000
    rec_wait_utrlrdy:
        ldr w11, [x20, #0x30]
        tbnz w11, #1, rec_utrlrdy_ok
        subs x10, x10, #1
        b.ne rec_wait_utrlrdy

    rec_utrlrdy_ok:
        // Re-ring doorbell (slot 0)
        mov w10, #1
        str w10, [x20, #0x58]
        dsb sy

        // Wait for doorbell to clear
        mov x10, #0x200000
    rec_wait_dbr:
        ldr w11, [x20, #0x58]
        tbz w11, #0, rec_dbr_ok     // doorbell cleared!
        subs x10, x10, #1
        b.ne rec_wait_dbr
        b rec_fail_timeout          // doorbell timeout

    rec_dbr_ok:
        // Clear completion notification
        mov w10, #1
        str w10, [x20, #0x64]
        dsb sy

        // Clear IS
        mvn w10, wzr
        str w10, [x20, #0x20]
        dsb sy

        // Invalidate cache for utrd_buf & data_buf
        mov x0, x22
        mov w1, #0x20
    _bl_flush2:
        bl 0                        // FlushPoC_DcacheRegion

        mov x0, #0xa000
        movk x0, #0x07e9, lsl #16
        movk x0, #0xfff0, lsl #32
        movk x0, #0xffff, lsl #48
        mov w1, #0x1000
    _bl_flush3:
        bl 0                        // FlushPoC_DcacheRegion

        // Check new OCS
        ldrb w8, [x22, #8]
        cbz w8, rec_success         // OCS == 0: RETRY SUCCEEDED!

    rec_fail_timeout:
        // Retry failed or timed out: print detailed diagnostics
        ldr w2, [x20, #0x20]        // IS
        ldr w3, [x20, #0x38]        // UECPA
        ldr w4, [x20, #0x3c]        // UECDL
        ldr w5, [x20, #0x44]        // UECT
        ldr w6, [x20, #0x30]        // HCS

        sub sp, sp, #64
        str x19, [sp]               // lba
        str x8,  [sp, #8]           // ocs
        str x2,  [sp, #16]          // is
        str x4,  [sp, #24]          // dl
        str x3,  [sp, #32]          // pa
        str x5,  [sp, #40]          // t
        str x6,  [sp, #48]          // hcs

        adr x0, str_detail_fail
    _bl_printf:
        bl 0                        // printf (0xfffffff0072e1bc0)

        add sp, sp, #64
        ldp x23, x24, [sp]
        ldp x20, x21, [sp, #16]
        ldp x29, x30, [sp, #32]
        add sp, sp, #48

        // Return failure: go to 0xfffffff0074cf424 (returns EIO / 5)
    _b_fail:
        b 0

    rec_success:
        // SUCCESS! Restore stack and jump to 0xfffffff0074cf3d4 (success path)
        ldp x23, x24, [sp]
        ldp x20, x21, [sp, #16]
        ldp x29, x30, [sp, #32]
        add sp, sp, #48
    _b_success:
        b 0

    str_detail_fail:
        .asciz "ufs_mtk: read fail lba=%llu ocs=%02x is=%08x dl=%08x pa=%08x t=%08x hcs=%08x\n"
        .align 2
    '''

    rec_bytes, rec_syms = assemble_with_symbols(recovery_hook_asm)
    rec_addr = 0x448810
    flush_addr = 0x438324
    target_fail = 0x4cb424
    target_success = 0x4cb3d4

    rec_bytes[rec_syms['_bl_flush'] : rec_syms['_bl_flush'] + 4] = calc_bl(rec_addr + rec_syms['_bl_flush'], flush_addr)
    rec_bytes[rec_syms['_bl_flush2'] : rec_syms['_bl_flush2'] + 4] = calc_bl(rec_addr + rec_syms['_bl_flush2'], flush_addr)
    rec_bytes[rec_syms['_bl_flush3'] : rec_syms['_bl_flush3'] + 4] = calc_bl(rec_addr + rec_syms['_bl_flush3'], flush_addr)
    rec_bytes[rec_syms['_bl_printf'] : rec_syms['_bl_printf'] + 4] = calc_bl(rec_addr + rec_syms['_bl_printf'], printf_addr)
    rec_bytes[rec_syms['_b_fail'] : rec_syms['_b_fail'] + 4] = calc_b(rec_addr + rec_syms['_b_fail'], target_fail)
    rec_bytes[rec_syms['_b_success'] : rec_syms['_b_success'] + 4] = calc_b(rec_addr + rec_syms['_b_success'], target_success)

    assert len(rec_bytes) <= 2032
    data[rec_addr : rec_addr + len(rec_bytes)] = rec_bytes
    data[0x4cb3c4 : 0x4cb3c8] = calc_b(0x4cb3c4, rec_addr)
    print(f"[+] Injected UFS error recovery hook at 0x4cb3c4 -> cave at 0x{rec_addr:x} ({len(rec_bytes)} bytes)")

    with open(kernel_out, 'wb') as f:
        f.write(data)
    print(f"[+] Successfully wrote clean patched kernel ({len(data)} bytes) to: {kernel_out}")

if __name__ == '__main__':
    main()
