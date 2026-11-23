#!/usr/bin/env python3
import subprocess, os, struct

def assemble(code):
    with open('/tmp/asm_probe.s', 'w') as f:
        f.write('.text\n' + code + '\n')
    subprocess.check_call(['aarch64-linux-gnu-as', '/tmp/asm_probe.s', '-o', '/tmp/asm_probe.o'])
    raw = subprocess.check_output(['aarch64-linux-gnu-objcopy', '-O', 'binary', '/tmp/asm_probe.o', '/tmp/asm_probe.bin'])
    with open('/tmp/asm_probe.bin', 'rb') as f:
        return f.read()

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

def main():
    kernel_orig = '/home/suchit-7x/hackios/out/mach.development.bcm2837.orig'
    kernel_out = '/home/suchit-7x/hackios/out/mach.development.bcm2837'

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
    adt_path = '/home/suchit-7x/hackios/out/KERNEL.adt'
    with open(adt_path, 'rb') as f:
        adt_data = f.read()
    assert len(adt_data) == 14048, f"Unexpected ADT length: {len(adt_data)}"
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
    # 5a. Probe 2: arm_init entry (RED bar at 0xff26f000) at 0xfffffff007447540 (file offset 0x447540)
    probe2_body = assemble('''
        mov x11, #0xf000
        movk x11, #0xff26, lsl #16
        mov w10, #0x0000
        movk w10, #0xffff, lsl #16
        mov x9, #0x5c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
        mov x19, x0
    ''')
    b_back_probe2 = calc_b(0xfffffff007447540 + len(probe2_body), 0xfffffff007440818)
    probe2 = probe2_body + b_back_probe2
    assert len(probe2) == 40
    data[0x447540 : 0x447540 + len(probe2)] = probe2
    data[0x43c814 : 0x43c818] = calc_b(0xfffffff007440814, 0xfffffff007447540)
    print("[+] Injected RED probe at arm_init entry (0x447540, hooked 0x43c814)")

    # 5b. Probe 3: PE_init_platform (MAGENTA before at 0xff27f000, LIME after at 0xff28f000) at 0xfffffff007447580 (file offset 0x447580)
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
    bl_pe_init = calc_bl(0xfffffff007447580 + len(probe3_part1), 0xfffffff007a51df4)
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
    data[0x447580 : 0x447580 + len(probe3)] = probe3
    data[0x43ccd4 : 0x43ccd8] = calc_bl(0xfffffff007440cd4, 0xfffffff007447580)
    print("[+] Injected MAGENTA/LIME probe around PE_init_platform (0x447580, hooked 0x43ccd4)")

    # 5c. Probe 4: After /chosen lookup (BLUE bar at 0xff29f000) at 0xfffffff007447600 (file offset 0x447600)
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
    b_back_probe4 = calc_b(0xfffffff007447600 + len(probe4_body), 0xfffffff007440d38)
    probe4 = probe4_body + b_back_probe4
    assert len(probe4) == 40
    data[0x447600 : 0x447600 + len(probe4)] = probe4
    data[0x43cd34 : 0x43cd38] = calc_b(0xfffffff007440d34, 0xfffffff007447600)
    print("[+] Injected BLUE probe after /chosen lookup (0x447600, hooked 0x43cd34)")

    # 5d. Probe 5: arm_vm_init (ORANGE bar at 0xff2af000) at 0xfffffff007447640 (file offset 0x447640)
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
    bl_vm_init = calc_bl(0xfffffff007447640 + len(probe5_part1), 0xfffffff007442618)
    probe5_part2 = assemble('''
        ldp x29, x30, [sp], #16
        ret
    ''')
    probe5 = probe5_part1 + bl_vm_init + probe5_part2
    assert len(probe5) == 48
    data[0x447640 : 0x447640 + len(probe5)] = probe5
    data[0x43cf38 : 0x43cf3c] = calc_bl(0xfffffff007440f38, 0xfffffff007447640)
    print("[+] Injected ORANGE probe before arm_vm_init (0x447640, hooked 0x43cf38)")

    # 6. Master CPU & Topology fixes:
    # 6a. Statically initialize topology_info at file offset 0x1b25a0 (KVA 0xfffffff0071b65a0)
    data[0x1b25a4 : 0x1b25a8] = (8).to_bytes(4, 'little')
    data[0x1b25a8 : 0x1b25ac] = (7).to_bytes(4, 'little')
    data[0x1b25c8 : 0x1b25d0] = (0xfffffff0071b6198).to_bytes(8, 'little')
    data[0x1b25d0 : 0x1b25d8] = (0xfffffff0071b6558).to_bytes(8, 'little')

    # 6b. Statically initialize cpu_data_entries at file offset 0x1b2198 (KVA 0xfffffff0071b6198)
    for c in range(8):
        c_off = 0x1b2198 + c * 0x78
        data[c_off : c_off + 4] = c.to_bytes(4, 'little')
        data[c_off + 4 : c_off + 8] = c.to_bytes(4, 'little')

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
    print("[+] Applied Master CPU and Topology fixes (arm_init, ml_get_boot_cpu_number, ml_get_cpu_number_local, ml_get_max_cpu_number)")

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

    # 8. arm_vm_prot_init bypass for missing TrustCache / AuxKC in chosen/memory-map:
    # At 0xfffffff007441e30 (file offset 0x43de30):
    b_skip_tc = calc_b(0xfffffff007441e30, 0xfffffff007441fdc)
    data[0x43de30 : 0x43de34] = b_skip_tc
    print("[+] Patched arm_vm_prot_init at 0x43de30 to skip TrustCache/AuxKC and bypass assert line 1287")

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

    # 9c. Patch _vc_colors 32-bit alpha byte to 0xFF (file offset 0x5228):
    for i in range(8):
        c_off = 0x5228 + i * 16 + 8
        c_val = struct.unpack_from('<I', data, c_off)[0]
        c_new = c_val | 0xff000000
        data[c_off : c_off + 4] = struct.pack('<I', c_new)
    print("[+] Patched _vc_colors at 0x5228 to force alpha=0xFF for all 8 console colors")

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

    with open(kernel_out, 'wb') as f:
        f.write(data)
    print(f"[+] Successfully wrote clean patched kernel ({len(data)} bytes) to: {kernel_out}")

if __name__ == '__main__':
    main()
