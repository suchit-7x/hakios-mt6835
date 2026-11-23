#!/usr/bin/env python3
import subprocess, capstone, shutil, os

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

    # 1. Kernel entry hook (PURPLE bar) at 0x41A4B4A8 (offset 0x4474a8)
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
    # Embed KERNEL.adt directly into __BOOTDATA zero padding at file offset 0xb20000 (KVA 0xfffffff007f9c000)
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
        movk w10, #0x00ff, lsl #16
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
    # At 0x44a4a8: b 0x41A4B4D0
    branch_to_cyan = assemble('''
    target:
    .space 12248
    _branch:
        b target
    ''')[12248:12252]
    data[0x44a4a8 : 0x44a4a8 + 4] = branch_to_cyan
    data[0x44a4ac : 0x44a4ac + 8] = bytes.fromhex('1f2003d5' * 2) # NOP out old sub and ret
    print("[+] Injected CYAN probe + ADT injection at 0x4474d0 and hooked start.s exit at 0x44a4a8")

    # 6. loader_checkpoint(n) hook (LIME GREEN bars) at 0xfffffff0074611e4 (offset 0x45d1e4)
    # Checkpoints 0..45 will draw from 0xff25f000 (Row 156) to 0xff34b000 (Row 489)
    cp_bytes = assemble('''
        stp x9, x10, [sp, #-32]!
        stp x11, x12, [sp, #16]
        and x9, x0, #0x3f
        mov x10, #0x4800
        mul x9, x9, x10
        mov x11, #0xf000
        movk x11, #0xff25, lsl #16
        add x11, x11, x9
        mov w10, #0xcd32
        movk w10, #0xff32, lsl #16
        mov x9, #0x4800
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
        ldp x11, x12, [sp, #16]
        ldp x9, x10, [sp], #32
        ret
    ''')
    assert len(cp_bytes) <= 68
    data[0x45d1e4 : 0x45d1e4 + len(cp_bytes)] = cp_bytes
    print("[+] Injected loader_checkpoint progress probe at 0x45d1e4")

    # 7. Exception hook (MAGENTA box with 2x text for ELR and FAR)
    # Placed at NOP padding: 0xfffffff007447004 (file offset 0x443004)
    # Hooked from fleh_synchronous_sp1 (0xfffffff0074486e4) and fleh_serror (0xfffffff0074486a0)
    exc_handler = assemble('''
        /* Read exception state */
        mrs x19, elr_el1
        mrs x20, esr_el1
        mrs x21, far_el1

        /* Load FB base KVA & rowbytes from vinfo at 0xfffffff007b2afb8 */
        mov x8, #0xafb8
        movk x8, #0x07b2, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        ldr x11, [x8]
        ldr w9, [x8, #-4]
        cbnz x11, 1f
        mov x11, #0xf000
        movk x11, #0xff1f, lsl #16
    1:  cbnz w9, 2f
        mov w9, #2944
    2:
        /* Fill background box with Magenta (0xffff00ff) from Row 580 to Row 720 (140 rows) */
        mov w10, #580
        madd x1, x9, x10, x11
        mov w10, #0x00ff
        movk w10, #0xffff, lsl #16
        mov w12, #140
    eb_loop:
        mov x17, x1
        mov x8, x9
    3:  str w10, [x17], #4
        subs x8, x8, #4
        b.hi 3b
        add x1, x1, x9
        subs w12, w12, #1
        b.ne eb_loop

        adr x12, exc_font_table

        /* Text color: White 0xffffffff */
        mov w14, #0xffff
        movk w14, #0xffff, lsl #16

        /* Line 1 at Row 600, X=32: ELR */
        mov w10, #600
        madd x13, x9, x10, x11
        add x13, x13, #(32 * 4)

        /* 'E' (14), 'L' (16), 'R' (20), ':' (18) */
        mov w15, #14
        bl exc_draw_glyph
        mov w15, #16
        bl exc_draw_glyph
        mov w15, #20
        bl exc_draw_glyph
        mov w15, #18
        bl exc_draw_glyph

        /* 16 hex digits of x19 (ELR) */
        mov w22, #16
    elr_loop:
        lsr x15, x19, #60
        and x15, x15, #0xf
        bl exc_draw_glyph
        lsl x19, x19, #4
        subs w22, w22, #1
        b.ne elr_loop

        /* Line 2 at Row 650, X=32: FAR */
        mov w10, #650
        madd x13, x9, x10, x11
        add x13, x13, #(32 * 4)

        /* 'F' (15), 'A' (10), 'R' (20), ':' (18) */
        mov w15, #15
        bl exc_draw_glyph
        mov w15, #10
        bl exc_draw_glyph
        mov w15, #20
        bl exc_draw_glyph
        mov w15, #18
        bl exc_draw_glyph

        /* 16 hex digits of x21 (FAR) */
        mov w22, #16
    far_loop:
        lsr x15, x21, #60
        and x15, x15, #0xf
        bl exc_draw_glyph
        lsl x21, x21, #4
        subs w22, w22, #1
        b.ne far_loop

        dsb sy
        isb

    exc_spin:
        b exc_spin

    exc_draw_glyph:
        and x15, x15, #0x1f
        lsl x15, x15, #4
        add x15, x15, x12
        mov x16, x13
        mov w17, #16
    edc_row:
        ldrb w18, [x15], #1
        mov x1, x16
        mov w2, #8
    edc_col:
        tbz w18, #0, edc_skip
        str w14, [x1]
        str w14, [x1, #4]
        str w14, [x1, x9]
        add x3, x1, x9
        str w14, [x3, #4]
    edc_skip:
        lsr w18, w18, #1
        add x1, x1, #8
        subs w2, w2, #1
        b.ne edc_col
        add x16, x16, x9, lsl #1
        subs w17, w17, #1
        b.ne edc_row
        add x13, x13, #64
        ret

    .align 4
    exc_font_table:
    /* 0 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x6b, 0x6b, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 1 */ .byte 0x00, 0x00, 0x18, 0x1e, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00
    /* 2 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x60, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* 3 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x60, 0x60, 0x3c, 0x60, 0x60, 0x60, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 4 */ .byte 0x00, 0x00, 0x30, 0x38, 0x3c, 0x36, 0x33, 0x7f, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00
    /* 5 */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x3f, 0x60, 0x60, 0x60, 0x60, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 6 */ .byte 0x00, 0x00, 0x3c, 0x06, 0x03, 0x03, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 7 */ .byte 0x00, 0x00, 0x7f, 0x60, 0x30, 0x30, 0x18, 0x18, 0x18, 0x0c, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00
    /* 8 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x3e, 0x63, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 9 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x7e, 0x60, 0x60, 0x60, 0x30, 0x1e, 0x00, 0x00, 0x00, 0x00
    /* A */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x7f, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00
    /* B */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3f, 0x00, 0x00, 0x00, 0x00
    /* C */ .byte 0x00, 0x00, 0x3c, 0x66, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x66, 0x3c, 0x00, 0x00, 0x00, 0x00
    /* D */ .byte 0x00, 0x00, 0x1f, 0x33, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x33, 0x1f, 0x00, 0x00, 0x00, 0x00
    /* E */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x03, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* F */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x03, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00
    /* L */ .byte 0x00, 0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* P */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00
    /* : */ .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00
    /*   */ .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    /* R */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x3f, 0x33, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00
    ''')
    assert len(exc_handler) <= 4096
    data[0x443004 : 0x443004 + len(exc_handler)] = exc_handler
    data[0x44457c : 0x444580] = calc_b(0xfffffff00744857c, 0xfffffff007447004) # _fleh_synchronous
    data[0x4446e4 : 0x4446e8] = calc_b(0xfffffff0074486e4, 0xfffffff007447004) # fleh_synchronous_sp1
    data[0x4446a0 : 0x4446a4] = calc_b(0xfffffff0074486a0, 0xfffffff007447004) # _fleh_serror
    data[0x44476c : 0x444770] = calc_b(0xfffffff00744876c, 0xfffffff007447004) # fleh_serror_sp1
    data[0x4446c4 : 0x4446c8] = calc_b(0xfffffff0074486c4, 0xfffffff007447004) # fleh_invalid_stack
    print("[+] Injected MAGENTA exception diagnostic handler at 0x443004 and hooked all vectors")

    # 8. Unified Assert and Panic Diagnostic Renderer
    # Located at _panic_trap_to_debugger at 0xfffffff0072bc7b0 (offset 0x2b87b0)
    # _entry_assert is at 0xfffffff0072bc7b0
    # _entry_panic  is at 0xfffffff0072bc7c0
    renderer_code = '''
    .global _entry_assert
    .global _entry_panic

    _entry_assert:
        /* x0 = file, w1 = line, x2 = expr, lr = caller PC */
        mov x19, x0
        mov w20, w1
        mov x21, lr
        b _render

    _entry_panic:
        /* x0 = fmt, lr = caller PC */
        mov x19, x0
        mov w20, wzr
        mov x21, lr

    _render:
        /* Load FB base KVA & rowbytes from vinfo */
        mov x8, #0xafb8
        movk x8, #0x07b2, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        ldr x11, [x8]
        ldr w9, [x8, #-4]
        cbnz x11, 1f
        mov x11, #0xf000
        movk x11, #0xff1f, lsl #16
    1:  cbnz w9, 2f
        mov w9, #2944
    2:
        /* Fill red box from Row 580 to Row 720 (140 rows) */
        mov w10, #580
        madd x1, x9, x10, x11
        mov w10, #0x0000
        movk w10, #0xffff, lsl #16
        mov w12, #140
    rb_loop:
        mov x17, x1
        mov x8, x9
    3:  str w10, [x17], #4
        subs x8, x8, #4
        b.hi 3b
        add x1, x1, x9
        subs w12, w12, #1
        b.ne rb_loop

        /* x12 = pointer to embedded font_table */
        adr x12, font_table

        /* Text color: White 0xffffffff */
        mov w14, #0xffff
        movk w14, #0xffff, lsl #16

        /* Line 1 at Row 600, X=32: 'A0:XXXXXXXXXXXXXXXX' */
        mov w10, #600
        madd x13, x9, x10, x11
        add x13, x13, #(32 * 4)

        /* Draw 'A' (10), '0' (0), ':' (18) */
        mov w15, #10
        bl draw_glyph
        mov w15, #0
        bl draw_glyph
        mov w15, #18
        bl draw_glyph

        /* 16 hex digits of x19 */
        mov w22, #16
    a0_hex_loop:
        lsr x15, x19, #60
        and x15, x15, #0xf
        bl draw_glyph
        lsl x19, x19, #4
        subs w22, w22, #1
        b.ne a0_hex_loop

        /* Line 2 at Row 650, X=32: 'L:XXXX  PC:XXXXXXXXXXXXXXXX' */
        mov w10, #650
        madd x13, x9, x10, x11
        add x13, x13, #(32 * 4)

        /* Draw 'L' (16), ':' (18) */
        mov w15, #16
        bl draw_glyph
        mov w15, #18
        bl draw_glyph

        /* 4 hex digits of w20 (line number) */
        mov w22, #4
        lsl w20, w20, #16
    line_hex_loop:
        lsr w15, w20, #28
        and w15, w15, #0xf
        bl draw_glyph
        lsl w20, w20, #4
        subs w22, w22, #1
        b.ne line_hex_loop

        /* Draw ' ' (19), 'P' (17), 'C' (12), ':' (18) */
        mov w15, #19
        bl draw_glyph
        mov w15, #17
        bl draw_glyph
        mov w15, #12
        bl draw_glyph
        mov w15, #18
        bl draw_glyph

        /* 16 hex digits of x21 (caller PC) */
        mov w22, #16
    pc_hex_loop:
        lsr x15, x21, #60
        and x15, x15, #0xf
        bl draw_glyph
        lsl x21, x21, #4
        subs w22, w22, #1
        b.ne pc_hex_loop

        dsb sy
        isb

    spin:
        b spin

    draw_glyph:
        /* w15 = glyph index (0..19) */
        and x15, x15, #0x1f
        lsl x15, x15, #4
        add x15, x15, x12
        mov x16, x13
        mov w17, #16
    dg_row:
        ldrb w18, [x15], #1
        mov x1, x16
        mov w2, #8
    dg_col:
        tbz w18, #0, dg_skip
        str w14, [x1]
        str w14, [x1, #4]
        str w14, [x1, x9]
        add x3, x1, x9
        str w14, [x3, #4]
    dg_skip:
        lsr w18, w18, #1
        add x1, x1, #8
        subs w2, w2, #1
        b.ne dg_col
        add x16, x16, x9, lsl #1
        subs w17, w17, #1
        b.ne dg_row
        add x13, x13, #64
        ret

    .align 4
    font_table:
    /* 0 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x6b, 0x6b, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 1 */ .byte 0x00, 0x00, 0x18, 0x1e, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00
    /* 2 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x60, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* 3 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x60, 0x60, 0x3c, 0x60, 0x60, 0x60, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 4 */ .byte 0x00, 0x00, 0x30, 0x38, 0x3c, 0x36, 0x33, 0x7f, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00
    /* 5 */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x3f, 0x60, 0x60, 0x60, 0x60, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 6 */ .byte 0x00, 0x00, 0x3c, 0x06, 0x03, 0x03, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 7 */ .byte 0x00, 0x00, 0x7f, 0x60, 0x30, 0x30, 0x18, 0x18, 0x18, 0x0c, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00
    /* 8 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x3e, 0x63, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 9 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x7e, 0x60, 0x60, 0x60, 0x30, 0x1e, 0x00, 0x00, 0x00, 0x00
    /* A */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x7f, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00
    /* B */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3f, 0x00, 0x00, 0x00, 0x00
    /* C */ .byte 0x00, 0x00, 0x3c, 0x66, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x66, 0x3c, 0x00, 0x00, 0x00, 0x00
    /* D */ .byte 0x00, 0x00, 0x1f, 0x33, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x33, 0x1f, 0x00, 0x00, 0x00, 0x00
    /* E */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x03, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* F */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x03, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00
    /* L */ .byte 0x00, 0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* P */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00
    /* : */ .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00
    /*   */ .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    '''
    renderer_bytes = assemble(renderer_code)
    assert len(renderer_bytes) <= 756
    data[0x2b87b0 : 0x2b87b0 + len(renderer_bytes)] = renderer_bytes
    print(f"[+] Injected Unified Assert/Panic renderer ({len(renderer_bytes)} bytes) at 0x2b87b0")

    # Hook _Assert at 0xa74c0c -> _entry_assert at 0x2b87b0
    b_assert = calc_b(0xfffffff007a78c0c, 0xfffffff0072bc7b0)
    data[0xa74c0c : 0xa74c10] = b_assert
    print("[+] Hooked _Assert at 0xa74c0c -> 0x2b87b0")

    # Hook _panic at 0xa74bd8 -> _entry_panic at 0x2b87c0
    b_panic = calc_b(0xfffffff007a78bd8, 0xfffffff0072bc7c0)
    data[0xa74bd8 : 0xa74bdc] = b_panic
    print("[+] Hooked _panic at 0xa74bd8 -> 0x2b87c0")

    # Hook _panic_with_options at 0xa74c2c -> _entry_panic at 0x2b87c0
    b_panic_opt = calc_b(0xfffffff007a78c2c, 0xfffffff0072bc7c0)
    data[0xa74c2c : 0xa74c30] = b_panic_opt
    print("[+] Hooked _panic_with_options at 0xa74c2c -> 0x2b87c0")

    # 9. Master CPU & Topology fixes:
    # 9a. Statically initialize topology_info at file offset 0x1b25a0 (KVA 0xfffffff0071b65a0)
    # +0x5a4: num_cpus = 8
    # +0x5a8: max_cpu  = 7
    # +0x5c8: boot_cpu = 0xfffffff0071b6198 (cpu_data_entries[0])
    # +0x5d0: boot_cluster = 0xfffffff0071b6558
    data[0x1b25a4 : 0x1b25a8] = (8).to_bytes(4, 'little')
    data[0x1b25a8 : 0x1b25ac] = (7).to_bytes(4, 'little')
    data[0x1b25c8 : 0x1b25d0] = (0xfffffff0071b6198).to_bytes(8, 'little')
    data[0x1b25d0 : 0x1b25d8] = (0xfffffff0071b6558).to_bytes(8, 'little')

    # 9b. Statically initialize cpu_data_entries at file offset 0x1b2198 (KVA 0xfffffff0071b6198)
    for c in range(8):
        c_off = 0x1b2198 + c * 0x78
        data[c_off : c_off + 4] = c.to_bytes(4, 'little')
        data[c_off + 4 : c_off + 8] = c.to_bytes(4, 'little')

    # 9c. In arm_init at 0xfffffff007440dc4 (file offset 0x43cdc4):
    # Replace `bl _ml_get_boot_cpu_number` (4 bytes) with `mov w0, #0`
    patch_boot_cpu = assemble('mov w0, #0')
    assert len(patch_boot_cpu) == 4
    data[0x43cdc4 : 0x43cdc4 + 4] = patch_boot_cpu

    # 9d. In arm_init at 0xfffffff007440de0 (file offset 0x43cde0):
    # NOP out `tbnz w21, #0x1f, #0xfffffff007441328`
    data[0x43cde0 : 0x43cde4] = bytes.fromhex('1f2003d5')

    # 9e. In arm_init at 0xfffffff007440dec (file offset 0x43cdec):
    # NOP out `b.gt #0xfffffff007441328`
    data[0x43cdec : 0x43cdf0] = bytes.fromhex('1f2003d5')

    # 9f. In _ml_get_boot_cpu_number at 0xfffffff007451258 (file offset 0x44d258):
    # Force return 0
    patch_ml_boot = assemble('''
        mov w0, #0
        ret
    ''')
    data[0x44d258 : 0x44d258 + len(patch_ml_boot)] = patch_ml_boot

    # 9g. In _ml_get_cpu_number_local at 0xfffffff007451314 (file offset 0x44d314):
    # Force return 0
    patch_ml_local = assemble('''
        mov w0, #0
        ret
    ''')
    data[0x44d314 : 0x44d314 + len(patch_ml_local)] = patch_ml_local

    # 9h. In _ml_get_max_cpu_number at 0xfffffff007451390 (file offset 0x44d390):
    # Force return 7
    patch_ml_max = assemble('''
        mov w0, #7
        ret
    ''')
    data[0x44d390 : 0x44d390 + len(patch_ml_max)] = patch_ml_max
    print("[+] Applied Master CPU and Topology fixes (arm_init, ml_get_boot_cpu_number, ml_get_cpu_number_local, ml_get_max_cpu_number)")

    # 10. Entropy initialization fix:
    # 10a. PE_get_random_seed at 0xfffffff007a50148 (file offset 0xa4c148)
    # Generates 64 bytes of pseudo-random entropy into [x0] and returns w0 = 0x40 (64)
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

    # 10b. NOP out b.ls at 0xfffffff00741b2d4 (file offset 0x4172d4)
    data[0x4172d4 : 0x4172d8] = bytes.fromhex('1f2003d5')
    print("[+] NOPed out panic branch in early_random_init at 0x4172d4")

    # 11. arm_vm_prot_init bypass for missing TrustCache / AuxKC in chosen/memory-map:
    # At 0xfffffff007441e30 (file offset 0x43de30):
    # Replace `b.ne #0xfffffff0074423c4` (which asserts err == kSuccess at line 1287 / 0x507)
    # with an unconditional branch to 0xfffffff007441fdc (skipping TrustCache/AuxKC setup directly to segment protection)
    b_skip_tc = calc_b(0xfffffff007441e30, 0xfffffff007441fdc)
    data[0x43de30 : 0x43de34] = b_skip_tc
    print("[+] Patched arm_vm_prot_init at 0x43de30 to skip TrustCache/AuxKC and bypass assert line 1287")

    # 12. Video Console Text Mode & disableConsoleOutput fixes:
    # 12a. Force PE_create_console to call PE_initialize_console(&PE_state.video, kPETextMode):
    # At 0xfffffff007a5227c (file offset 0xa4e27c):
    # mov w1, #2 (41008052), nop (1f2003d5)
    patch_pe_console = assemble('''
        mov w1, #2
        nop
    ''')
    assert len(patch_pe_console) == 8
    data[0xa4e27c : 0xa4e284] = patch_pe_console
    print("[+] Patched PE_create_console at 0xa4e27c to force kPETextMode")

    # 12b. Unconditionally clear disableConsoleOutput in arm_init:
    # At 0xfffffff007441078 (file offset 0x43d078):
    # Branch directly to 0xfffffff007441090 where `str wzr, [x8]` clears disableConsoleOutput
    b_clear_dco = calc_b(0xfffffff007441078, 0xfffffff007441090)
    data[0x43d078 : 0x43d07c] = b_clear_dco
    print("[+] Patched arm_init at 0x43d078 to unconditionally clear disableConsoleOutput")

    # 12c. Patch _vc_colors 32-bit alpha byte to 0xFF (file offset 0x5228):
    # Default XNU colors in column 2 have alpha=0x00, which hardware overlay treats as transparent.
    # Setting alpha=0xFF ensures all video console text is 100% solid, crisp, and high-contrast!
    import struct
    for i in range(8):
        c_off = 0x5228 + i * 16 + 8
        c_val = struct.unpack_from('<I', data, c_off)[0]
        c_new = c_val | 0xff000000
        data[c_off : c_off + 4] = struct.pack('<I', c_new)
    print("[+] Patched _vc_colors at 0x5228 to force alpha=0xFF for all 8 console colors")

    # 13. Machine startup & Kernel Bootstrap Visual Probes:
    # Injected into free zero space at __TEXT_EXEC file offset 0xa841d0 (VA 0xfffffff007a881d0)
    probe_code = '''
    .global machine_startup_probe
    .global kdebug_probe
    .global draw_load_probe
    .global draw_init_result

    machine_startup_probe:
        /* Draw Blue bar across row 490 (0xff360000) */
        mov x11, #0x0000
        movk x11, #0xff36, lsl #16
        mov w10, #0x00ff
        movk w10, #0xff00, lsl #16
        mov x9, #0x2c00
    1:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 1b
        dsb sy
        isb

        /* Original machine_startup operations */
        stp x29, x30, [sp, #-0x10]!
        mov x29, sp
        mov x16, #0xfb64
        movk x16, #0x0744, lsl #16
        movk x16, #0xfff0, lsl #32
        movk x16, #0xffff, lsl #48
        blr x16
        ldp x29, x30, [sp], #0x10

        /* Draw Magenta bar across row 495 (0xff363000) for kernel_bootstrap transition */
        mov x11, #0x3000
        movk x11, #0xff36, lsl #16
        mov w10, #0x00ff
        movk w10, #0xffff, lsl #16
        mov x9, #0x2c00
    3:  stp w10, w10, [x11], #8
        subs x9, x9, #8
        b.hi 3b
        dsb sy
        isb

        /* Jump to kernel_bootstrap */
        mov x16, #0xe080
        movk x16, #0x072f, lsl #16
        movk x16, #0xfff0, lsl #32
        movk x16, #0xffff, lsl #48
        br x16

    .align 4
    get_fb_info:
        /* Returns x1 = FB base, w9 = rowbytes from vinfo at 0xfffffff007b2afb8 */
        mov x8, #0xafb8
        movk x8, #0x07b2, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        ldr x1, [x8]
        ldr w9, [x8, #-4]
        cbnz x1, 1f
        mov x1, #0xf000
        movk x1, #0xff1f, lsl #16
    1:  cbnz w9, 2f
        mov w9, #2944
    2:  ret

    .align 4
    kdebug_probe:
        /* Preserve registers */
        stp x29, x30, [sp, #-48]!
        stp x19, x20, [sp, #16]
        stp x21, x22, [sp, #32]
        mov x29, sp

        /* Preserve incoming string arg x0 */
        mov x21, x0

        /* Global call counter at KVA 0xfffffff007adbfc0 (in __DATA) */
        mov x8, #0xbfc0
        movk x8, #0x07ad, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        ldr w20, [x8]
        add w9, w20, #1
        str w9, [x8]

        /* Record first 4 chars into log ring in __DATA at 0xfffffff007adb000 */
        mov x8, #0xb000
        movk x8, #0x07ad, lsl #16
        movk x8, #0xfff0, lsl #32
        movk x8, #0xffff, lsl #48
        ldr w14, [x8]
        and w15, w14, #0x7f
        add w14, w14, #1
        str w14, [x8]
        mov w16, wzr
        cbz x21, 4f
        ldr w16, [x21]
    4:  add x8, x8, #4
        str w16, [x8, w15, uxtw #2]

        bl get_fb_info

        /* 1. Draw progressive status bar at row 1350/1370 */
        cmp w20, #230
        b.hs check_milestones

        /* Calculate address in framebuffer: 24 bytes (6 pixels) per tick */
        mov x10, #24
        and x11, x20, #0x7f
        mul x10, x10, x11

        cmp w20, #115
        b.hs 5f
        mov w12, #1350
        b 6f
    5:  mov w12, #1370
    6:  madd x11, x9, x12, x1
        add x11, x11, x10

        /* Color: Solid Green 0xff00ff00 */
        mov w10, #0xff00
        movk w10, #0x00ff, lsl #16

        /* Paint 12 lines high */
        mov w12, #12
    draw_meter_loop:
        stp w10, w10, [x11]
        stp w10, w10, [x11, #8]
        stp w10, w10, [x11, #16]
        add x11, x11, x9
        subs w12, w12, #1
        b.ne draw_meter_loop

    check_milestones:
        cbz x21, done_probe

        /* Load first 4 characters of message */
        ldr w13, [x21]

        /* Milestone 1: 'load' (load_context) = 0x64616f6c */
        mov w14, #0x6f6c
        movk w14, #0x6461, lsl #16
        cmp w13, w14
        b.eq draw_load

        /* Milestone 2: 'idle' (idle_thread_create) = 0x656c6469 */
        mov w14, #0x6469
        movk w14, #0x656c, lsl #16
        cmp w13, w14
        b.eq draw_idle

        /* Milestone 3: 'PE_i' (PE_init_iokit) = 0x695f4550 */
        mov w14, #0x4550
        movk w14, #0x695f, lsl #16
        cmp w13, w14
        b.eq draw_pe_iokit

        /* Milestone 4: 'mach' (machine_lockdown or machine_init) = 0x6863616d */
        mov w14, #0x616d
        movk w14, #0x6863, lsl #16
        cmp w13, w14
        b.eq draw_machine

        /* Milestone 5: 'bsd_' (bsd_init) = 0x5f647362 */
        mov w14, #0x7362
        movk w14, #0x5f64, lsl #16
        cmp w13, w14
        b.eq draw_bsd

        b done_probe

    draw_load:
        /* Row 1460: Bright Yellow (0xffffff00) */
        mov w10, #1460
        mov w14, #0xff00
        movk w14, #0xffff, lsl #16
        b draw_full_milestone_bar

    draw_idle:
        /* Row 1480: Bright Cyan (0xff00ffff) */
        mov w10, #1480
        mov w14, #0xffff
        movk w14, #0x00ff, lsl #16
        b draw_full_milestone_bar

    draw_pe_iokit:
        /* Row 1400: Bright Magenta (0xffff00ff) */
        mov w10, #1400
        mov w14, #0x00ff
        movk w14, #0xffff, lsl #16
        b draw_full_milestone_bar

    draw_machine:
        /* Row 1420: Bright Orange (0xffff8000) */
        mov w10, #1420
        mov w14, #0x8000
        movk w14, #0xffff, lsl #16
        b draw_full_milestone_bar

    draw_bsd:
        /* Row 1440: Bright White (0xffffffff) */
        mov w10, #1440
        mov w14, #0xffff
        movk w14, #0xffff, lsl #16
        b draw_full_milestone_bar

    draw_full_milestone_bar:
        bl get_fb_info
        madd x11, x9, x10, x1
        mov w12, #8
    bar_rows_loop:
        mov x17, x11
        mov x8, x9
    7:  str w14, [x17], #4
        subs x8, x8, #4
        b.hi 7b
        add x11, x11, x9
        subs w12, w12, #1
        b.ne bar_rows_loop

    done_probe:
        dsb sy
        isb

        ldp x21, x22, [sp, #32]
        ldp x19, x20, [sp, #16]
        ldp x29, x30, [sp], #48
        ret

    .global draw_load_probe
    draw_load_probe:
        stp x29, x30, [sp, #-48]!
        stp x19, x20, [sp, #16]
        stp x21, x22, [sp, #32]

        bl get_fb_info
        mov w10, #1460
        madd x11, x9, x10, x1
        mov w10, #0xff00
        movk w10, #0xffff, lsl #16
        mov w12, #8
    bar_rows_loop_load:
        mov x17, x11
        mov x8, x9
    8:  str w10, [x17], #4
        subs x8, x8, #4
        b.hi 8b
        add x11, x11, x9
        subs w12, w12, #1
        b.ne bar_rows_loop_load

        dsb sy
        isb
        ldp x21, x22, [sp, #32]
        ldp x19, x20, [sp, #16]
        ldp x29, x30, [sp], #48
        sub x21, x29, #0x70
        ret

    .global draw_init_result
    draw_init_result:
        /* Check if w0 == 0 (success) */
        cbnz w0, init_failed

        /* SUCCESS: Paint Bright Lime Green (0xff00ff00) across Row 500..520 */
        bl get_fb_info
        mov w10, #500
        madd x1, x9, x10, x1
        mov w2, #0xff00
        movk w2, #0x00ff, lsl #16
        mov w12, #20
    succ_row:
        mov x17, x1
        mov x8, x9
    9:  str w2, [x17], #4
        subs x8, x8, #4
        b.hi 9b
        add x1, x1, x9
        subs w12, w12, #1
        b.ne succ_row
        dsb sy
        isb

        /* Jump to 0xfffffff0077b3498 (success exit of load_init_program) */
        mov x16, #0x3498
        movk x16, #0x077b, lsl #16
        movk x16, #0xfff0, lsl #32
        movk x16, #0xffff, lsl #48
        br x16

    init_failed:
        /* Save errno in w25 */
        mov w25, w0

        bl get_fb_info

        /* 1. Paint large Bright RED (0xffff0000) banner across Row 600..680 */
        mov w10, #600
        madd x1, x9, x10, x1
        mov w2, #0x0000
        movk w2, #0xffff, lsl #16
        mov w12, #80
    err_bg_row:
        mov x17, x1
        mov x8, x9
    10: str w2, [x17], #4
        subs x8, x8, #4
        b.hi 10b
        add x1, x1, x9
        subs w12, w12, #1
        b.ne err_bg_row

        /* 2. Setup text rendering */
        adr x12, init_font_table
        /* Text color: White 0xffffffff */
        mov w14, #0xffff
        movk w14, #0xffff, lsl #16

        /* Row 625, X=64 */
        bl get_fb_info
        mov w10, #625
        madd x13, x9, x10, x1
        add x13, x13, #(64 * 4)

        /* Draw 'E' (14), 'R' (20), 'R' (20), ':' (18), ' ' (19) */
        mov w15, #14
        bl draw_init_glyph
        mov w15, #20
        bl draw_init_glyph
        mov w15, #20
        bl draw_init_glyph
        mov w15, #18
        bl draw_init_glyph
        mov w15, #19
        bl draw_init_glyph

        /* Draw Hex High (w25 >> 4) & 0xf */
        lsr w15, w25, #4
        and w15, w15, #0xf
        bl draw_init_glyph

        /* Draw Hex Low w25 & 0xf */
        and w15, w25, #0xf
        bl draw_init_glyph

        /* Draw ' ' (19), '(' (21) */
        mov w15, #19
        bl draw_init_glyph
        mov w15, #21
        bl draw_init_glyph

        /* Decimal tens: w25 / 10 */
        mov w8, #10
        udiv w15, w25, w8
        and w15, w15, #0xf
        bl draw_init_glyph

        /* Decimal ones: w25 % 10 = w25 - (tens * 10) */
        msub w15, w15, w8, w25
        and w15, w15, #0xf
        bl draw_init_glyph

        /* Draw ')' (22) */
        mov w15, #22
        bl draw_init_glyph

        dsb sy
        isb

    init_freeze:
        b init_freeze

    draw_init_glyph:
        and x15, x15, #0x1f
        lsl x15, x15, #4
        add x15, x15, x12
        mov x16, x13
        mov w17, #16
    dig_row:
        ldrb w18, [x15], #1
        mov x1, x16
        mov w2, #8
    dig_col:
        tbz w18, #0, dig_skip
        str w14, [x1]
        str w14, [x1, #4]
        str w14, [x1, x9]
        add x3, x1, x9
        str w14, [x3, #4]
    dig_skip:
        lsr w18, w18, #1
        add x1, x1, #8
        subs w2, w2, #1
        b.ne dig_col
        add x16, x16, x9, lsl #1
        subs w17, w17, #1
        b.ne dig_row
        add x13, x13, #64
        ret

    .align 4
    init_font_table:
    /* 0 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x6b, 0x6b, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 1 */ .byte 0x00, 0x00, 0x18, 0x1e, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00
    /* 2 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x60, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* 3 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x60, 0x60, 0x3c, 0x60, 0x60, 0x60, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 4 */ .byte 0x00, 0x00, 0x30, 0x38, 0x3c, 0x36, 0x33, 0x7f, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00
    /* 5 */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x3f, 0x60, 0x60, 0x60, 0x60, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 6 */ .byte 0x00, 0x00, 0x3c, 0x06, 0x03, 0x03, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 7 */ .byte 0x00, 0x00, 0x7f, 0x60, 0x30, 0x30, 0x18, 0x18, 0x18, 0x0c, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00
    /* 8 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x3e, 0x63, 0x63, 0x63, 0x63, 0x3e, 0x00, 0x00, 0x00, 0x00
    /* 9 */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x7e, 0x60, 0x60, 0x60, 0x30, 0x1e, 0x00, 0x00, 0x00, 0x00
    /* A (10) */ .byte 0x00, 0x00, 0x3e, 0x63, 0x63, 0x63, 0x7f, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00
    /* B (11) */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3f, 0x00, 0x00, 0x00, 0x00
    /* C (12) */ .byte 0x00, 0x00, 0x3c, 0x66, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x66, 0x3c, 0x00, 0x00, 0x00, 0x00
    /* D (13) */ .byte 0x00, 0x00, 0x1f, 0x33, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x33, 0x1f, 0x00, 0x00, 0x00, 0x00
    /* E (14) */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x03, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* F (15) */ .byte 0x00, 0x00, 0x7f, 0x03, 0x03, 0x03, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00
    /* L (16) */ .byte 0x00, 0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x7f, 0x00, 0x00, 0x00, 0x00
    /* P (17) */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x63, 0x3f, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00
    /* : (18) */ .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00
    /*   (19) */ .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    /* R (20) */ .byte 0x00, 0x00, 0x3f, 0x63, 0x63, 0x63, 0x3f, 0x33, 0x63, 0x63, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00
    /* ( (21) */ .byte 0x00, 0x00, 0x0c, 0x18, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x18, 0x0c, 0x00, 0x00, 0x00, 0x00
    /* ) (22) */ .byte 0x00, 0x00, 0x30, 0x18, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00
    '''
    probe_bytes = assemble(probe_code)
    assert len(probe_bytes) <= 2048
    data[0xa841d0 : 0xa841d0 + len(probe_bytes)] = probe_bytes
    print(f"[+] Injected Machine Startup & Kdebug visual probes ({len(probe_bytes)} bytes) at 0xa841d0")

    # Find kdebug_probe offset dynamically from nm output
    nm_out = subprocess.check_output(['aarch64-linux-gnu-nm', '/tmp/asm_probe.o']).decode()
    kdebug_off = None
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == 'kdebug_probe':
            kdebug_off = int(parts[0], 16)
            break
    assert kdebug_off is not None, "Failed to find kdebug_probe symbol"
    kdebug_kva = 0xfffffff007a881d0 + kdebug_off
    print(f"[+] kdebug_probe is at offset +{hex(kdebug_off)} (KVA {hex(kdebug_kva)})")

    # Hook machine_startup at 0xfffffff00744fe88 (file offset 0x44be88) -> machine_startup_probe (0xfffffff007a881d0)
    b_ms = calc_b(0xfffffff00744fe88, 0xfffffff007a881d0)
    data[0x44be88 : 0x44be8c] = b_ms
    print("[+] Hooked machine_startup at 0x44be88 -> 0xa841d0")

    # Hook _kernel_debug_string_early at 0xfffffff007788814 (file offset 0x784814) -> kdebug_probe
    b_kd = calc_b(0xfffffff007788814, kdebug_kva)
    data[0x784814 : 0x784818] = b_kd
    print(f"[+] Hooked _kernel_debug_string_early at 0x784814 -> {hex(kdebug_kva)}")

    # 14. NOP out `msr ttbr0_el1, x0` in set_mmu_ttb at 0xfffffff007452c68 (file offset 0x44ec68)
    # This prevents invalid_ttep from wiping TTBR0 identity mapping throughout kernel bootstrap!
    data[0x44ec68 : 0x44ec6c] = bytes.fromhex('1f2003d5')
    print("[+] NOPed out msr ttbr0_el1, x0 in set_mmu_ttb at 0x44ec68 to preserve TTBR0 mapping")

    # 15. Hook load_init_program at 0xfffffff0077b32cc (file offset 0x7af2cc) -> draw_load_probe
    load_off = None
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == 'draw_load_probe':
            load_off = int(parts[0], 16)
            break
    assert load_off is not None, "Failed to find draw_load_probe symbol"
    load_kva = 0xfffffff007a881d0 + load_off
    b_load = calc_bl(0xfffffff0077b32cc, load_kva)
    data[0x7af2cc : 0x7af2d0] = b_load
    print(f"[+] Hooked load_init_program at 0x7af2cc -> {hex(load_kva)} (offset +{hex(load_off)})")

    # 16. Patch default init binary path from /sbin/launchd to /sbin/init
    launchd_str = b'/sbin/launchd\x00'
    init_str    = b'/sbin/init\x00\x00\x00\x00'
    assert data[0xfa234 : 0xfa234 + len(launchd_str)] == launchd_str, f"Unexpected data at 0xfa234: {data[0xfa234:0xfa234+len(launchd_str)]}"
    data[0xfa234 : 0xfa234 + len(init_str)] = init_str
    print("[+] Patched /sbin/launchd -> /sbin/init at file offset 0xfa234")

    # 17. Disable code signing enforcement & AMFI restrictions across kernel
    # a) Patch _code_signing_configuration at 0xfffffff0077f5f90 (file offset 0x7f1f90)
    # Force config = 0xff (ALLOW_ANY_SIGNATURE | ENFORCEMENT_DISABLED | GET_OUT_OF_MY_WAY | UNRESTRICTED_DEBUGGING)
    cs_patch = bytes.fromhex("400000b41f0000b9610000b4e81f8052280000b9c0035fd6")
    assert len(cs_patch) == 24
    data[0x7f1f90 : 0x7f1f90 + 24] = cs_patch
    print("[+] Patched _code_signing_configuration at 0x7f1f90 to force config=0xff")

    # b) Patch _cs_process_enforcement at 0xfffffff0077948fc (file offset 0x7908fc) -> return 0
    ret_zero = bytes.fromhex("00008052c0035fd6") # mov w0, #0; ret
    data[0x7908fc : 0x7908fc + 8] = ret_zero
    print("[+] Patched _cs_process_enforcement at 0x7908fc -> return 0")

    # c) Patch _cs_system_enforcement at 0xfffffff007794950 (file offset 0x790950) -> return 0
    data[0x790950 : 0x790950 + 8] = ret_zero
    print("[+] Patched _cs_system_enforcement at 0x790950 -> return 0")

    # d) Patch _cs_process_global_enforcement at 0xfffffff00779493c (file offset 0x79093c) -> return 0
    data[0x79093c : 0x79093c + 8] = ret_zero
    print("[+] Patched _cs_process_global_enforcement at 0x79093c -> return 0")

    # e) Statically zero out cs_system_enforcement_enable and cs_process_enforcement_enable
    # at file offsets 0x1ce260 and 0x1ce264
    data[0x1ce260 : 0x1ce268] = bytes.fromhex("0000000000000000")
    print("[+] Zeroed cs_system_enforcement_enable and cs_process_enforcement_enable at 0x1ce260")

    # 18. Hook load_init_program result at 0xfffffff0077b3434 (file offset 0x7af434) -> draw_init_result
    init_res_off = None
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == 'draw_init_result':
            init_res_off = int(parts[0], 16)
            break
    assert init_res_off is not None, "Failed to find draw_init_result symbol"
    init_res_kva = 0xfffffff007a881d0 + init_res_off
    b_init_res = calc_bl(0xfffffff0077b3434, init_res_kva)
    data[0x7af434 : 0x7af438] = b_init_res
    print(f"[+] Hooked load_init_program result at 0x7af434 -> {hex(init_res_kva)} (offset +{hex(init_res_off)})")

    # 19. Mach-O Loader: Bypass LOAD_FAILURE checks in parse_machfile and load_segment
    # Check 1: !using_lcmain && validentry == 0 at 0xfffffff007848a6c (file offset 0x844a6c)
    # Original: b.eq #0xfffffff0078494f4 (40 54 00 54) -> Patch with NOP so it falls through to mov w8, #1
    assert data[0x844a6c : 0x844a70] == bytes.fromhex("40540054"), f"Unexpected at 0x844a6c: {data[0x844a6c:0x844a70].hex()}"
    data[0x844a6c : 0x844a70] = bytes.fromhex("1f2003d5") # nop
    print("[+] Patched parse_machfile check 1 (validentry check) at 0x844a6c -> nop")

    # Check 2: needs_dynlinker && !dlp at 0xfffffff0078495ac & 0xfffffff0078495b0 (file offset 0x8455ac & 0x8455b0)
    # Original: mov w9, #4 (89 00 80 52); csel w8, w8, w9, eq (08 01 89 1a)
    assert data[0x8455ac : 0x8455b0] == bytes.fromhex("89008052"), f"Unexpected at 0x8455ac: {data[0x8455ac:0x8455b0].hex()}"
    assert data[0x8455b0 : 0x8455b4] == bytes.fromhex("0801891a"), f"Unexpected at 0x8455b0: {data[0x8455b0:0x8455b4].hex()}"
    data[0x8455ac : 0x8455b0] = bytes.fromhex("09008052") # mov w9, #0
    data[0x8455b0 : 0x8455b4] = bytes.fromhex("1f2003d5") # nop
    print("[+] Patched parse_machfile check 2 (needs_dynlinker check) at 0x8455ac..0x8455b0 -> mov w9, #0; nop")

    # Check 3: thread_count == 0 at 0xfffffff007849600 (file offset 0x845600)
    # Original: lsl w3, w8, #2 (03 75 1e 53)
    assert data[0x845600 : 0x845604] == bytes.fromhex("03751e53"), f"Unexpected at 0x845600: {data[0x845600:0x845604].hex()}"
    data[0x845600 : 0x845604] = bytes.fromhex("03008052") # mov w3, #0
    print("[+] Patched parse_machfile check 3 (thread_count check) at 0x845600 -> mov w3, #0")

    # Check 4: PAGEZERO unprotect check at 0xfffffff00784af70 (file offset 0x846f70)
    # Original: mov w23, #4 (97 00 80 52)
    assert data[0x846f70 : 0x846f74] == bytes.fromhex("97008052"), f"Unexpected at 0x846f70: {data[0x846f70:0x846f74].hex()}"
    data[0x846f70 : 0x846f74] = bytes.fromhex("07008052") # mov w23, #0
    print("[+] Patched load_segment check 4 (PAGEZERO unprotect) at 0x846f70 -> mov w23, #0")

    # Check 5: PAGEZERO min_offset check at 0xfffffff00784b000 (file offset 0x847000)
    # Original: mov w23, #4 (97 00 80 52)
    assert data[0x847000 : 0x847004] == bytes.fromhex("97008052"), f"Unexpected at 0x847000: {data[0x847000:0x847004].hex()}"
    data[0x847000 : 0x847004] = bytes.fromhex("07008052") # mov w23, #0
    print("[+] Patched load_segment check 5 (PAGEZERO min_offset) at 0x847000 -> mov w23, #0")

    # Check 6: load_unixthread thread_count check at 0xfffffff00784b398 (file offset 0x847398)
    # Original: mov w0, #4 (80 00 80 52)
    assert data[0x847398 : 0x84739c] == bytes.fromhex("80008052"), f"Unexpected at 0x847398: {data[0x847398:0x84739c].hex()}"
    data[0x847398 : 0x84739c] = bytes.fromhex("00008052") # mov w0, #0
    print("[+] Patched load_unixthread check 6 (thread_count check) at 0x847398 -> mov w0, #0")

    with open(kernel_out, 'wb') as f:
        f.write(data)
    print(f"[+] Successfully wrote patched kernel to: {kernel_out}")

if __name__ == '__main__':
    main()
