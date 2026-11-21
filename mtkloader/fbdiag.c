/*
 * fbdiag: bare-metal probe of the MT6835 display path on REDMI 13C 5G (air).
 * Booted by LK as a Linux arm64 Image (MMU and caches off).
 * Results go on screen and into the ramoops console; after FBDIAG_SECONDS it
 * moves Android's kernel down to _start and boots Android normally.
 */
#include <stdint.h>
#include "mtkdbg.h"

#define FBDIAG_SECONDS 5

#define CHAIN_OFFSET  0x40000u
#define STUB_PA       0x4a000000ULL

extern char _start[];
extern char chain_stub[], chain_stub_end[];
static uint64_t chain_dtb;

static uint64_t sysreg_el(void)
{
	uint64_t v;
	__asm__ volatile("mrs %0, CurrentEL" : "=r"(v));
	return (v >> 2) & 3;
}

static void report_sysregs(void)
{
	uint64_t el = sysreg_el(), sctlr, cpacr = 0, mpidr;

	if (el == 2) {
		__asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
	} else {
		__asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
	}
	__asm__ volatile("mrs %0, cpacr_el1" : "=r"(cpacr));
	__asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
	dbg_puts("EL");
	dbg_dec(el);
	dbg_puts(" SCTLR=");
	dbg_hex(sctlr, 8);
	dbg_puts(" CPACR=");
	dbg_hex(cpacr, 8);
	dbg_puts(" MPIDR=");
	dbg_hex(mpidr, 8);
	dbg_puts(" CNTFRQ=");
	dbg_dec(dbg_freq());
	dbg_putc('\n');
}

static void bar(uint32_t y, uint32_t color, const char *label)
{
	fb_rect(0, y, PANEL_W, 48, color);
	uint32_t saved_y = fbc.y, saved_x = fbc.x, saved_bg = fbc.bg, saved_fg = fbc.fg;
	uint64_t saved_base = fbc.base;
	fbc.x = 16;
	fbc.y = y + 8;
	fbc.bg = 0xff000000u;
	fbc.fg = 0xffffffffu;
	while (*label) {
		fbcon_putc(*label++);
	}
	fbc.x = saved_x;
	fbc.y = saved_y;
	fbc.bg = saved_bg;
	fbc.fg = saved_fg;
	fbc.base = saved_base;
}

static void __attribute__((noreturn)) chain_android(void)
{
	const volatile uint32_t *img = (const volatile uint32_t *)((uint64_t)_start + CHAIN_OFFSET);
	uint64_t image_size;

	if (img[14] != 0x644d5241u) { /* "ARM\x64" */
		dbg_puts("no Linux Image to chain to: warm reset\n");
		dbg_delay_ms(3000);
		wdt_reset();
	}
	/* Copy text and data; Linux clears its own BSS. The packer stored the Image's file length
	 * in this program's own header (res2, offset 0x28). */
	const volatile uint32_t *hdr = (const volatile uint32_t *)_start;
	image_size = ((uint64_t)hdr[11] << 32 | hdr[10]);
	image_size = (image_size + 7) & ~7ULL;
	dbg_puts("chaining to Android kernel, ");
	dbg_dec(image_size);
	dbg_puts(" bytes\n");

	uint64_t entry = (uint64_t)_start;
	volatile uint32_t *dst = (volatile uint32_t *)STUB_PA;
	const volatile uint32_t *src = (const volatile uint32_t *)chain_stub;
	for (uint64_t i = 0; i < (uint64_t)(chain_stub_end - chain_stub) / 4; i++) {
		dst[i] = src[i];
	}
	__asm__ volatile("dsb sy; ic iallu; dsb sy; isb" ::: "memory");
	void (*stub)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) = (void *)STUB_PA;
	stub(chain_dtb, entry, (uint64_t)img, image_size, entry);
	__builtin_unreachable();
}

void fbdiag_fault(uint64_t vec, uint64_t esr, uint64_t elr, uint64_t far)
{
	fbc.fg = 0xffff4040u;
	dbg_puts("\n*** FAULT vec=");
	dbg_hex(vec, 3);
	dbg_puts(" ESR=");
	dbg_hex(esr, 8);
	dbg_puts(" ELR=");
	dbg_hex(elr, 10);
	dbg_puts(" FAR=");
	dbg_hex(far, 10);
	dbg_puts("\n");
	dbg_delay_ms(5000);
	chain_android();
}

void fbdiag_main(uint64_t dtb)
{
	wdt_disable();
	plog_reset();
	chain_dtb = dtb;

	/* Where does OVL0 layer 0 read from? Use it only if it is inside DRAM. */
	uint32_t l0_addr = rd32(OVL0_BASE + OVL_L0_ADDR);
	uint32_t l0_pitch = rd32(OVL0_BASE + OVL_L0_PITCH) & 0xffff;
	uint32_t l0_con = rd32(OVL0_BASE + OVL_L0_CON);
	uint64_t fb = LK_FB_BASE;
	uint32_t pitch = LK_FB_PITCH;
	if (l0_addr >= 0x40000000ULL && l0_pitch >= PANEL_W * 4 && l0_pitch <= 8192) {
		fb = l0_addr;
		pitch = l0_pitch;
	}

	/* Leave the logo's top part; the report goes below a band of test bars. */
	fbcon_init(fb, pitch, 560, 1);
	fb_rect(0, 0, PANEL_W, 560, 0xff000000u);
	bar(0, 0xffff0000u, "A: red   alpha=ff");
	bar(56, 0xff00ff00u, "B: green alpha=ff");
	bar(112, 0xff0000ffu, "C: blue  alpha=ff");
	bar(168, 0x00ffffffu, "D: white alpha=00");
	bar(224, 0x80ffffffu, "E: white alpha=80");
	bar(280, 0xffffffffu, "F: white alpha=ff");
	fbc.scale = 2;
	fbc.y = 360;
	fbc.x = 0;
	fbc.fg = 0xff40ff40u;
	dbg_puts("HakiOS fbdiag: MT6835 air\n");
	fbc.scale = 1;
	fbc.y = 560;
	fbc.x = 0;
	fbc.fg = 0xffffffffu;

	dbg_puts("== fbdiag (REDMI 13C 5G MT6835 air) ==\nx0(dtb)=");
	dbg_hex(dtb, 10);
	dbg_putc('\n');
	report_sysregs();
	dbg_puts("OVL0 L0_ADDR=");
	dbg_hex(l0_addr, 8);
	dbg_puts(" L0_PITCH=");
	dbg_hex(l0_pitch, 4);
	dbg_puts(" L0_CON=");
	dbg_hex(l0_con, 8);
	dbg_puts("\n");

	/* Per-pixel alpha off on layer 0: constant alpha 0xff stays. */
	wr32(OVL0_BASE + OVL_L0_CON, l0_con & ~(1u << 8));
	dbg_delay_ms(50);

	for (int s = FBDIAG_SECONDS; s > 0; s--) {
		dbg_puts("Android boots in ");
		dbg_dec(s);
		dbg_puts(" s...\n");
		dbg_delay_ms(1000);
	}
	dbg_puts("Handing off to Android GKI kernel...\n");
	dbg_delay_ms(100);
	chain_android();
}
