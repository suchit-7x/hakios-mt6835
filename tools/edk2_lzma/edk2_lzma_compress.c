#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "LzmaEnc.h"
#include "LzmaDec.h"

static void *SzAlloc(void *p, size_t size) { (void)p; return malloc(size); }
static void SzFree(void *p, void *address) { (void)p; free(address); }
static ISzAlloc g_Alloc = { SzAlloc, SzFree };

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input_raw_fv> <output_lzma>\n", argv[0]);
        return 1;
    }

    FILE *f_in = fopen(argv[1], "rb");
    if (!f_in) { perror("fopen input"); return 1; }
    fseek(f_in, 0, SEEK_END);
    size_t in_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);

    uint8_t *in_buf = (uint8_t *)malloc(in_size);
    if (fread(in_buf, 1, in_size, f_in) != in_size) {
        perror("fread input");
        return 1;
    }
    fclose(f_in);

    // Prepare compression properties matching EDK2
    CLzmaEncProps props;
    LzmaEncProps_Init(&props);
    props.level = 9;
    props.dictSize = 16 * 1024 * 1024; // 16 MiB
    props.lc = 3;
    props.lp = 0;
    props.pb = 2;
    props.fb = 64;
    props.writeEndMark = 0; // CRITICAL: EDK2 MUST have no EOPM
    props.numThreads = 1;

    size_t props_size = LZMA_PROPS_SIZE;
    uint8_t props_encoded[LZMA_PROPS_SIZE];

    size_t dest_size = in_size + (in_size / 3) + 128 * 1024;
    uint8_t *dest_buf = (uint8_t *)malloc(dest_size);

    SRes res = LzmaEncode(
        dest_buf, &dest_size,
        in_buf, in_size,
        &props,
        props_encoded, &props_size,
        0, // writeEndMark = 0
        NULL, &g_Alloc, &g_Alloc
    );

    if (res != SZ_OK) {
        fprintf(stderr, "LzmaEncode failed: %d\n", res);
        return 1;
    }

    printf("Compression OK: in=%zu -> out=%zu (props_size=%zu)\n", in_size, dest_size, props_size);

    // Verify self-decompression with LzmaDecode
    uint8_t *decomp_buf = (uint8_t *)malloc(in_size);
    SizeT out_proc = in_size;
    SizeT in_proc = dest_size;
    ELzmaStatus status;

    res = LzmaDecode(
        decomp_buf, &out_proc,
        dest_buf, &in_proc,
        props_encoded, props_size,
        LZMA_FINISH_END,
        &status,
        &g_Alloc
    );

    if (res != SZ_OK || out_proc != in_size || memcmp(decomp_buf, in_buf, in_size) != 0) {
        fprintf(stderr, "Verification decompress FAILED: res=%d, out_proc=%zu, status=%d\n", res, out_proc, status);
        return 1;
    }
    printf("Self-verification with LzmaDecode SUCCESS!\n");
    free(decomp_buf);

    // Write EDK2 LZMA format: 5 bytes props + 8 bytes uncompressed size LE + dest_buf
    FILE *f_out = fopen(argv[2], "wb");
    if (!f_out) { perror("fopen output"); return 1; }
    fwrite(props_encoded, 1, 5, f_out);

    uint64_t in_size64 = (uint64_t)in_size;
    uint8_t size_le[8];
    for (int i = 0; i < 8; i++) {
        size_le[i] = (uint8_t)((in_size64 >> (i * 8)) & 0xFF);
    }
    fwrite(size_le, 1, 8, f_out);
    fwrite(dest_buf, 1, dest_size, f_out);
    fclose(f_out);

    printf("Wrote %zu bytes to %s\n", 5 + 8 + dest_size, argv[2]);
    free(in_buf);
    free(dest_buf);
    return 0;
}
