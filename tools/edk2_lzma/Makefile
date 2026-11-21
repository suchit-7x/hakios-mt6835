CC ?= gcc
CFLAGS ?= -O2 -Wall -D_7ZIP_ST

all: edk2_lzma_compress

edk2_lzma_compress: edk2_lzma_compress.c LzmaEnc.c LzmaDec.c LzFind.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f edk2_lzma_compress

.PHONY: all clean
