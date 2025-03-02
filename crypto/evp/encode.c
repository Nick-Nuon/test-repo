/*
 * Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include "crypto/evp.h"
#include "evp_local.h"

static unsigned char conv_ascii2bin(unsigned char a,
                                    const unsigned char *table);
static int evp_encodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int dlen);
static int evp_decodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int n);

#ifndef CHARSET_EBCDIC
# define conv_bin2ascii(a, table)       ((table)[(a)&0x3f])
#else
/*
 * We assume that PEM encoded files are EBCDIC files (i.e., printable text
 * files). Convert them here while decoding. When encoding, output is EBCDIC
 * (text) format again. (No need for conversion in the conv_bin2ascii macro,
 * as the underlying textstring data_bin2ascii[] is already EBCDIC)
 */
# define conv_bin2ascii(a, table)       ((table)[(a)&0x3f])
#endif

/*-
 * 64 char lines
 * pad input with 0
 * left over chars are set to =
 * 1 byte  => xx==
 * 2 bytes => xxx=
 * 3 bytes => xxxx
 */
#define BIN_PER_LINE    (64/4*3)
#define CHUNKS_PER_LINE (64/4)
#define CHAR_PER_LINE   (64+1)

static const unsigned char data_bin2ascii[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* SRP uses a different base64 alphabet */
static const unsigned char srpdata_bin2ascii[65] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";


/*-
 * 0xF0 is a EOLN
 * 0xF1 is ignore but next needs to be 0xF0 (for \r\n processing).
 * 0xF2 is EOF
 * 0xE0 is ignore at start of line.
 * 0xFF is error
 */

#define B64_EOLN                0xF0
#define B64_CR                  0xF1
#define B64_EOF                 0xF2
#define B64_WS                  0xE0
#define B64_ERROR               0xFF
#define B64_NOT_BASE64(a)       (((a)|0x13) == 0xF3)
#define B64_BASE64(a)           (!B64_NOT_BASE64(a))

static const unsigned char data_ascii2bin[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const unsigned char srpdata_ascii2bin[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2, 0x3E, 0x3F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
    0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

#ifndef CHARSET_EBCDIC
static unsigned char conv_ascii2bin(unsigned char a, const unsigned char *table)
{
    if (a & 0x80)
        return B64_ERROR;
    return table[a];
}
#else
static unsigned char conv_ascii2bin(unsigned char a, const unsigned char *table)
{
    a = os_toascii[a];
    if (a & 0x80)
        return B64_ERROR;
    return table[a];
}
#endif

EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_ENCODE_CTX));
}

void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx)
{
    OPENSSL_free(ctx);
}

int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, const EVP_ENCODE_CTX *sctx)
{
    memcpy(dctx, sctx, sizeof(EVP_ENCODE_CTX));

    return 1;
}

int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx)
{
    return ctx->num;
}

void evp_encode_ctx_set_flags(EVP_ENCODE_CTX *ctx, unsigned int flags)
{
    ctx->flags = flags;
}

void EVP_EncodeInit(EVP_ENCODE_CTX *ctx)
{
    ctx->length = 48;
    ctx->num = 0;
    ctx->line_num = 0;
    ctx->flags = 0;
}

int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    int i, j;
    size_t total = 0;

    *outl = 0;
    if (inl <= 0)
        return 0;
    OPENSSL_assert(ctx->length <= (int)sizeof(ctx->enc_data));
    if (ctx->length - ctx->num > inl) {
        memcpy(&(ctx->enc_data[ctx->num]), in, inl);
        ctx->num += inl;
        return 1;
    }
    if (ctx->num != 0) {
        i = ctx->length - ctx->num;
        memcpy(&(ctx->enc_data[ctx->num]), in, i);
        in += i;
        inl -= i;
        j = evp_encodeblock_int(ctx, out, ctx->enc_data, ctx->length);
        ctx->num = 0;
        out += j;
        total = j;
        if ((ctx->flags & EVP_ENCODE_CTX_NO_NEWLINES) == 0) {
            *(out++) = '\n';
            total++;
        }
        *out = '\0';
    }
    while (inl >= ctx->length && total <= INT_MAX) {
        j = evp_encodeblock_int(ctx, out, in, ctx->length);
        in += ctx->length;
        inl -= ctx->length;
        out += j;
        total += j;
        if ((ctx->flags & EVP_ENCODE_CTX_NO_NEWLINES) == 0) {
            *(out++) = '\n';
            total++;
        }
        *out = '\0';
    }
    if (total > INT_MAX) {
        /* Too much output data! */
        *outl = 0;
        return 0;
    }
    if (inl != 0)
        memcpy(&(ctx->enc_data[0]), in, inl);
    ctx->num = inl;
    *outl = total;

    return 1;
}

void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
    unsigned int ret = 0;

    if (ctx->num != 0) {
        ret = evp_encodeblock_int(ctx, out, ctx->enc_data, ctx->num);
        if ((ctx->flags & EVP_ENCODE_CTX_NO_NEWLINES) == 0)
            out[ret++] = '\n';
        out[ret] = '\0';
        ctx->num = 0;
    }
    *outl = ret;
}

static int evp_encodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int dlen)
{
    int i, ret = 0;
    unsigned long l;
    const unsigned char *table;

    if (ctx != NULL && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
        table = srpdata_bin2ascii;
    else
        table = data_bin2ascii;

    for (i = dlen; i > 0; i -= 3) {
        if (i >= 3) {
            l = (((unsigned long)f[0]) << 16L) |
                (((unsigned long)f[1]) << 8L) | f[2];
            *(t++) = conv_bin2ascii(l >> 18L, table);
            *(t++) = conv_bin2ascii(l >> 12L, table);
            *(t++) = conv_bin2ascii(l >> 6L, table);
            *(t++) = conv_bin2ascii(l, table);
        } else {
            l = ((unsigned long)f[0]) << 16L;
            if (i == 2)
                l |= ((unsigned long)f[1] << 8L);

            *(t++) = conv_bin2ascii(l >> 18L, table);
            *(t++) = conv_bin2ascii(l >> 12L, table);
            *(t++) = (i == 1) ? '=' : conv_bin2ascii(l >> 6L, table);
            *(t++) = '=';
        }
        ret += 4;
        f += 3;
    }

    *t = '\0';
    return ret;
}

int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen)
{
    return evp_encodeblock_int(NULL, t, f, dlen);
}

void EVP_DecodeInit(EVP_ENCODE_CTX *ctx)
{
    /* Only ctx->num and ctx->flags are used during decoding. */
    ctx->num = 0;
    ctx->length = 0;
    ctx->line_num = 0;
    ctx->flags = 0;
}


/*-
 * -1 for error
 *  0 for last line
 *  1 for full line
 *
 * Note: even though EVP_DecodeUpdate attempts to detect and report end of
 * content, the context doesn't currently remember it and will accept more data
 * in the next call. Therefore, the caller is responsible for checking and
 * rejecting a 0 return value in the middle of content.
 *
 * Note: even though EVP_DecodeUpdate has historically tried to detect end of
 * content based on line length, this has never worked properly. Therefore,
 * we now return 0 when one of the following is true:
 *   - Padding or B64_EOF was detected and the last block is complete.
 *   - Input has zero-length.
 * -1 is returned if:
 *   - Invalid characters are detected.
 *   - There is extra trailing padding, or data after padding.
 *   - B64_EOF is detected after an incomplete base64 block.
 */
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    int seof = 0, eof = 0, rv = -1, ret = 0, i, v, tmp, n, decoded_len;
    unsigned char *d;
    const unsigned char *table;

    n = ctx->num;
    d = ctx->enc_data;

    if (n > 0 && d[n - 1] == '=') {
        eof++;
        if (n > 1 && d[n - 2] == '=')
            eof++;
    }

     /* Legacy behaviour: an empty input chunk signals end of input. */
    if (inl == 0) {
        rv = 0;
        goto end;
    }

    if ((ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
        table = srpdata_ascii2bin;
    else
        table = data_ascii2bin;

    for (i = 0; i < inl; i++) {
        tmp = *(in++);
        v = conv_ascii2bin(tmp, table);
        if (v == B64_ERROR) {
            rv = -1;
            goto end;
        }

        if (tmp == '=') {
            eof++;
        } else if (eof > 0 && B64_BASE64(v)) {
            /* More data after padding. */
            rv = -1;
            goto end;
        }

        if (eof > 2) {
            rv = -1;
            goto end;
        }

        if (v == B64_EOF) {
            seof = 1;
            goto tail;
        }

        /* Only save valid base64 characters. */
        if (B64_BASE64(v)) {
            if (n >= 64) {
                /*
                 * We increment n once per loop, and empty the buffer as soon as
                 * we reach 64 characters, so this can only happen if someone's
                 * manually messed with the ctx. Refuse to write any more data.
                 */
                rv = -1;
                goto end;
            }
            OPENSSL_assert(n < (int)sizeof(ctx->enc_data));
            d[n++] = tmp;
        }

        if (n == 64) {
            decoded_len = evp_decodeblock_int(ctx, out, d, n);
            n = 0;
            if (decoded_len < 0 || eof > decoded_len) {
                rv = -1;
                goto end;
            }
            ret += decoded_len - eof;
            out += decoded_len - eof;
        }
    }

    /*
     * Legacy behaviour: if the current line is a full base64-block (i.e., has
     * 0 mod 4 base64 characters), it is processed immediately. We keep this
     * behaviour as applications may not be calling EVP_DecodeFinal properly.
     */
tail:
    if (n > 0) {
        if ((n & 3) == 0) {
            decoded_len = evp_decodeblock_int(ctx, out, d, n);
            n = 0;
            if (decoded_len < 0 || eof > decoded_len) {
                rv = -1;
                goto end;
            }
            ret += (decoded_len - eof);
        } else if (seof) {
            /* EOF in the middle of a base64 block. */
            rv = -1;
            goto end;
        }
    }

    rv = seof || (n == 0 && eof) ? 0 : 1;
end:
    /* Legacy behaviour. This should probably rather be zeroed on error. */
    *outl = ret;
    ctx->num = n;
    return rv;
}


const uint8_t to_base64_value[] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 64,  64,  255, 64, 64,  255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 64,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,  255,
    255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255,
    255, 255, 255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,


    10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,


    25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,


    34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,


    49,  50,  51,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,


    255};





const uint32_t d0[256] = {


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x000000f8, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x000000fc,


    0x000000d0, 0x000000d4, 0x000000d8, 0x000000dc, 0x000000e0, 0x000000e4,


    0x000000e8, 0x000000ec, 0x000000f0, 0x000000f4, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x00000000,


    0x00000004, 0x00000008, 0x0000000c, 0x00000010, 0x00000014, 0x00000018,


    0x0000001c, 0x00000020, 0x00000024, 0x00000028, 0x0000002c, 0x00000030,


    0x00000034, 0x00000038, 0x0000003c, 0x00000040, 0x00000044, 0x00000048,


    0x0000004c, 0x00000050, 0x00000054, 0x00000058, 0x0000005c, 0x00000060,


    0x00000064, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x00000068, 0x0000006c, 0x00000070, 0x00000074, 0x00000078,


    0x0000007c, 0x00000080, 0x00000084, 0x00000088, 0x0000008c, 0x00000090,


    0x00000094, 0x00000098, 0x0000009c, 0x000000a0, 0x000000a4, 0x000000a8,


    0x000000ac, 0x000000b0, 0x000000b4, 0x000000b8, 0x000000bc, 0x000000c0,


    0x000000c4, 0x000000c8, 0x000000cc, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff};





const uint32_t d1[256] = {


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x0000e003, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x0000f003,


    0x00004003, 0x00005003, 0x00006003, 0x00007003, 0x00008003, 0x00009003,


    0x0000a003, 0x0000b003, 0x0000c003, 0x0000d003, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x00000000,


    0x00001000, 0x00002000, 0x00003000, 0x00004000, 0x00005000, 0x00006000,


    0x00007000, 0x00008000, 0x00009000, 0x0000a000, 0x0000b000, 0x0000c000,


    0x0000d000, 0x0000e000, 0x0000f000, 0x00000001, 0x00001001, 0x00002001,


    0x00003001, 0x00004001, 0x00005001, 0x00006001, 0x00007001, 0x00008001,


    0x00009001, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x0000a001, 0x0000b001, 0x0000c001, 0x0000d001, 0x0000e001,


    0x0000f001, 0x00000002, 0x00001002, 0x00002002, 0x00003002, 0x00004002,


    0x00005002, 0x00006002, 0x00007002, 0x00008002, 0x00009002, 0x0000a002,


    0x0000b002, 0x0000c002, 0x0000d002, 0x0000e002, 0x0000f002, 0x00000003,


    0x00001003, 0x00002003, 0x00003003, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff};





const uint32_t d2[256] = {


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x00800f00, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x00c00f00,


    0x00000d00, 0x00400d00, 0x00800d00, 0x00c00d00, 0x00000e00, 0x00400e00,


    0x00800e00, 0x00c00e00, 0x00000f00, 0x00400f00, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x00000000,


    0x00400000, 0x00800000, 0x00c00000, 0x00000100, 0x00400100, 0x00800100,


    0x00c00100, 0x00000200, 0x00400200, 0x00800200, 0x00c00200, 0x00000300,


    0x00400300, 0x00800300, 0x00c00300, 0x00000400, 0x00400400, 0x00800400,


    0x00c00400, 0x00000500, 0x00400500, 0x00800500, 0x00c00500, 0x00000600,


    0x00400600, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,


    0x01ffffff, 0x00800600, 0x00c00600, 0x00000700, 0x00400700, 0x00800700,


    0x00c00700, 0x00000800, 0x00400800, 0x00800800, 0x00c00800, 0x00000900,
    0x00400900, 0x00800900, 0x00c00900, 0x00000a00, 0x00400a00, 0x00800a00,
    0x00c00a00, 0x00000b00, 0x00400b00, 0x00800b00, 0x00c00b00, 0x00000c00,
    0x00400c00, 0x00800c00, 0x00c00c00, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff};

const uint32_t d3[256] = {
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x003e0000, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x003f0000,
    0x00340000, 0x00350000, 0x00360000, 0x00370000, 0x00380000, 0x00390000,
    0x003a0000, 0x003b0000, 0x003c0000, 0x003d0000, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x00000000,
    0x00010000, 0x00020000, 0x00030000, 0x00040000, 0x00050000, 0x00060000,
    0x00070000, 0x00080000, 0x00090000, 0x000a0000, 0x000b0000, 0x000c0000,
    0x000d0000, 0x000e0000, 0x000f0000, 0x00100000, 0x00110000, 0x00120000,
    0x00130000, 0x00140000, 0x00150000, 0x00160000, 0x00170000, 0x00180000,
    0x00190000, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x001a0000, 0x001b0000, 0x001c0000, 0x001d0000, 0x001e0000,
    0x001f0000, 0x00200000, 0x00210000, 0x00220000, 0x00230000, 0x00240000,
    0x00250000, 0x00260000, 0x00270000, 0x00280000, 0x00290000, 0x002a0000,
    0x002b0000, 0x002c0000, 0x002d0000, 0x002e0000, 0x002f0000, 0x00300000,
    0x00310000, 0x00320000, 0x00330000, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff,
    0x01ffffff, 0x01ffffff, 0x01ffffff, 0x01ffffff};


inline uint32_t swap_bytes(const uint32_t word) {
  return ((word >> 24) & 0xff) |      // move byte 3 to byte 0
         ((word << 8) & 0xff0000) |   // move byte 1 to byte 2
         ((word >> 8) & 0xff00) |     // move byte 2 to byte 1
         ((word << 24) & 0xff000000); // byte 0 to byte 3
}


// Returns 1 upon success. -1 upon error The destination buffer must be large enough.
// This functions assumes that the padding (=) has been removed.
static int base64_tail_decode(EVP_ENCODE_CTX *ctx,char *dst, const char *src, int length) {
  // This looks like 5 branches, but we expect the compiler to resolve this to a single branch:
  const uint8_t *to_base64 = to_base64_value;
  const uint32_t *d0 = d0;
  const uint32_t *d1 = d1;
  const uint32_t *d2 = d2;
  const uint32_t *d3 = d3;

  const char *srcend = src + length;
  const char *srcinit = src;
  const char *dstinit = dst;

  uint32_t x;
  size_t idx;
  uint8_t buffer[4];
  while (1) {
    while (src + 4 <= srcend &&
           (x = d0[(uint8_t)(src[0])] | d1[(uint8_t)(src[1])] |
                d2[(uint8_t)(src[2])] | d3[(uint8_t)(src[3])]) < 0x01FFFFFF) {   

    // There is no mention of endianness in the immediate source code, I assume it is dealt with somewhere else
      // if(match_system(endianness::BIG)) {
      //   x = scalar::utf32::swap_bytes(x);
      // }
      memcpy(dst, &x, 3); // optimization opportunity: copy 4 bytes
      dst += 3;
      src += 4;
    }
    idx = 0;
    // we need at least four characters.
    while (idx < 4 && src < srcend) {
      char c = *src;
      uint8_t code = to_base64[(uint8_t)(c)];
      buffer[idx] = (uint8_t)(code);
      if (code <= 63) {
        idx++;
      } else if (code > 64) {
        return -1;
      } else {
        // We have a space or a newline. We ignore it.
      }
      src++;
    }
    if (idx != 4) {
      if (idx == 2) {
        uint32_t triple =
            ((uint32_t)(buffer[0]) << 3 * 6) + ((uint32_t)(buffer[1]) << 2 * 6);        // if(match_system(endianness::BIG)) {
          triple <<= 8;
          memcpy(dst, &triple, 1);
        //  } //else {
        //   triple = scalar::utf32::swap_bytes(triple);
        //   triple >>= 8;
        //   std::memcpy(dst, &triple, 1);
        // }
        dst += 1;

      } else if (idx == 3) {
        uint32_t triple = ((uint32_t)(buffer[0]) << 3 * 6) +
                          ((uint32_t)(buffer[1]) << 2 * 6) +
                          ((uint32_t)(buffer[2]) << 1 * 6);
        // if(match_system(endianness::BIG)) {
          triple <<= 8;
          memcpy(dst, &triple, 2);
        // } else {
          // triple = scalar::utf32::swap_bytes(triple);
          // triple >>= 8;
          // std::memcpy(dst, &triple, 2);
        }
        dst += 2;
      } else if (idx == 1) {
        // return {BASE64_INPUT_REMAINDER, size_t(dst - dstinit)};
        return -1;
      }
    //   return {SUCCESS, size_t(dst - dstinit)};
          return (size_t)(dst - dstinit);
    }

    uint32_t triple =
        ((uint32_t)((buffer)[0]) << 3 * 6) + ((uint32_t)((buffer)[1]) << 2 * 6) +
        ((uint32_t)((buffer)[2]) << 1 * 6) + ((uint32_t)((buffer)[3]) << 0 * 6); 
    // if(match_system(endianness::BIG)) {
    //   triple <<= 8;
    //   std::memcpy(dst, &triple, 3);
    // } else {
      triple = swap_bytes(triple);
      triple >>= 8;
      memcpy(dst, &triple, 3);
    // }
    dst += 3;
  }

static int evp_decodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int n)
{
    int i, ret = 0, a, b, c, d;
    unsigned long l;
    const unsigned char *table;

    if (ctx != NULL && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
        table = srpdata_ascii2bin;
    else
        table = data_ascii2bin;

    /* trim whitespace from the start of the line. */
    while ((n > 0) && (conv_ascii2bin(*f, table) == B64_WS)) {
        f++;
        n--;
    }

    /*
     * strip off stuff at the end of the line ascii2bin values B64_WS,
     * B64_EOLN, B64_EOLN and B64_EOF
     */
    while ((n > 3) && (B64_NOT_BASE64(conv_ascii2bin(f[n - 1], table))))
        n--;

    if (n % 4 != 0)
        return -1;

    for (i = 0; i < n; i += 4) {
        a = conv_ascii2bin(*(f++), table);
        b = conv_ascii2bin(*(f++), table);
        c = conv_ascii2bin(*(f++), table);
        d = conv_ascii2bin(*(f++), table);
        if ((a | b | c | d) & 0x80)
            return -1;
        l = ((((unsigned long)a) << 18L) |
             (((unsigned long)b) << 12L) |
             (((unsigned long)c) << 6L) | (((unsigned long)d)));
        *(t++) = (unsigned char)(l >> 16L) & 0xff;
        *(t++) = (unsigned char)(l >> 8L) & 0xff;
        *(t++) = (unsigned char)(l) & 0xff;
        ret += 3;
    }
    return ret;
}

int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n)
{
    return evp_decodeblock_int(NULL, t, f, n);
}

int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    int j;

    *outl = 0;
    if (ctx->num != 0) {
        // i = evp_decodeblock_int(ctx, out, ctx->enc_data, ctx->num);
        i = base64_tail_decode(ctx, out, ctx->enc_data, ctx->num);
        if (i < 0)
            return -1;
        ctx->num = 0;
        *outl = i;
        return 1;
    } else
        return 1;
}
