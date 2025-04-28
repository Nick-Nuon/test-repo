/*
 * Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"
#include "evp_local.h"
#include "internal/cryptlib.h"
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>

static unsigned char conv_ascii2bin(unsigned char a,
                                    const unsigned char *table);
static int evp_encodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int dlen);
static int evp_decodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int n);

full_result base64_tail_decode_trim_end(EVP_ENCODE_CTX *ctx, char *output, int *outl,
char *input, size_t length);


#define DEBUG 1 // Set to 1 to enable debug prints, 0 to disable
#define RED_TEXT(str) "\033[31m" str "\033[0m"
#define GREEN_TEXT(str) "\033[32m" str "\033[0m"

// Standard Colors
#define BLACK_TEXT(str) "\033[30m" str "\033[0m"
#define WHITE_TEXT(str) "\033[37m" str "\033[0m"

// Bright Colors
#define BRIGHT_RED_TEXT(str) "\033[91m" str "\033[0m"
#define BRIGHT_GREEN_TEXT(str) "\033[92m" str "\033[0m"
#define BRIGHT_YELLOW_TEXT(str) "\033[93m" str "\033[0m"
#define BRIGHT_BLUE_TEXT(str) "\033[94m" str "\033[0m"
#define BRIGHT_MAGENTA_TEXT(str) "\033[95m" str "\033[0m"
#define BRIGHT_CYAN_TEXT(str) "\033[96m" str "\033[0m"
#define BRIGHT_WHITE_TEXT(str) "\033[97m" str "\033[0m"

// Background Colors (Bright)
#define BRIGHT_BLACK_BG(str) "\033[100m" str "\033[0m"
#define BRIGHT_RED_BG(str) "\033[101m" str "\033[0m"
#define BRIGHT_GREEN_BG(str) "\033[102m" str "\033[0m"
#define BRIGHT_YELLOW_BG(str) "\033[103m" str "\033[0m"
#define BRIGHT_BLUE_BG(str) "\033[104m" str "\033[0m"
#define BRIGHT_MAGENTA_BG(str) "\033[105m" str "\033[0m"
#define BRIGHT_CYAN_BG(str) "\033[106m" str "\033[0m"
#define BRIGHT_WHITE_BG(str) "\033[107m" str "\033[0m"

#define BOLD_TEXT(str) "\033[1m" str "\033[0m"
#define UNDERLINE_TEXT(str) "\033[4m" str "\033[0m"
#define BLINK_TEXT(str) "\033[5m" str "\033[0m" // May not work on all terminals

#define DEBUG_CHECK_NULL(ptr)                                         \
    do {                                                              \
        if (!(ptr)) {                                                 \
            fprintf(stderr,                                           \
                    "DEBUG: Pointer '%s' is NULL at %s:%d in %s()\n",  \
                    #ptr, __FILE__, __LINE__, __func__);              \
        }                                                             \
    } while (0)



#if DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        do { \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
            fflush(stderr); \
        } while (0)
#else
    #define DEBUG_PRINT(fmt, ...)
#endif


#ifndef CHARSET_EBCDIC
#define conv_bin2ascii(a, table) ((table)[(a) & 0x3f])
#else
/*
 * We assume that PEM encoded files are EBCDIC files (i.e., printable text
 * files). Convert them here while decoding. When encoding, output is EBCDIC
 * (text) format again. (No need for conversion in the conv_bin2ascii macro,
 * as the underlying textstring data_bin2ascii[] is already EBCDIC)
 */
#define conv_bin2ascii(a, table) ((table)[(a) & 0x3f])
#endif

/*-
 * 64 char lines
 * pad input with 0
 * left over chars are set to =
 * 1 byte  => xx==
 * 2 bytes => xxx=
 * 3 bytes => xxxx
 */
#define BIN_PER_LINE (64 / 4 * 3)
#define CHUNKS_PER_LINE (64 / 4)
#define CHAR_PER_LINE (64 + 1)

// Normal Base64 alphabet
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

#define B64_EOLN 0xF0 // 1111 0000 outside the range of valid base64 characters
#define B64_CR 0xF1 // 1111 0001 outside the range of valid base64 characters, but ASCII CR is 0x0D....
#define B64_EOF 0xF2 // 1111 0002 outside the range of valid base64 characters
#define B64_WS 0xE0 // 1110 0000 outside the range of valid base64 characters
#define B64_ERROR 0xFF
#define B64_NOT_BASE64(a) (((a) | 0x13) == 0xF3)
#define B64_BASE64(a) (!B64_NOT_BASE64(a))

static const unsigned char data_ascii2bin[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0xF0, 0xFF,
    0xFF, 0xF1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF,
    0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const unsigned char srpdata_ascii2bin[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0xF0, 0xFF,
    0xFF, 0xF1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2, 0x3E, 0x3F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
    0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
    0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
    0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

#ifndef CHARSET_EBCDIC
static unsigned char conv_ascii2bin(unsigned char a,
                                    const unsigned char *table) {
  if (a & 0x80)
    return B64_ERROR;
  return table[a];
}
#else
static unsigned char conv_ascii2bin(unsigned char a,
                                    const unsigned char *table) {
  a = os_toascii[a];
  if (a & 0x80)
    return B64_ERROR;
  return table[a];
}
#endif

EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void) {
  return OPENSSL_zalloc(sizeof(EVP_ENCODE_CTX));
}

void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx) { OPENSSL_free(ctx); }

int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX *dctx, const EVP_ENCODE_CTX *sctx) {
  memcpy(dctx, sctx, sizeof(EVP_ENCODE_CTX));

  return 1;
}

int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX *ctx) { return ctx->num; }

void evp_encode_ctx_set_flags(EVP_ENCODE_CTX *ctx, unsigned int flags) {
  ctx->flags = flags;
}

void EVP_EncodeInit(EVP_ENCODE_CTX *ctx) {
  ctx->length = 48;
  ctx->num = 0;
  ctx->line_num = 0;
  ctx->flags = 0;
}

int EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl) {
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

void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl) {
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
                               const unsigned char *f, int dlen) {
  int i, ret = 0;
  unsigned long l;
  const unsigned char *table;

  if (ctx != NULL && (ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
    table = srpdata_bin2ascii;
  else
    table = data_bin2ascii;

  for (i = dlen; i > 0; i -= 3) {
    if (i >= 3) {
      l = (((unsigned long)f[0]) << 16L) | (((unsigned long)f[1]) << 8L) | f[2];
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

int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen) {
  return evp_encodeblock_int(NULL, t, f, dlen);
}

void EVP_DecodeInit(EVP_ENCODE_CTX *ctx) {
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
                     const unsigned char *in, int inl) {
  DEBUG_PRINT(GREEN_TEXT("********************* DEBUG: Entered EVP_DecodeUpdate\n"));
  int seof = 0, eof = 0, rv = -1, ret = 0, i, v, tmp, n, decoded_len;
  unsigned char *d;
  const unsigned char *table;
  int temp_total  = 0; // for debugging purposes

  n = ctx->num;  // for partial decode/encode. As I understand it, 
  // it starts high and diminishes as the buffer gets processed
  d = ctx->enc_data;

  // detects padding inside the ctx's buffer
  if (n > 0 && d[n - 1] == '=') {
    eof++;
    if (n > 1 && d[n - 2] == '=')
      eof++;
  }

  /* Legacy behaviour: an empty input chunk signals end of input. */
  if (inl == 0) { // fastpast if len == 0
    rv = 0;
    goto end;
  }

  if ((ctx->flags & EVP_ENCODE_CTX_USE_SRP_ALPHABET) != 0)
    table = srpdata_ascii2bin;
  else
    table = data_ascii2bin;

  // check for errors first, we can axe that 
  for (i = 0; i < inl; i++) {
    // DEBUG_PRINT(GREEN_TEXT("DEBUG: EVP_DecodeUpdate: inl: %d, i: %d, tmp: %02x\n"), inl, i, *(in + i));
    tmp = *(in++);
    v = conv_ascii2bin(tmp, table); // this is a straight conversion without surprises, it fails 
    // if the leading bit is set eg it does char c & 0x80  
    if (v == B64_ERROR) { // does some more error handling here, leaves WS/equals/EOF alone.
      DEBUG_PRINT(RED_TEXT("DEBUG: Error in EVP_DecodeUpdate: invalid character early on: %02x, position: %d, input length: %d \n"), tmp,i,inl);
      rv = -1;
      goto end;
    }

    // // check padding related errors , we can axe that
    if (tmp == '=') {
      DEBUG_PRINT(RED_TEXT("DEBUG: Found EOF at position %d, tmp: %02x\n"), i, tmp);
      eof++;
    } else if (eof > 0 && B64_BASE64(v)) {
      /* More data after padding. */
      DEBUG_PRINT(RED_TEXT("DEBUG: Error in EVP_DecodeUpdate: more data after padding %02x\n"), tmp);
      rv = -1;
      goto end;
    }

    if (eof > 2) {  // if there are more than two padding characters, fails
      DEBUG_PRINT(RED_TEXT("DEBUG: Error in EVP_DecodeUpdate: too many padding characters %02x\n"), tmp);
      rv = -1;
      goto end;
    }

    if (v == B64_EOF) {
      DEBUG_PRINT(RED_TEXT("DEBUG: EVP_DecodeUpdate: SEOF character %02x\n"), tmp);
      seof = 1;
      goto tail;
    }

    /* Only save valid base64 characters. */ // to the ctx buffer that is, forgo WS/EOF/etc
    if (B64_BASE64(v)) {
      if (n >= 64) {
        /*
         * We increment n once per loop, and empty the buffer as soon as
         * we reach 64 characters, so this can only happen if someone's
         * manually messed with the ctx. Refuse to write any more data.
         */
        DEBUG_PRINT(RED_TEXT("DEBUG: Error in EVP_DecodeUpdate: buffer overflow/someone is tampering %02x\n"), tmp);
        rv = -1; //recall this is used for encoding . 80 bytes is probably for historical reasons
        goto end;
      }
      OPENSSL_assert(n < (int)sizeof(ctx->enc_data)); // can only get 80 bytes at a time , hardcoded
      d[n++] = tmp; // write to the ctx. 
    }

    if (n == 64) {
      temp_total += 64; // for debugging purposes
      decoded_len = evp_decodeblock_int(ctx, out, d, n); // this only takes care of the conversion
      n = 0; // we process 64 bytes at a time
      if (decoded_len < 0 || eof > decoded_len) { //if there is an error or basic check to see  
        // if the padding is correcteg there will never decode only 1 or two bytes
        DEBUG_PRINT(RED_TEXT("DEBUG: Error in EVP_DecodeUpdate: decodeblock error %02x\n"), tmp);
        rv = -1;
        goto end;
      }
      // This is the number of bytes we have written to the output buffer up to an error
      // e.g. if the 64 bit block fails, then the pointers ret and out aren't incremented 
      ret += decoded_len - eof; // advance the "partial error" pointer
      out += decoded_len - eof; //advance the write pointer, for internal use
      DEBUG_PRINT("DEBUG: eof: %d, \n", eof);
    }
  }

  /*
   * Legacy behaviour: if the current line is a full base64-block (i.e., has
   * 0 mod 4 base64 characters), it is processed immediately. We keep this
   * behaviour as applications may not be calling EVP_DecodeFinal properly.
   */
tail:
  if (n > 0) {
    temp_total += n; // for debugging purposes
    if ((n & 3) == 0) { // is it a multiple of 4?
      DEBUG_PRINT(GREEN_TEXT("DEBUG: EVP_DecodeUpdate: n is a multiple of 4, n: %d\n"), n);
      decoded_len = evp_decodeblock_int(ctx, out, d, n);
      n = 0;
      if (decoded_len < 0 || eof > decoded_len) {
        rv = -1;
        goto end;
      }
      ret += (decoded_len - eof); // same story as above. 
      // e.g. if the decode fx fails on the remaining tail,
      //  then the pointer  ret and out aren't incremented
    } else if (seof) {
      /* EOF in the middle of a base64 block. */
      rv = -1;
      goto end;
    }
  }

  rv = seof || (n == 0 && eof) ? 0 : 1;
end:
  /* Legacy behaviour. This should probably rather be zeroed on error. */
  // DEBUG_PRINT(GREEN_TEXT("DEBUG: EVP_DecodeUpdate: outl: %d, ret: %d, n: %d, eof: %d, rv: %d\n", temp_total: %d\n"), *outl, ret, n, eof, rv, temp_total);
  *outl = ret; 
  ctx->num = n;
  return rv;
}

const uint8_t to_base64_value[] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 64,  64,  255, 64,  64,  255,
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

const char base64_e0[256] = {
    'A', 'A', 'A', 'A', 'B', 'B', 'B', 'B', 'C', 'C', 'C', 'C', 'D', 'D', 'D',
    'D', 'E', 'E', 'E', 'E', 'F', 'F', 'F', 'F', 'G', 'G', 'G', 'G', 'H', 'H',
    'H', 'H', 'I', 'I', 'I', 'I', 'J', 'J', 'J', 'J', 'K', 'K', 'K', 'K', 'L',
    'L', 'L', 'L', 'M', 'M', 'M', 'M', 'N', 'N', 'N', 'N', 'O', 'O', 'O', 'O',
    'P', 'P', 'P', 'P', 'Q', 'Q', 'Q', 'Q', 'R', 'R', 'R', 'R', 'S', 'S', 'S',
    'S', 'T', 'T', 'T', 'T', 'U', 'U', 'U', 'U', 'V', 'V', 'V', 'V', 'W', 'W',
    'W', 'W', 'X', 'X', 'X', 'X', 'Y', 'Y', 'Y', 'Y', 'Z', 'Z', 'Z', 'Z', 'a',
    'a', 'a', 'a', 'b', 'b', 'b', 'b', 'c', 'c', 'c', 'c', 'd', 'd', 'd', 'd',
    'e', 'e', 'e', 'e', 'f', 'f', 'f', 'f', 'g', 'g', 'g', 'g', 'h', 'h', 'h',
    'h', 'i', 'i', 'i', 'i', 'j', 'j', 'j', 'j', 'k', 'k', 'k', 'k', 'l', 'l',
    'l', 'l', 'm', 'm', 'm', 'm', 'n', 'n', 'n', 'n', 'o', 'o', 'o', 'o', 'p',
    'p', 'p', 'p', 'q', 'q', 'q', 'q', 'r', 'r', 'r', 'r', 's', 's', 's', 's',
    't', 't', 't', 't', 'u', 'u', 'u', 'u', 'v', 'v', 'v', 'v', 'w', 'w', 'w',
    'w', 'x', 'x', 'x', 'x', 'y', 'y', 'y', 'y', 'z', 'z', 'z', 'z', '0', '0',
    '0', '0', '1', '1', '1', '1', '2', '2', '2', '2', '3', '3', '3', '3', '4',
    '4', '4', '4', '5', '5', '5', '5', '6', '6', '6', '6', '7', '7', '7', '7',
    '8', '8', '8', '8', '9', '9', '9', '9', '+', '+', '+', '+', '/', '/', '/',
    '/'};

const char base64_e1[256] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C',
    'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+',
    '/'};

const char base64_e2[256] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', 'A', 'B', 'C',
    'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+',
    '/'};

static inline uint32_t swap_bytes(const uint32_t word) {
  return ((word >> 24) & 0xff) |      // move byte 3 to byte 0
         ((word << 8) & 0xff0000) |   // move byte 1 to byte 2
         ((word >> 8) & 0xff00) |     // move byte 2 to byte 1
         ((word << 24) & 0xff000000); // byte 0 to byte 3
}

// int max(int a, int b) {
//   return (a > b) ? a : b;
// }

// // Returns the number of bytes written. The destination buffer must be large
// // enough. It will add padding (=) if needed.
//
int tail_encode_base64(EVP_ENCODE_CTX *ctx, char *dst, const char *src,
                       size_t srclen) {
  // This looks like 3 branches, but we expect the compiler to resolve this to a
  // single branch:
  DEBUG_PRINT(RED_TEXT("DEBUG: Entering tail_encode_base64\n"));
  // DEBUG_PRINT(GREEN_TEXT("DEBUG: Source string: \"%s\"\n"), src);
  
  const char *e0 = base64_e0;
  const char *e1 = base64_e1;
  const char *e2 = base64_e2;
  char *out = dst;
  size_t i = 0;
  uint8_t t1, t2, t3;

  DEBUG_PRINT(RED_TEXT("DEBUG: Source length = %zu\n"), srclen);
  for (; i + 2 < srclen; i += 3) {
    t1 = (uint8_t)src[i];
    t2 = (uint8_t)src[i + 1];
    t3 = (uint8_t)src[i + 2];
    DEBUG_PRINT(
        RED_TEXT("DEBUG: Processing bytes at index %zu: %02x %02x %02x\n"), i,
        t1, t2, t3);

    *out++ = e0[t1];
    *out++ = e1[((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F)];
    *out++ = e1[((t2 & 0x0F) << 2) | ((t3 >> 6) & 0x03)];
    *out++ = e2[t3];

    DEBUG_PRINT(RED_TEXT("DEBUG: Output so far: %.*s\n"), (int)(out - dst),
                dst);
  }
  size_t remaining = srclen - i;
  DEBUG_PRINT(RED_TEXT("DEBUG: Remaining bytes = %zu\n"), remaining);
  switch (remaining) {
  case 0:
    break;
  case 1:
    t1 = (uint8_t)src[i];
    DEBUG_PRINT(RED_TEXT("DEBUG: Processing last byte at index %zu: %02x\n"), i,
                t1);
    *out++ = e0[t1];
    *out++ = e1[(t1 & 0x03) << 4];
    *out++ = '=';
    *out++ = '=';
    DEBUG_PRINT(RED_TEXT("DEBUG: Output so far: %.*s\n"), (int)(out - dst),
                dst);
    break;
  case 2:
    t1 = (uint8_t)src[i];
    t2 = (uint8_t)src[i + 1];
    DEBUG_PRINT(
        RED_TEXT("DEBUG: Processing last 2 bytes at index %zu: %02x %02x\n"), i,
        t1, t2);
    *out++ = e0[t1];
    *out++ = e1[((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F)];
    *out++ = e2[(t2 & 0x0F) << 2];
    *out++ = '=';
    DEBUG_PRINT(RED_TEXT("DEBUG: Output so far: %.*s\n"), (int)(out - dst),
                dst);
    break;
  }
  int total = (int)(out - dst);
  DEBUG_PRINT(
      RED_TEXT("DEBUG: Exiting tail_encode_base64, total output bytes = %d\n"),
      total);
  return total;
}

// This function is not expected to be fast. Do not use in long loops.
static inline int is_ascii_white_space(char c) {
  // return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

int simdutf_decode(EVP_ENCODE_CTX *ctx, unsigned char *output, int *outl,
  const char *input, int length) {
    full_result r = base64_tail_decode_trim_end(ctx, output, outl, input, length);
    // int orginal_length = length;

    // DEBUG_PRINT(RED_TEXT("DEBUG: 
    
    DEBUG_PRINT(RED_TEXT("DEBUG: r.error Simdutf: %d\n"),
                r.error);

    DEBUG_PRINT(RED_TEXT("DEBUG: r.input_count Simdutf: %zu\n"),
                r.input_count);
    DEBUG_PRINT(RED_TEXT("DEBUG: r.output_count Simdutf: %zu\n"),
                r.output_count);
    DEBUG_PRINT(RED_TEXT("DEBUG: r.whitespaces Simdutf: %d\n"),
                r.whitespaces);
    DEBUG_PRINT(RED_TEXT("DEBUG: r.equalsigns Simdutf: %d\n"),
                r.padding);
    DEBUG_PRINT(RED_TEXT("DEBUG: r.internal_padding Simdutf: %zu\n"),
                r.internal_padding);


    DEBUG_PRINT(RED_TEXT("DEBUG: r.input_count - r.whitespaces + r.padding: %zu\n"),
                r.input_count - r.whitespaces + r.padding);


    //TODO: There is probably a way to Simplify/unify this!!!!

    // int len_no_pad_ws = r.input_count - r.whitespaces - surplus_paddings;
    int alt_adj_len = length - r.whitespaces - r.padding;
    // int alt_adj_len = length - r.whitespaces - surplus_paddings;
    int adj_len = r.input_count - r.whitespaces + r.padding;
    DEBUG_PRINT(RED_TEXT("DEBUG: length - length mod 64: %d\n"), length - length % 64);
    DEBUG_PRINT(RED_TEXT("DEBUG: alt_adj_len: %d\n"), alt_adj_len);
    DEBUG_PRINT(RED_TEXT("DEBUG: adj_len: %d\n"), adj_len);
    DEBUG_PRINT(RED_TEXT("DEBUG: adj_len mod 4: %d\n"), (adj_len) % 4);
    DEBUG_PRINT(RED_TEXT("DEBUG: adj_len mod 64: %d\n"), (adj_len) % 64);


  if (r.error == EXTRA_PADDING){
      DEBUG_PRINT(RED_TEXT("DEBUG: Simdutf Extra padding found in core kernel\n"));
      // Calculate the number of bytes that constitute the valid part.
     
      if (r.input_count > 64 && alt_adj_len % 64 == 0){
        int valid = alt_adj_len/4 *3 - r.internal_padding;
        valid = valid > 0 ? valid : 0;
  
        *outl = (int) valid;
        // Cleanse (erase) the remaining incomplete portion.
        // TODO: because OpenSSL does buffering, we need to cleanse what simdutf decoded but openssl didn't
        // size_t to_cleanse = r.output_count % 48;
        // OPENSSL_cleanse(output + valid, to_cleanse);
        return -1;
      }
      else if (adj_len % 64 == 0) {
        DEBUG_PRINT(RED_TEXT("DEBUG: Second option\n"));

        // we cap possible padding to 2 because OpenSSL only removes 2 padding from *outlen
        int surplus_paddings = r.padding + r.internal_padding > 2 ? 2 : r.padding + r.internal_padding;
        DEBUG_PRINT(RED_TEXT("DEBUG: surplus_paddings: %d\n"), surplus_paddings);  

        int valid = adj_len/4 *3 - surplus_paddings;
        valid = valid > 0 ? valid : 0;
  
        *outl = (int) valid;
        // Cleanse (erase) the remaining incomplete portion.
        // TODO: because OpenSSL does buffering, we need to cleanse what simdutf decoded but openssl didn't
        // size_t to_cleanse = r.output_count % 48;
        // OPENSSL_cleanse(output + valid, to_cleanse);
        return -1;
      }
      else if (adj_len % 64 == 63) {
        DEBUG_PRINT(RED_TEXT("DEBUG: Theird option\n"));

        // we cap possible padding to 2 because OpenSSL only removes 2 padding from *outlen
        int surplus_paddings = r.padding + r.internal_padding > 2 ? 2 : r.padding + r.internal_padding;
        DEBUG_PRINT(RED_TEXT("DEBUG: surplus_paddings: %d\n"), surplus_paddings);  

        int valid = (adj_len +1)/4 *3 - surplus_paddings;
        valid = valid > 0 ? valid : 0;
  
        *outl = (int) valid;
        // Cleanse (erase) the remaining incomplete portion.
        // TODO: because OpenSSL does buffering, we need to cleanse what simdutf decoded but openssl didn't
        // size_t to_cleanse = r.output_count % 48;
        // OPENSSL_cleanse(output + valid, to_cleanse);
        return -1;
      }
      DEBUG_PRINT(RED_TEXT("DEBUG: length: %d\n"), length);
      DEBUG_PRINT(RED_TEXT("DEBUG: length - length mod 64: %d\n"), length - length % 64);
      DEBUG_PRINT(RED_TEXT("DEBUG: Length - length mod 64 == 0: %d\n"), ((length - length % 64) % 64) == 0);
    }

  if (r.error == BASE64_SUCCESS) {
    // DEBUG_PRINT(RED_TEXT("DEBUG: Simdutf decode successful, output count: %d\n"),
    //             r.output_count);
    *outl = (int)r.output_count;
    return (int)r.output_count;
  } 
  // e.g.  last bytes were ended with XXX=|= where ‘X’ denotes a valid character, ‘=’ denotes padding and ‘|’ denotes the point where the 64 buffer ends
  // OpenSSL's outln will take up to '|' into account but no more 
  else if (r.error == NOT_MULTIPLE_OF_FOUR && r.padding == 2 && ((adj_len % 64) == 0 || (adj_len % 64) == 1) ) {
        DEBUG_PRINT(RED_TEXT("DEBUG: Simdutf decode failed, invalid base64 character with padding at seems\n"));
        // Calculate the number of bytes that constitute the valid part.
       
        // int valid = (adj_len)/4 * 3 - (((adj_len)/4 * 3) % 48) -1;
        int valid = r.output_count + r.padding;
        // int valid = r.output_count - (r.output_count % 48) -1;
        valid = valid > 0 ? valid : 0;
        *outl = (int) valid;
        // Cleanse (erase) the remaining incomplete portion.
        int to_cleanse = r.output_count % 48 -1;
        OPENSSL_cleanse(output + valid, to_cleanse);
        return -1;

  } else {
    // Calculate the number of bytes that constitute the valid part.
    DEBUG_PRINT(RED_TEXT("DEBUG: Simdutf decode failed, invalid base64 character\n"));
    // DEBUG_PRINT(RED_TEXT("DEBUG: THes should not be possible\n"));

    size_t valid = r.output_count - (r.output_count % 48);
    *outl = (int) valid;
    // Cleanse (erase) the remaining incomplete portion.
    size_t to_cleanse = r.output_count % 48;
    OPENSSL_cleanse(output + valid, to_cleanse);
    return -1;
}


}


// removes padding and white spaces at the end
full_result base64_tail_decode_trim_end(EVP_ENCODE_CTX *ctx, char *output, int *outl,
                                   char *input, size_t length) {
  DEBUG_PRINT(
      BRIGHT_YELLOW_TEXT("DEBUG: Entered base64_tail_decode_trim_end\n"));
      DEBUG_CHECK_NULL(output);


  DEBUG_PRINT(GREEN_TEXT("DEBUG: Input string (hex): "));
  for (size_t i = 0; i < (size_t)length; i++) {
    DEBUG_PRINT(GREEN_TEXT("%02x "), (unsigned char)input[i]);
  }
  DEBUG_PRINT("\n");

  DEBUG_PRINT(GREEN_TEXT("DEBUG: Input string (char): "));
  for (size_t i = 0; i < (size_t)length; i++) {
    DEBUG_PRINT(GREEN_TEXT("%c "), (unsigned char)input[i]);
  }
  DEBUG_PRINT("\n");
  DEBUG_PRINT(GREEN_TEXT("DEBUG: Length: %zu\n"), length);

  int easy_whitespaces = 0;
  for (size_t i = 0; i < length; i++) {
    if (is_ascii_white_space(input[i])) {
      easy_whitespaces++;
    }
  }

  // int trailing_ws_count = 0;
  while (length > 0 && is_ascii_white_space(input[length - 1])) {
    // trailing_ws_count++;
    length--;
  }
  
  size_t equallocation =
      length; // location of the first padding character if any

  auto equalsigns = 0;
  if (length > 0 && input[length - 1] == '=') {
    equallocation = length - 1;
    length -= 1;
    equalsigns++;
    // DEBUG_PRINT("Found = sign: %d", equalsigns);

    while (length > 0 && is_ascii_white_space(input[length - 1])) {
      length--;
      DEBUG_PRINT("Found trailing whitespace: %d", length);
    }
    if (length > 0 && input[length - 1] == '=') {
      equallocation = length - 1;
      equalsigns++;
      DEBUG_PRINT("Found = sign: %d", equalsigns);
      length -= 1;
    }
  }
  if (length == 0) {
    if (equalsigns > 0) {
      return (full_result){EXTRA_PADDING, equallocation, 0, easy_whitespaces, equalsigns};
    }
    return (full_result){BASE64_SUCCESS, 0,0, easy_whitespaces, equalsigns};
  }
  full_result r = base64_tail_decode(ctx, output, input, length, equalsigns);
  
  DEBUG_PRINT(" Base64_tail Input count after removing padding and white spaces: %d, Output count: %d,  \n",
              r.input_count, r.output_count);

  // DEBUG_PRINT(GREEN_TEXT("DEBUG: r.whitespaces: %d\n"), r.whitespaces);
            
  if (r.error == BASE64_SUCCESS && equalsigns > 0) {
    // additional checks
    DEBUG_PRINT(
        GREEN_TEXT("DEBUG: Additional checks: equalsigns: %d, r.output_count: %zu\n"), equalsigns,
        r.output_count);

    if ((r.output_count % 3 == 0) ||
        ((r.output_count % 3) + 1 + equalsigns != 4)) {
      return (full_result){INVALID_BASE64_CHARACTER, equallocation, (size_t)r.output_count, easy_whitespaces, equalsigns};
    }
  }
  // DEBUG_PRINT(GREEN_TEXT("DEBUG: Final r.count:%d\n"), r.input_count);
  if (r.error == BASE64_SUCCESS | r.error == BASE64_INPUT_REMAINDER) {
    return (full_result){r.error, r.input_count, (size_t)r.output_count, easy_whitespaces, equalsigns};
  } else {
    return (full_result){r.error, r.input_count,(size_t)r.output_count, easy_whitespaces, equalsigns, r.internal_padding};
  }
}

// Returns 1 upon BASE64_SUCCESS. -1 upon error. The destination buffer must be
// large enough. This function assumes that the padding (=) has been removed.
full_result base64_tail_decode(EVP_ENCODE_CTX *ctx, char *dst, const char *src,
                               int length,int equalsigns) {
  DEBUG_PRINT("\n");
  DEBUG_PRINT(RED_TEXT("DEBUG: Starting base64_tail_decode\n"));
                              
  DEBUG_PRINT(
      BRIGHT_YELLOW_TEXT("DEBUG: length = %d, equalsigns = %d\n"), length, equalsigns);

  if (length == 0) {
    return (full_result){BASE64_SUCCESS, 0, 0,0};
  }
  int whitespaces = 0;
  // Use local aliases for the global lookup tables.
  const uint8_t *to_base64 = to_base64_value;
  const uint32_t *p0 = d0;
  const uint32_t *p1 = d1;
  const uint32_t *p2 = d2;
  const uint32_t *p3 = d3;

  const char *srcend = src + length;
  const char *srcinit = src;
  const char *dstinit = dst;

  uint32_t x;
  size_t idx;
  uint8_t buffer[4];

#if DEBUG
  DEBUG_PRINT("DEBUG: Input (hex): ");
  for (int i = 0; i < length; i++) {
    DEBUG_PRINT(GREEN_TEXT("%02x "), (unsigned char)src[i]);
  }
  DEBUG_PRINT("\n\n");
#endif

  while (1) {
    // DEBUG_PRINT("Entering While(1) loop\n:");
    // while (src + 4 <= srcend &&
    //        (x = p0[(uint8_t)(src[0])] | p1[(uint8_t)(src[1])] |
    //             p2[(uint8_t)(src[2])] | p3[(uint8_t)(src[3])]) < 0x01FFFFFF) {
    //   DEBUG_PRINT("fast track loop!!!\n");
    //   memcpy(dst, &x, 3); // Copy 3 bytes from the computed value.
    //   dst += 3;
    //   src += 4;
    // }
    idx = 0;
    // Gather up to four valid characters.
    while (idx < 4 && src < srcend) {
      // DEBUG_PRINT("Main 4 char loop\n");
      char c = *src;
      uint8_t code = to_base64[(uint8_t)(c)];
      buffer[idx] = code;
      if (code <= 63) {
        // DEBUG_PRINT("Valid base64 character\n");
        idx++;
      } else if (code > 64) {
        DEBUG_PRINT("INVALID_BASE64_CHARACTER: code > 64 \n");
        // INVALID_BASE64_CHARACTER
        if (c == 0x2D & (idx % 4) == 0 ) { // '-' sign/ SEOF. TODO: change the tables
          DEBUG_PRINT("SEOF detected\n");
          printf("SEOF detected\n");
          // idx++;
          break;
        }
        if (c == 0x3D) {
          // all padding have already been removed by the caller
          DEBUG_PRINT("Extraneous Padding detected inside core kernel\n");
          int internal_padding = 0;
          int internal_whitespaces = 0;
          DEBUG_PRINT("equalsigns: %d\n", equalsigns);
          const char* temp_src = srcend ;  // Start from the end
          
            // while (temp_src > src && (*temp_src == '='|| is_ascii_white_space(*temp_src))) {
              while (temp_src > src && (*temp_src == '=')) {
            DEBUG_PRINT("Found padding character: %c\n", *temp_src);
            internal_padding++;
            temp_src--;
            }
          DEBUG_PRINT("Internal padding count inside core: %d\n", internal_padding);
          DEBUG_PRINT("src - srcinit: %zu\n", (size_t)(src - srcinit));
          
          // // Add this where you want to see the consumed input
          // int consumed_length = src - srcinit;
          // DEBUG_PRINT("DEBUG: Consumed input (length %d): ", consumed_length);
          // for (int i = 0; i < consumed_length; i++) {
          //     DEBUG_PRINT("%c", srcinit[i]);
          // }
          // // DEBUG_PRINT("\nConsumed input (hex): ");
          // // for (int i = 0; i < consumed_length; i++) {
          // //     DEBUG_PRINT("%02x ", (unsigned char)srcinit[i]);
          // // }
          // DEBUG_PRINT("\n");

          return (full_result){EXTRA_PADDING, (size_t)(src - srcinit),
            (size_t)((dst - dstinit)),  whitespaces, equalsigns, internal_padding};
        }
        else {
            return (full_result){INVALID_BASE64_CHARACTER, (size_t)(src - srcinit),
                             (size_t)((dst - dstinit)),  whitespaces};
        }
      } else {
        if (c == '\f') {
          DEBUG_PRINT("Simdutf:Form feed detected!!!!Not a valid b64 char by OpenSSL standards!\n");
          return (full_result){INVALID_BASE64_CHARACTER, (size_t)(src - srcinit),
            (size_t)(dst - dstinit), whitespaces};
        }
        // DEBUG_PRINT("WS detected!!!!\n");
        whitespaces++;
        // A whitespace or newline; ignore it.
      }
      src++;
      // DEBUG_PRINT("idx = %d\n", idx);
    }
    if (idx != 4) {
      DEBUG_PRINT("idx != 4\n");


      if (idx == 2) {
        DEBUG_PRINT("idx == 2\n");
        if (equalsigns != 2){
          DEBUG_PRINT("equalsigns != 2\n");
          DEBUG_PRINT("dst - dstinit: %zu\n", (size_t)(dst - dstinit));
          return (full_result){NOT_MULTIPLE_OF_FOUR, (size_t)(src - srcinit),(size_t)(dst - dstinit), whitespaces};
        }

        uint32_t triple = ((uint32_t)(buffer[0]) << (3 * 6)) +
                          ((uint32_t)(buffer[1]) << (2 * 6));
        // For little-endian system: swap and shift.
        triple = swap_bytes(triple);
        triple >>= 8;
        memcpy(dst, &triple, 1);
        dst += 1;
      } else if (idx == 3) {
        DEBUG_PRINT("idx == 3\n");
        if (equalsigns != 1){
              DEBUG_PRINT("equalsigns != 1\n");
              return (full_result){NOT_MULTIPLE_OF_FOUR, (size_t)(src - srcinit),(size_t)(dst - dstinit), whitespaces};
        }
        uint32_t triple = ((uint32_t)(buffer[0]) << (3 * 6)) +
                          ((uint32_t)(buffer[1]) << (2 * 6)) +
                          ((uint32_t)(buffer[2]) << (1 * 6));
        triple = swap_bytes(triple);
        triple >>= 8;
        memcpy(dst, &triple, 2);
        dst += 2;
      } else if (idx == 1) {
        DEBUG_PRINT("idx == 1\n");

        return (full_result){NOT_MULTIPLE_OF_FOUR, (size_t)(src - srcinit),(size_t)(dst - dstinit), whitespaces};
      }
#if DEBUG
      {
        int final_bytes = (int)(dst - dstinit);
        DEBUG_PRINT("DEBUG: Final output (hex): ");
        for (int j = 0; j < final_bytes; j++) {
          DEBUG_PRINT(GREEN_TEXT("%02x "), (unsigned char)dstinit[j]);
        }
        DEBUG_PRINT("\n\n");
      }
#endif
      return (full_result){BASE64_SUCCESS, (size_t)(src - srcinit),
                           (size_t)(dst - dstinit),whitespaces};

    }
    // DEBUG_PRINT("idx == 4 remaining\n");
    // DEBUG_PRINT("Buffer: %02x %02x %02x %02x\n", buffer[0], buffer[1],buffer[2], buffer[3]);

        /* Count whitespace characters in the buffer */
    int ws_count = 0;
    for (int i = 0; i < 4; i++) {
        if (is_ascii_white_space(buffer[i])) {
            ws_count++;
        }
    }
    // DEBUG_PRINT("DEBUG: Found %d whitespace characters in the final block\n", ws_count);
    whitespaces += ws_count;

    uint32_t triple = ((uint32_t)(buffer[0]) << (3 * 6)) +
                      ((uint32_t)(buffer[1]) << (2 * 6)) +
                      ((uint32_t)(buffer[2]) << (1 * 6)) +
                      ((uint32_t)(buffer[3]) << (0 * 6));
    // DEBUG_PRINT("Read past buffer Triple: %08x\n", triple);
    triple = swap_bytes(triple);
    triple >>= 8;
    memcpy(dst, &triple, 3);
    // DEBUG_PRINT("Read past dst copy");
    dst += 3;
  }
}

// returns the number of bytes written
// returns -1 on error
static int evp_decodeblock_int(EVP_ENCODE_CTX *ctx, unsigned char *t,
                               const unsigned char *f, int n) {
  DEBUG_PRINT(
      RED_TEXT("DEBUG OpenSSL: Entering evp_decodeblock_int\n")); 
      DEBUG_PRINT(      RED_TEXT("DEBUG OpenSSL: n = %d\n"), n);

  int i, ret = 0, a, b, c, d;
  unsigned long l;
  const unsigned char *table;

  // DEBUG_PRINT(      RED_TEXT("DEBUG OpenSSL: n = %d, f = %s, t = %s\n"), n, f, t);


  // DEBUG_CHECK_NULL(t);

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


  if (n % 4 != 0){
    DEBUG_PRINT(RED_TEXT("DEBUG OpenSSL: n %% 4 != 0\n"));
    return -1;
  }

  for (i = 0; i < n; i += 4) {
    a = conv_ascii2bin(*(f++), table);
    b = conv_ascii2bin(*(f++), table);
    c = conv_ascii2bin(*(f++), table);
    d = conv_ascii2bin(*(f++), table);
    if ((a | b | c | d) & 0x80) // does any of them return B64_Error or (additional checks) non-base 64 chars(eg WS)?
      return -1;
    l = ((((unsigned long)a) << 18L) | (((unsigned long)b) << 12L) |
         (((unsigned long)c) << 6L) | (((unsigned long)d)));
    *(t++) = (unsigned char)(l >> 16L) & 0xff;
    *(t++) = (unsigned char)(l >> 8L) & 0xff;
    *(t++) = (unsigned char)(l) & 0xff;
    ret += 3;
  }
  DEBUG_PRINT(RED_TEXT("DEBUG OpenSSL: ret = %d\n"), ret);
  return ret;
}

int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n) {
  return evp_decodeblock_int(NULL, t, f, n);
}

int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    int j;

    DEBUG_CHECK_NULL(out);

    *outl = 0;
    if (ctx->num != 0) {
        i = evp_decodeblock_int(ctx, out, ctx->enc_data, ctx->num);
        if (i < 0)
            return -1;
        ctx->num = 0;
        *outl = i;
        return 1;
    } else
        return 1;
}