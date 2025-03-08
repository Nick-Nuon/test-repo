/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// Include the test framework header
#include "testutil.h"
#include <openssl/evp.h>

#define BUFMAX 0xa0000          /* Encode at most 640kB. */
#define RED_TEXT(str) "\033[31m" str "\033[0m"
#define GREEN_TEXT(str) "\033[32m" str "\033[0m"


/* Prototypes for encoding helper functions */
static int memout(BIO *mem, char c, int llen, int *pos);
static int memoutws(BIO *mem, char c, unsigned wscnt, unsigned llen, int *pos);
int base64_tail_decode(EVP_ENCODE_CTX *ctx, char *dst, const char *src, int length);

size_t maximal_binary_length_from_base64(const char *input, size_t length) {
  size_t padding = 0;
  if(length > 0) {
    if(input[length - 1] == '=') {
      padding++;
      if(length > 1 && input[length - 2] == '=') {
        padding++;
      }
    }
  }
  size_t actual_length = length - padding;
  if(actual_length % 4 <= 1) {
    return (actual_length / 4) * 3;
  }
  // When valid, remainder is 2 or 3, so subtract 1.
  return (actual_length / 4) * 3 + (actual_length % 4) - 1;
}

/* Generate `len` random octets */
static unsigned char *genbytes(unsigned len)
{
    unsigned char *buf = NULL;

    if (len > 0 && len <= BUFMAX && (buf = OPENSSL_malloc(len)) != NULL)
        RAND_bytes(buf, len);

    return buf;
}


/* Encode and append one 6-bit(2^6 = 64) slice, randomly prepending some whitespace */
static int memoutws(BIO *mem, char c, unsigned wscnt, unsigned llen, int *pos)
{
    if (wscnt > 0
        && (test_random() % llen) < wscnt
        && memout(mem, ' ', llen, pos) == 0)
        return 0;
    return memout(mem, c, llen, pos);
}

/*
 * Encode an octet string in base64, approximately `llen` bytes per line,
 * with up to roughly `wscnt` additional space characters inserted at random
 * before some of the base64 code points.
 */
static int encode(unsigned const char *buf, unsigned buflen, char *encoded,
                  int trunc, unsigned llen, unsigned wscnt, BIO *mem)
{
    static const unsigned char b64[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int pos = 0;
    char nl = '\n';

    /* Use a verbatim encoding when provided */
    if (encoded != NULL) {
        int elen = strlen(encoded);

        return BIO_write(mem, encoded, elen) == elen;
    }

    /* Encode full 3-octet groups */
    while (buflen > 2) {
        unsigned long v = buf[0] << 16 | buf[1] << 8 | buf[2];

        if (memoutws(mem, b64[v >> 18], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v >> 12) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v >> 6) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[v & 0x3f], wscnt, llen, &pos) == 0)
            return 0;
        buf += 3;
        buflen -= 3;
    }

    /* Encode and pad final 1 or 2 octet group */
    if (buflen == 2) {
        unsigned long v = buf[0] << 8 | buf[1];

        if (memoutws(mem, b64[(v >> 10) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v >> 4) & 0x3f], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v & 0xf) << 2], wscnt, llen, &pos) == 0
            || memoutws(mem, '=', wscnt, llen, &pos) == 0)
            return 0;
    } else if (buflen == 1) {
        unsigned long v = buf[0];

        if (memoutws(mem, b64[v >> 2], wscnt, llen, &pos) == 0
            || memoutws(mem, b64[(v & 0x3) << 4], wscnt, llen, &pos) == 0
            || memoutws(mem, '=', wscnt, llen, &pos) == 0
            || memoutws(mem, '=', wscnt, llen, &pos) == 0)
            return 0;
    }

    while (trunc-- > 0)
        if (memoutws(mem, 'A', wscnt, llen, &pos) == 0)
            return 0;

    /* Terminate last line */
    if (pos > 0 && BIO_write(mem, &nl, 1) != 1)
        return 0;

    return 1;
}

/* Append one base64 codepoint, adding newlines after every `llen` bytes */
static int memout(BIO *mem, char c, int llen, int *pos)
{
    if (BIO_write(mem, &c, 1) != 1)
        return 0;
    if (++*pos == llen) {
        *pos = 0;
        c = '\n';
        if (BIO_write(mem, &c, 1) != 1)
            return 0;
    }
    return 1;
}


// This test function always returns true
static int test_decode_base64_cases_scalar_utf8(void)
{
    // Simply return 1 to indicate success
    return 1;
}


/*-------------------------------------------------------------
 * Test Function: decode_base64_cases
 *
 *   For each test case (here, one case: {0x53, 0x53} equivalent to "SS"),
 *   it computes the maximum binary length, decodes the Base64 tail using
 *   base64_tail_decode, and asserts that the decoded byte count matches
 *   the expected value (1) and that no error occurred.
 *-------------------------------------------------------------*/
static int test_decode_base64_cases(void)
{
    printf(GREEN_TEXT("DEBUG: Entered Test\n"));

    /* Define one test case: "SS" */
    const char *cases[] = { "SS" };
    const size_t expected_counts[] = { 1 };
    size_t num_cases = sizeof(cases) / sizeof(cases[0]);

    for (size_t i = 0; i < num_cases; i++) {
        size_t len = strlen(cases[i]); 
        size_t max_len = maximal_binary_length_from_base64(cases[i], len);
        unsigned char *buffer = OPENSSL_malloc(max_len);
        if (buffer == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        /* Call base64_tail_decode with a NULL EVP_ENCODE_CTX.
         * Our function returns the number of decoded bytes on success,
         * or -1 on error.
         */
        // TODO: the ctx isn't supposed to be NULL, come back to it when implementing the SRP alphabet/tables
        // int decoded = base64_tail_decode_trim_end(NULL, (char *)buffer, cases[i], (int)len);
        int decoded = base64_tail_decode_trim_end(NULL, cases[i], len, (char *)buffer);
        if (decoded < 0) {
            TEST_error(RED_TEXT("base64_to_binary_with_ws error in test case %zu"), i);
            OPENSSL_free(buffer);
            return 0;
        }
        if ((size_t)decoded != expected_counts[i]) {
            TEST_error(RED_TEXT("Decoded byte count mismatch: got %d, expected %zu"), decoded, expected_counts[i]);


            OPENSSL_free(buffer);
            return 0;
        }
        OPENSSL_free(buffer);
    }
    return 1;
}


// The setup_tests() function is called by the test harness to register tests.
int setup_tests(void)
{
    // Register our sample test. The macro ADD_TEST() takes our test function.
    ADD_TEST(test_decode_base64_cases);

    // Return 1 to indicate successful test setup.
    return 1;
}
