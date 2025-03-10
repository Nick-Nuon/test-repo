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


/* Example: ASSERT_EQUAL for integers */
#define ASSERT_EQUAL_INT(actual, expected) do {                      \
    if ((actual) != (expected)) {                                      \
        TEST_error(RED_TEXT("Assertion failed: %s != %s, got %d, expected %d"), \
                   #actual, #expected, (int)(actual), (int)(expected));\
        return 0;                                                    \
    }                                                                \
} while(0)

/* ASSERT_EQUAL for size_t values */
#define ASSERT_EQUAL_SIZE(actual, expected) do {                     \
    if ((actual) != (expected)) {                                      \
        TEST_error(RED_TEXT("Assertion failed: %s != %s, got %zu, expected %zu"), \
                   #actual, #expected, (actual), (expected));         \
        return 0;                                                    \
    }                                                                \
} while(0)

/* ASSERT_STREQ: compare two null-terminated strings */
#define ASSERT_STREQ(actual, expected) do {                          \
    if (strcmp((actual), (expected)) != 0) {                           \
        TEST_error(RED_TEXT("Assertion failed: strings \"%s\" != \"%s\""), (actual), (expected)); \
        return 0;                                                    \
    }                                                                \
} while(0)

/* ASSERT_EQUAL_HEX: for comparing two byte values with an index context */
#define ASSERT_EQUAL_HEX(idx, actual, expected) do {                 \
    if ((unsigned int)(actual) != (unsigned int)(expected)) {          \
        TEST_error(RED_TEXT("Mismatch at index %zu: got %02x, expected %02x"), \
                   (idx), (unsigned int)(actual), (unsigned int)(expected)); \
        return 0;                                                    \
    }                                                                \
} while(0)

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

/* Define one test case: expected decoded string "abcd", 
    encoded string with extra whitespace and padding " Y\fW\tJ\njZ A=\r= " */
typedef struct {
    const char *decoded;  /* expected output */
    const char *encoded;  /* input Base64 string */
} case_pair;

static int test_complete_decode_base64_cases(void)
{
    printf(GREEN_TEXT("DEBUG: Entered complete_decode_base64_cases Test\n"));

    case_pair cases[] = {
        {"abcd", " Y\fW\tJ\njZ A=\r= "}
    };
    size_t num_cases = sizeof(cases) / sizeof(cases[0]);
    size_t i;

    /* First, test using base64_to_binary (normal decoding) */
    for(i = 0; i < num_cases; i++) {
        size_t enc_len = strlen(cases[i].encoded);
        size_t max_len = maximal_binary_length_from_base64(cases[i].encoded, enc_len);
        unsigned char *buffer = OPENSSL_malloc(max_len);
        if(buffer == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        int r = base64_tail_decode_trim_end(NULL,cases[i].encoded, enc_len, (char *)buffer);
        if(r < 0) {
            TEST_error(RED_TEXT("base64_to_binary error in test case %zu"), i);
            OPENSSL_free(buffer);
            return 0;
        }
        if(r != strlen(cases[i].decoded)) {
            TEST_error(RED_TEXT("Decoded byte count mismatch in test case %zu: got %zu, expected %zu"), 
                       i, r, strlen(cases[i].decoded));
            OPENSSL_free(buffer);
            return 0;
        }

        for(size_t j = 0; j < r; j++) {
            if(buffer[j] != cases[i].decoded[j]) {
                TEST_error(RED_TEXT("Mismatch at index %zu in test case %zu: got %02x, expected %02x"), 
                           j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
                OPENSSL_free(buffer);
                return 0;
            }
        }
        OPENSSL_free(buffer);
    }

    printf(GREEN_TEXT(" --  "));

    // /* Second, test using base64_to_binary_safe */
    // for(i = 0; i < num_cases; i++) {
    //     size_t enc_len = strlen(cases[i].encoded);
    //     size_t max_len = maximal_binary_length_from_base64(cases[i].encoded, enc_len);
    //     unsigned char *buffer = OPENSSL_malloc(max_len);
    //     if(buffer == NULL) {
    //         TEST_error("Out of memory");
    //         return 0;
    //     }
    //     size_t out_len = max_len;
    //     result r = base64_to_binary_safe(cases[i].encoded, enc_len, (char *)buffer, &out_len, 0);
    //     if(r.error != SUCCESS) {
    //         TEST_error(RED_TEXT("base64_to_binary_safe error in test case %zu"), i);
    //         OPENSSL_free(buffer);
    //         return 0;
    //     }
    //     if(out_len != strlen(cases[i].decoded)) {
    //         TEST_error(RED_TEXT("Safe decoded byte count mismatch in test case %zu: got %zu, expected %zu"),
    //                    i, out_len, strlen(cases[i].decoded));
    //         OPENSSL_free(buffer);
    //         return 0;
    //     }
    //     for(size_t j = 0; j < out_len; j++) {
    //         if(buffer[j] != cases[i].decoded[j]) {
    //             TEST_error(RED_TEXT("Safe mismatch at index %zu in test case %zu: got %02x, expected %02x"),
    //                        j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
    //             OPENSSL_free(buffer);
    //             return 0;
    //         }
    //     }
    //     OPENSSL_free(buffer);
    // }
    return 1;
}

static int test_encode_base64_cases(void)
{
    printf(GREEN_TEXT("DEBUG: Entered encode_base64_cases Test\n"));

    /* Define test cases as an array of case_pair.
       These mirror your C++ test cases.
    */
    case_pair cases[] = {
        { "Hello, World!", "SGVsbG8sIFdvcmxkIQ==" },
        { "GeeksforGeeks", "R2Vla3Nmb3JHZWVrcw==" },
        { "123456", "MTIzNDU2" },
        { "Base64 Encoding", "QmFzZTY0IEVuY29kaW5n" },
        { "!R~J2jL&mI]O)3=c:G3Mo)oqmJdxoprTZDyxEvU0MI.'Ww5H{G>}y;;+B8E_Ah,Ed[ PdBqY'^N>O$4:7LK1<:|7)btV@|{YWR$$Er59-XjVrFl4L}~yzTEd4'E[@k",
          "IVJ+SjJqTCZtSV1PKTM9YzpHM01vKW9xbUpkeG9wclRaRHl4RXZVME1JLidXdzVIe0c+fXk7OytCOEVfQWgsRWRbIFBkQnFZJ15OPk8kNDo3TEsxPDp8NylidFZAfHtZV1IkJEVyNTktWGpWckZsNEx9fnl6VEVkNCdFW0Br" }
    };
    size_t num_cases = sizeof(cases) / sizeof(cases[0]);
    size_t i, j;

    /* --- Part 2: Test base64_to_binary decoding (normal) --- */
    printf(GREEN_TEXT(" -- Testing base64_to_binary decoding (normal)\n"));
    for (i = 0; i < num_cases; i++) {
        size_t enc_len = strlen(cases[i].encoded);
        size_t expected_dec_len = strlen(cases[i].decoded);
        size_t bufsize = maximal_binary_length_from_base64(cases[i].encoded, enc_len);
        char *buffer = OPENSSL_malloc(bufsize);
        if (!buffer) {
            TEST_error("Out of memory in decoding test case %zu", i);
            return 0;
        }
        int r = base64_tail_decode_trim_end(NULL,cases[i].encoded, enc_len, (char *)buffer);
        if(r < 0) {
            TEST_error(RED_TEXT("base64_to_binary error in test case %zu"), i);
            OPENSSL_free(buffer);
            return 0;
        }
        if(r != strlen(cases[i].decoded)) {
            TEST_error(RED_TEXT("Decoded byte count mismatch in test case %zu: got %zu, expected %zu"), 
                       i, r, strlen(cases[i].decoded));
            OPENSSL_free(buffer);
            return 0;
        }

        for(size_t j = 0; j < r; j++) {
            if(buffer[j] != cases[i].decoded[j]) {
                TEST_error(RED_TEXT("Mismatch at index %zu in test case %zu: got %02x, expected %02x"), 
                           j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
                OPENSSL_free(buffer);
                return 0;
            }
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
    ADD_TEST(test_complete_decode_base64_cases);
    ADD_TEST(test_encode_base64_cases);

    // Return 1 to indicate successful test setup.
    return 1;
}
