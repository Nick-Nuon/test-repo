
// /*
//  * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
//  *
//  * Licensed under the Apache License 2.0 (the "License").  You may not use
//  * this file except in compliance with the License.  You can obtain a copy
//  * in the file LICENSE in the source distribution or at
//  * https://www.openssl.org/source/license.html
//  */

#include <stdio.h>
#include "testutil.h"
#include <openssl/evp.h>

#define RED_TEXT(str)     "\033[31m" str "\033[0m"

/* Example: ASSERT_EQUAL for integers */
#define ASSERT_EQUAL_INT(actual, expected) do {                      \
    if ((actual) != (expected)) {                                      \
        TEST_error(RED_TEXT("Assertion failed: %s != %s, got %d, expected %d"), \
                   #actual, #expected, (int)(actual), (int)(expected));\
        return 0;                                                    \
    }                                                                \
} while(0)

#define ASSERT_NOT_EQUAL_INT(actual, expected) do {                      \
    if ((actual) == (expected)) {                                      \
        TEST_error(RED_TEXT("Assertion failed: %s == %s, got %d, didn't want %d"), \
                   #actual, #expected, (int)(actual), (int)(expected));\
        OPENSSL_free(buffer);                                                    \
        return 0;                                                    \
    }                                                                \
} while(0)

/* Macro with an extra message */
#define ASSERT_EQUAL_INT_MSG(actual, expected, msg) do {                   \
    if ((actual) != (expected)) {                                          \
        TEST_error(RED_TEXT("Assertion failed: %s != %s, got %d, expected %d. %s"), \
                   #actual, #expected, (int)(actual), (int)(expected), msg);  \
        return 0;                                                        \
    }                                                                    \
} while(0)

/* ASSERT_EQUAL for size_t values */
#define ASSERT_EQUAL_SIZE(actual, expected) do {                     \
    if ((actual) != (expected)) {                                      \
        TEST_error(RED_TEXT("Assertion failed: %s != %s, got %zu, expected %zu"), \
                   #actual, #expected, (actual), (expected));         \
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

#define ASSERT_TRUE(cond) do {                        \
    if (!(cond)) {                                    \
        TEST_error(RED_TEXT("Assertion failed: %s is false at %s:%d"), \
                   #cond, __FILE__, __LINE__);          \
        return 0;                                   \
    }                                               \
} while(0)

#define PRINT_STRINGS(expected, actual, len) do {                         \
    size_t _i;                                                            \
    /* Print as regular strings */                                        \
    printf("Expected buffer (%s) as string: \"%s\"\n", #expected, (expected)); \
    printf("Actual buffer   (%s) as string: \"%s\"\n", #actual, (actual));   \
    /* Print as hexadecimal */                                            \
    printf("Expected buffer (%s) as hex: ", #expected);                    \
    for (_i = 0; _i < (len); _i++) {                                       \
        printf("%02x ", (unsigned int)(expected)[_i]);                    \
    }                                                                     \
    printf("\n");                                                         \
    printf("Actual buffer   (%s) as hex: ", #actual);                      \
    for (_i = 0; _i < (len); _i++) {                                       \
        printf("%02x ", (unsigned int)(actual)[_i]);                      \
    }                                                                     \
    printf("\n");                                                         \
} while(0)


#define ASSERT_MEM_EQUAL(expected, actual, len) do {                         \
    size_t _i, _mismatch_index = (size_t)(-1);                               \
    for (_i = 0; _i < (len); _i++) {                                         \
        if ((expected)[_i] != (actual)[_i]) {                                \
            _mismatch_index = _i;                                            \
            break;                                                         \
        }                                                                    \
    }                                                                        \
    if (_mismatch_index != (size_t)(-1)) {                                   \
        printf("Memory mismatch detected:\n");                             \
        printf("Expected buffer:\n");                                         \
        for (_i = 0; _i < (len); _i++) {                                     \
            printf("%02x ", (unsigned int)(expected)[_i]);                   \
            if ((_i + 1) % 9 == 0) printf("\n");                           \
        }                                                                    \
        if (_i % 9) printf("\n");                                          \
        printf("Actual buffer:\n");                                      \
        for (_i = 0; _i < (len); _i++) {                                     \
            printf("%02x ", (unsigned int)(actual)[_i]);                     \
            if ((_i + 1) % 9 == 0) printf("\n");                           \
        }                                                                    \
        if (_i % 9) printf("\n");                                          \
        printf("Memory mismatch at index %zu: got %02x, expected %02x\n",     \
               _mismatch_index,                                              \
               (unsigned int)(actual)[_mismatch_index],                      \
               (unsigned int)(expected)[_mismatch_index]);                   \
        return 0;                                                            \
        }                                                                        \
    } while(0)

static int test_encode_line_lengths(void)
{
    const int trials = 50;
    const int max_input_len = 256;
    unsigned int seed = 12345;

    for (int t = 0; t < trials; t++) {
        int inl = rand_r(&seed) % max_input_len;
        unsigned char input[max_input_len];
        for (int i = 0; i < inl; i++)
            input[i] = (unsigned char)(rand_r(&seed) % 256);

        for (int linelen = 3; linelen <= 80; linelen += 3) {
            EVP_ENCODE_CTX *ctx_simd = EVP_ENCODE_CTX_new();
            EVP_ENCODE_CTX *ctx_ref  = EVP_ENCODE_CTX_new();

            unsigned char out_simd[512] = {0};
            unsigned char out_ref[512] = {0};
            int outlen_simd = 0, outlen_ref = 0;
            int finlen_simd = 0, finlen_ref = 0;

            if (!ctx_simd || !ctx_ref) {
                EVP_ENCODE_CTX_free(ctx_simd);
                EVP_ENCODE_CTX_free(ctx_ref);
                TEST_error("Out of memory for contexts");
                return 0;
            }

            // printf("Trial %d, input length %d, line length %d\n", t, inl, linelen);
            // initialize with specific line lengths
            EVP_EncodeInit(ctx_simd);
            EVP_EncodeInit(ctx_ref);
            EVP_Set_length(ctx_simd, linelen);
            EVP_Set_length(ctx_ref, linelen);

            int ret_simd = EVP_EncodeUpdate(ctx_simd, out_simd, &outlen_simd, input, inl);
            int ret_ref  = EVP_EncodeUpdate_openssl(ctx_ref, out_ref, &outlen_ref, input, inl);

            ASSERT_EQUAL_INT(ret_simd, ret_ref);
            ASSERT_EQUAL_INT(outlen_simd, outlen_ref);
            ASSERT_MEM_EQUAL(out_simd, out_ref, outlen_ref);

            EVP_ENCODE_CTX_free(ctx_simd);
            EVP_ENCODE_CTX_free(ctx_ref);
        }
    }

    return 1;

}

int setup_tests(void)
{
    ADD_TEST(test_encode_line_lengths);
    return 1;
}
