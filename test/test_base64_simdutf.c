/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "testutil.h"
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "evp_local.h"

#define RED_TEXT(str)     "\033[31m" str "\033[0m"
#define ASSERT_EQUAL_INT(actual, expected) do {                      \
    if ((actual) != (expected)) {                                      \
        TEST_error(RED_TEXT("Assertion failed: %s != %s, got %d, expected %d"), \
                   #actual, #expected, (int)(actual), (int)(expected));\
        return 0;                                                    \
    }                                                                \
} while(0)

#define ASSERT_MEM_EQUAL(expected, actual, len)                                          \
    do {                                                                                 \
        const unsigned char *_exp = (const unsigned char *)(expected);                   \
        const unsigned char *_act = (const unsigned char *)(actual);                     \
        size_t _n = (size_t)(((len) < 0) ? 0 : (len));                                   \
        size_t _i, _mismatch_index = (size_t)-1;                                         \
                                                                                         \
        if (memcmp(_exp, _act, _n) != 0) {                                               \
            for (_i = 0; _i < _n; _i++) {                                                \
                if (_exp[_i] != _act[_i]) {                                              \
                    _mismatch_index = _i;                                                \
                    break;                                                               \
                }                                                                        \
            }                                                                            \
            printf("Memory mismatch detected:\n");                                       \
            printf("Expected buffer:\n");                                                \
            for (_i = 0; _i < _n; _i++) {                                                \
                if (_i == _mismatch_index)                                               \
                    printf("\033[31m%02x\033[0m ", (unsigned)_exp[_i]);                  \
                else                                                                     \
                    printf("%02x ", (unsigned)_exp[_i]);                                 \
                if ((_i + 1) % 16 == 0) printf("\n");                                    \
            }                                                                            \
            if (_n % 16) printf("\n");                                                   \
                                                                                         \
            printf("*************************************\n");                           \
            printf("Actual buffer:\n");                                                  \
            for (_i = 0; _i < _n; _i++) {                                                \
                if (_i == _mismatch_index)                                               \
                    printf("\033[31m%02x\033[0m ", (unsigned)_act[_i]);                  \
                else                                                                     \
                    printf("%02x ", (unsigned)_act[_i]);                                 \
                if ((_i + 1) % 16 == 0) printf("\n");                                    \
            }                                                                            \
            if (_n % 16) printf("\n");                                                   \
                                                                                         \
            if (_mismatch_index != (size_t)-1) {                                         \
                printf("Mismatch at index %zu: got \033[31m%02x\033[0m, "                \
                       "expected \033[31m%02x\033[0m\n",                                  \
                       _mismatch_index, (unsigned)_act[_mismatch_index],                 \
                       (unsigned)_exp[_mismatch_index]);                                  \
            }                                                                            \
            return 0; \
        }                                                                                \
    } while (0)

static void fuzz_fill_encode_ctx(EVP_ENCODE_CTX *ctx, int max_fill)
{
    static int seeded = 0;

    if (!seeded) {
        srand((unsigned)time(NULL));
        seeded = 1;
    }

    int num = rand() % (max_fill + 1);
    ctx->num = num;

    for (int i = 0; i < num; i++) {
        ctx->enc_data[i] = (unsigned char)(rand() & 0xFF);
    }

    ctx->length = (rand() % 80) + 1;
    ctx->line_num = rand() % (ctx->length + 1);
}

static inline uint32_t next_u32(uint32_t *state) {
    *state = (*state * 1664525u) + 1013904223u;
    return *state;
}

static int test_encode_line_lengths_reinforced(void)
{
    const int trials = 50;
    #define MAX_INPUT_LEN 3000
    unsigned int seed = 12345;
    /* Generous output buffers (Update + Final + newlines), plus a guard byte */
    unsigned char out_simd[9000 * 2 + 1] = { 0 };
    unsigned char out_ref[9000 * 2 + 1] = { 0 };

    for (int t = 0; t < trials; t++) {
        uint32_t r = next_u32(&seed);
        int inl = rand_r(&seed) % MAX_INPUT_LEN;
        // int inl = r % MAX_INPUT_LEN;
        /* Fresh random input */
        unsigned char input[MAX_INPUT_LEN];

        for (int i = 0; i < inl; i++)
            input[i] = (unsigned char)(rand_r(&seed) % 256);
            // input[i] = (unsigned char)(r % 256);

        for (int partial_ctx_fill = 0; partial_ctx_fill <= 80;
             partial_ctx_fill += 1) {
            for (int ctx_len = 1; ctx_len <= 80; ctx_len += 1) {
                printf
                ("Trial %d, input length %d, ctx length %d, partial ctx fill %d\n",
                 t + 1, inl, ctx_len, partial_ctx_fill);
                EVP_ENCODE_CTX *ctx_simd = EVP_ENCODE_CTX_new();
                EVP_ENCODE_CTX *ctx_ref = EVP_ENCODE_CTX_new();

                fuzz_fill_encode_ctx(ctx_simd, partial_ctx_fill);

                memset(out_simd, 0xCC, sizeof(out_simd)); /* poison to catch short writes */
                memset(out_ref, 0xDD, sizeof(out_ref));

                int outlen_simd = 0, outlen_ref = 0; /* bytes produced by Update */
                int finlen_simd = 0, finlen_ref = 0; /* bytes produced by Final */

                if (!ctx_simd || !ctx_ref) {
                    EVP_ENCODE_CTX_free(ctx_simd);
                    EVP_ENCODE_CTX_free(ctx_ref);
                    TEST_error("Out of memory for contexts");
                    return 0;
                }

                EVP_EncodeInit(ctx_simd);
                EVP_EncodeInit(ctx_ref);
                ctx_simd->length = ctx_len;
                ctx_ref->length = ctx_len;

                for (int i = 0; i < 2; i++) {
                    if (i % 2 == 0) {
                        /* Turn SRP alphabet OFF */
                        ctx_simd->flags &= ~EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                        ctx_ref->flags &= ~EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                    } else {
                        /* Turn SRP alphabet ON */
                        ctx_simd->flags |= EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                        ctx_ref->flags |= EVP_ENCODE_CTX_USE_SRP_ALPHABET;
                    }

                    int ret_simd =
                        EVP_EncodeUpdate(ctx_simd, out_simd, &outlen_simd,
                                         input, (int)inl);
                    int ret_ref =
                        EVP_EncodeUpdate_openssl(ctx_ref, out_ref, &outlen_ref,
                                                 input, (int)inl);

                    ASSERT_EQUAL_INT(ret_simd, ret_ref);
                    ASSERT_MEM_EQUAL(out_ref, out_simd, outlen_ref);
                    ASSERT_EQUAL_INT(outlen_simd, outlen_ref);

                    EVP_EncodeFinal(ctx_simd, out_simd + outlen_simd,
                                    &finlen_simd);
                    EVP_EncodeFinal_openssl(ctx_ref, out_ref + outlen_ref,
                                            &finlen_ref);

                    int total_ref = outlen_ref + finlen_ref;

                    ASSERT_EQUAL_INT(finlen_simd, finlen_ref);
                    ASSERT_MEM_EQUAL(out_ref, out_simd, total_ref);
                }

                EVP_ENCODE_CTX_free(ctx_simd);
                EVP_ENCODE_CTX_free(ctx_ref);
            }
        }
    }

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_encode_line_lengths_reinforced);

    return 1;
}
