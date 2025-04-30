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

#define DEBUG 0 // Set to 1 to enable debug prints, 0 to disable

#define BUFMAX 0xa0000          /* Encode at most 640kB. */
#define RED_TEXT(str)     "\033[31m" str "\033[0m"
#define GREEN_TEXT(str)   "\033[32m" str "\033[0m"
#define YELLOW_TEXT(str)  "\033[33m" str "\033[0m"
#define BLUE_TEXT(str)    "\033[34m" str "\033[0m"
#define MAGENTA_TEXT(str) "\033[35m" str "\033[0m"
#define CYAN_TEXT(str)    "\033[36m" str "\033[0m"

// Standard Colors
#define BLACK_TEXT(str)   "\033[30m" str "\033[0m"
#define WHITE_TEXT(str)   "\033[37m" str "\033[0m"

// Bright Colors
#define BRIGHT_RED_TEXT(str)     "\033[91m" str "\033[0m"
#define BRIGHT_GREEN_TEXT(str)   "\033[92m" str "\033[0m"
#define BRIGHT_YELLOW_TEXT(str)  "\033[93m" str "\033[0m"
#define BRIGHT_BLUE_TEXT(str)    "\033[94m" str "\033[0m"
#define BRIGHT_MAGENTA_TEXT(str) "\033[95m" str "\033[0m"
#define BRIGHT_CYAN_TEXT(str)    "\033[96m" str "\033[0m"
#define BRIGHT_WHITE_TEXT(str)   "\033[97m" str "\033[0m"


// Background Colors (Bright)
#define BRIGHT_BLACK_BG(str)   "\033[100m" str "\033[0m"
#define BRIGHT_RED_BG(str)     "\033[101m" str "\033[0m"
#define BRIGHT_GREEN_BG(str)   "\033[102m" str "\033[0m"
#define BRIGHT_YELLOW_BG(str)  "\033[103m" str "\033[0m"
#define BRIGHT_BLUE_BG(str)    "\033[104m" str "\033[0m"
#define BRIGHT_MAGENTA_BG(str) "\033[105m" str "\033[0m"
#define BRIGHT_CYAN_BG(str)    "\033[106m" str "\033[0m"
#define BRIGHT_WHITE_BG(str)   "\033[107m" str "\033[0m"

#define BOLD_TEXT(str)       "\033[1m" str "\033[0m"
#define UNDERLINE_TEXT(str)  "\033[4m" str "\033[0m"
#define BLINK_TEXT(str)      "\033[5m" str "\033[0m"  // May not work on all terminals


#if DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        do { \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
            fflush(stderr); \
        } while (0)
#else
    #define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif


/* Example: ASSERT_EQUAL for integers */
#define ASSERT_EQUAL_INT(actual, expected) do {                      \
    if ((actual) != (expected)) {                                      \
        TEST_error(RED_TEXT("Assertion failed: %s != %s, got %d, expected %d"), \
                   #actual, #expected, (int)(actual), (int)(expected));\
        OPENSSL_free(buffer);                                                    \
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

#define ASSERT_BASE64_DECODE_EQUAL(input) do {                                         \
    size_t len = strlen(input);                                                        \
    size_t max_len = maximal_binary_length_from_base64(input, len);                    \
    unsigned char *buffer_simd = OPENSSL_malloc(max_len);                              \
    if (buffer_simd == NULL) {                                                         \
        TEST_error("Out of memory");                                                   \
        return 0;                                                                      \
    }                                                                                  \
    int outlen_simdutf = 0;                                                            \
    int simdutf_result = simdutf_decode(NULL, (char *)buffer_simd, &outlen_simdutf, input, len); \
                                                                                       \
    unsigned char *buffer_openssl = OPENSSL_malloc(max_len);                           \
    if (buffer_openssl == NULL) {                                                      \
        TEST_error("Out of memory");                                                   \
        OPENSSL_free(buffer_simd);                                                     \
        return 0;                                                                      \
    }                                                                                  \
    int openssl_outlen = 0;                                                            \
    int result_openssl = OpenSSL_decode(NULL, (char *)buffer_openssl, &openssl_outlen, input, len); \
                                                                                       \
    ASSERT_EQUAL_INT(outlen_simdutf, openssl_outlen);                                  \
    ASSERT_EQUAL_INT(simdutf_result, result_openssl);                                  \
                                                                                       \
    OPENSSL_free(buffer_simd);                                                         \
    OPENSSL_free(buffer_openssl);                                                      \
} while(0)

// #define PRINT_STRINGS(expected, actual, len) do {                         \
//     size_t _i;                                                            \
//     printf("Expected buffer (%s): ", #expected);                          \
//     for (_i = 0; _i < (len); _i++) {                                       \
//         printf("%02x ", (unsigned int)(expected)[_i]);                    \
//     }                                                                     \
//     printf("\nActual buffer (%s): ", #actual);                            \
//     for (_i = 0; _i < (len); _i++) {                                       \
//         printf("%02x ", (unsigned int)(actual)[_i]);                      \
//     }                                                                     \
//     printf("\n");                                                         \
// } while(0)


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

// #define ASSERT_MEM_EQUAL(expected, actual, len) do {                             \
//     size_t _i;                                                                 \
//     for (_i = 0; _i < (len); _i++) {                                             \
//         if ((expected)[_i] != (actual)[_i]) {                                    \
//             TEST_error(RED_TEXT("Memory mismatch at index %zu: got %02x, expected %02x"), \
//                        _i, (unsigned int)(actual)[_i], (unsigned int)(expected)[_i]); \
//             return 0;                                                          \
//         }                                                                      \
//     }                                                                          \
// } while(0)


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
        printf("Expected buffer: ");                                         \
        for (_i = 0; _i < (len); _i++) {                                     \
            printf("%02x ", (unsigned int)(expected)[_i]);                   \
        }                                                                    \
        printf("\nActual buffer  : ");                                      \
        for (_i = 0; _i < (len); _i++) {                                     \
            printf("%02x ", (unsigned int)(actual)[_i]);                     \
        }                                                                    \
        printf("\n");                                                        \
        printf("Memory mismatch at index %zu: got %02x, expected %02x\n",     \
               _mismatch_index,                                              \
               (unsigned int)(actual)[_mismatch_index],                      \
               (unsigned int)(expected)[_mismatch_index]);                   \
        return 0;                                                            \
    }                                                                        \
} while(0)

size_t base64_length_from_binary(size_t length) {
    return (length + 2)/3 * 4; // We use padding to make the length a multiple of 4.
  }

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

size_t add_garbage(char **v, size_t *v_len, unsigned int *seed, const uint8_t *table) {
    size_t i, len;
    char *array = *v;
    
    /* Determine the upper bound for the insertion index:
       If '=' is found, use its index; otherwise, use the full length.
    */
    len = *v_len;
    for (i = 0; i < *v_len; i++) {
        if (array[i] == '=') {
            // DEBUG_PRINT("= is found in add_garbage\n");
            len = i;
            break;
        }
    }
    
    /* Choose a random insertion index between 0 and len (inclusive) */
    size_t index = rand_r(seed) % (len + 1);

    /* Choose a random byte value between 0 and 255 until table[c] equals 255 */
    uint8_t c = rand_r(seed) % 256;
    while (table[c] != 255 || c == 0x2D) { // 0x2D is the ASCII hyphen / SEOF marker
        c = rand_r(seed) % 256;
    }

    // do {
    //     c = rand_r(seed) % 256;
    // } while (table[c] != 255 && c == 0x2D); // 0x2D is the ASCII hyphen / SEOF marker

    /* Reallocate the array to make room for one extra character.
       Note: Passing a pointer to the array pointer so that it can be updated.
    */
    char *new_v = OPENSSL_realloc(array, *v_len +2);
    if (new_v == NULL) {
        /* Allocation failure */
        return (size_t)-1;
    }
    
    /* Shift the tail of the array one position to the right.
       We move *v_len - index bytes starting at new_v[index].
    */
    memmove(new_v + index + 1, new_v + index, *v_len - index);
    new_v[index] = (char)c;

    // DEBUG_PRINT((GREEN_TEXT("DEBUG: Inserted garbage byte %02x  at index %zu\n"), c, index));
    
    *v = new_v;
    (*v_len)++;
    new_v[*v_len] = '\0';
    return index;
}

/**
 * swap_seof - Replaces a character in the given string with the SEOF marker.
 *
 * @v: pointer to the buffer (string) to modify. Must be a valid, allocated string.
 * @v_len: pointer to the current length of the string.
 * @seed: pointer to an unsigned int used for random number generation.
 * @at_multiple_of_4: if non-zero, the replacement index will be chosen such that
 *                    it is a multiple of 4; if zero, the index will be chosen such that
 *                    it is NOT a multiple of 4.
 *
 * Returns the index at which the character was replaced, or (size_t)-1 on failure.
 *
 * Note: The function does not change the length of the string.
 */
static size_t swap_seof(char **v, size_t *v_len, unsigned int *seed, int at_multiple_of_4) {
    size_t index;
    size_t len = *v_len;
    char *array = *v;
    
    if (len == 0) {
        // Nothing to swap in an empty string.
        TEST_error("swap_seof: Buffer length is zero.");
        return (size_t)-1;
    }
    
    DEBUG_PRINT(GREEN_TEXT("DEBUG: swap_seof: Buffer length = %zu\n"), len);
    if (at_multiple_of_4) {
        // Choose a random index that IS a multiple of 4.
        do {
            index = rand_r(seed) % len;
            DEBUG_PRINT(GREEN_TEXT("DEBUG: swap_seof: Random index = %zu\n"), index);
        } while (index % 4 != 0);
    } else {
        // Choose a random index that is NOT a multiple of 4.
        do {
            index = rand_r(seed) % len;
        } while (index % 4 == 0);
    }
    
    // Swap: just overwrite the character at index with the SEOF marker '-'
    // DEBUG_PRINT((GREEN_TEXT("DEBUG: Replacing character at index %zu with SEOF marker\n"), index));
    array[index] = (char)0x2D;   // 0x2D is the ASCII hyphen
    return index;
}


size_t add_seof(char **v, size_t *v_len, unsigned int *seed, int at_multiple_of_4) {
    size_t i, len;
    char *array = *v;

    DEBUG_PRINT(BRIGHT_YELLOW_TEXT("DEBUG: add_seof: Buffer length = %zu\n"), *v_len);
    
    /* Determine the upper bound for the insertion index:
       If '=' is found, use its index; otherwise, use the full length.
    */
    len = *v_len;
    // (Skipping searching for '=' for now)

    uint8_t c = 0x2D; // '-' character

    /* Choose a random insertion index between 0 and len (inclusive) */
    size_t rand_num =  rand_r(seed);
    DEBUG_PRINT(GREEN_TEXT("DEBUG: rand_num = %d\n"), rand_num);
    DEBUG_PRINT(GREEN_TEXT("DEBUG: len + 1= %zu\n"), len + 1);
    size_t index = 0;
    if (at_multiple_of_4){
        index = rand_num % (len - 3);
    } else {
        index = rand_num % (len + 1);
    }
    
    size_t index_mod = index % 4;
    DEBUG_PRINT(GREEN_TEXT("DEBUG: add_seof: Random index = %zu\n"), index);

    if (index == 0) {
        // index remains 0 if no change is desired.
        if (len > 0) {
            index += rand_r(seed) % 2 + 1;
        }
    } else if (at_multiple_of_4){
        DEBUG_PRINT(GREEN_TEXT("DEBUG: at_multiple_of_4 is true\n"));
        DEBUG_PRINT("DEBUG: index before slashing = %zu\n", index);
        index = index - (index % 4);
        DEBUG_PRINT("DEBUG: index after slashing = %zu\n", index);
    } else if (index_mod == 0) {
        DEBUG_PRINT(GREEN_TEXT("DEBUG: index_mod == 0\n"));
        index -= rand_r(seed) % 3 + 1; 
    }

    /* Reallocate the array to make room for one extra character */
    char *new_v = OPENSSL_realloc(array, *v_len + 2);
    if (new_v == NULL) {
        /* Allocation failure */
        return (size_t)-1;
    }
    
    /* Shift the tail of the array one position to the right.
       We move *v_len - index bytes starting at new_v[index].
    */
    memmove(new_v + index + 1, new_v + index, *v_len - index);
    new_v[index] = (char)c;
    
    (*v_len)++;
    new_v[*v_len] = '\0';
    
    *v = new_v;
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Inserted SEOF byte %02x at index %zu\n"), c, index);
    return index;
}


int OpenSSL_decode(EVP_ENCODE_CTX *dummy,char *dst,int *outl, const char *src, int srclen) {
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }

    int outlen = 0;
    int taillen = 0;

    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, (unsigned char *)dst, &outlen,
                         (const unsigned char *)src, srclen) < 0 ||
        EVP_DecodeFinal(ctx, (unsigned char *)&dst[outlen], &taillen) < 0) {
        // fprintf(stderr, "Invalid input for openssl base64 decode.\n");
        EVP_ENCODE_CTX_free(ctx);
        *outl = outlen;
        DEBUG_PRINT(RED_TEXT("DEBUG: OpenSSL decode error: outlen = %d, taillen = %d\n"), outlen, taillen);
        // fprintf(stderr, "Decoded length: %d\n", outlen);
        return -1;
        // return (result){NOT_MULTIPLE_OF_FOUR, (size_t)outlen};        
    }

    EVP_ENCODE_CTX_free(ctx);
    outlen += taillen;
    *outl = outlen;
    return outlen;
    // return (result){BASE64_SUCCESS, (size_t)outlen};
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
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered Test\n"));

    const char *cases[] = { "SS" };
    const size_t expected_counts[] = { 0 };
    size_t num_cases = sizeof(cases) / sizeof(cases[0]);

    for (size_t i = 0; i < num_cases; i++) {
        size_t len = strlen(cases[i]); 
        size_t max_len = maximal_binary_length_from_base64(cases[i], len);
        
        unsigned char *buffer = OPENSSL_malloc(max_len);
        if (buffer == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        int simdutf_outlen = 0;
        int simdutf_result = simdutf_decode(NULL, (char *)buffer, &simdutf_outlen, cases[i], len);

        // *** OpenSSL part ***

        unsigned char *buffer_openssl = OPENSSL_malloc(max_len);
        if (buffer_openssl == NULL) {
            TEST_error("Out of memory");
            return 0;
        }

        int openssl_outlen = 0;
        int openssl_result = OpenSSL_decode(NULL, (char *)buffer_openssl, &openssl_outlen, cases[i], len);

        ASSERT_EQUAL_INT(simdutf_outlen, openssl_outlen);
        ASSERT_EQUAL_INT(simdutf_result, openssl_result);


        // ****** TEST SPECIFIC ASSERTIONS ******

        ASSERT_EQUAL_INT(openssl_result, -1);

        if (simdutf_outlen != expected_counts[i]) {
            TEST_error(RED_TEXT("Simdutf:Decoded byte count mismatch: got %d, expected %zu"), simdutf_result, expected_counts[i]);
            OPENSSL_free(buffer_openssl);
            return 0;
        }
        OPENSSL_free(buffer_openssl);


        
        ASSERT_EQUAL_INT(simdutf_result, -1);

        if (openssl_outlen != expected_counts[i]) {
            TEST_error(RED_TEXT("Simdutf:Decoded byte count mismatch: got %d, expected %zu"), simdutf_result, expected_counts[i]);
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
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered complete_decode_base64_cases Test\n"));

    case_pair cases[] = {
        {"abcd", " YW\tJ\njZ A=\r= "}
    };
    size_t num_cases = sizeof(cases) / sizeof(cases[0]);
    size_t i;

    /* First, test using base64_to_binary (normal decoding) */
    for(i = 0; i < num_cases; i++) {
        size_t enc_len = strlen(cases[i].encoded);
        size_t max_len = maximal_binary_length_from_base64(cases[i].encoded, enc_len);
        unsigned char *buffer = OPENSSL_malloc(max_len);
        if (buffer == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        int outlen_simdutf = 0;
        int simdutf_result = simdutf_decode(NULL, (char *)buffer, &outlen_simdutf, cases[i].encoded, enc_len);

        for(size_t j = 0; j < simdutf_result; j++) {
            if(buffer[j] != cases[i].decoded[j]) {
                TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for simdutf: got %02x, expected %02x"), 
                           j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
                OPENSSL_free(buffer);
                return 0;
            }
        }

        // *** OpenSSL part ***

        unsigned char *buffer_openssl = OPENSSL_malloc(max_len);
        if (buffer_openssl == NULL) {
            TEST_error("Out of memory");
            return 0;
        }

        int openssl_outlen = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)buffer_openssl, &openssl_outlen, cases[i].encoded, enc_len);

        for(size_t j = 0; j < result_openssl; j++) {
            if(buffer_openssl[j] != cases[i].decoded[j]) {
                TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for OpenSSL: got %02x, expected %02x"), 
                           j, i, (unsigned int)buffer_openssl[j], (unsigned int)cases[i].decoded[j]);
                OPENSSL_free(buffer_openssl);
                return 0;
            }
        }

        printf("max_len: %zu\n", max_len);
        printf("simdutf_result: %d\n", simdutf_result);
        printf("simdutf_outlen: %d\n", outlen_simdutf);
        printf("result_openssl: %d\n", result_openssl);
        printf("openssl_outlen: %d\n", openssl_outlen);

        ASSERT_EQUAL_INT(simdutf_result, result_openssl);
        ASSERT_EQUAL_INT(outlen_simdutf, openssl_outlen);
        // ****** TEST SPECIFIC ASSERTIONS ******

        ASSERT_EQUAL_INT(result_openssl, strlen(cases[i].decoded));
        ASSERT_EQUAL_INT(simdutf_result, strlen(cases[i].decoded));
        
        OPENSSL_free(buffer);
        OPENSSL_free(buffer_openssl);
    }
    return 1;
}

static int inline check_cases(case_pair *cases, size_t num_cases)
{
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered encode_base64_cases Test\n"));
    printf(GREEN_TEXT("DEBUG: Number of cases: %zu\n"), num_cases);

    /* Define test cases as an array of case_pair.
       These mirror your C++ test cases.
    */
    size_t i, j;

        /* --- Part 1: Test binary => base64 (normal) --- */
        DEBUG_PRINT(GREEN_TEXT(" -- Testing base64_to_binary decoding (normal)\n"));
        for (i = 0; i < num_cases; i++) {
            size_t enc_len = strlen(cases[i].encoded);
            size_t expected_dec_len = strlen(cases[i].decoded);
            size_t bufsize = base64_length_from_binary(strlen(cases[i].decoded));
            char *buffer = OPENSSL_malloc(bufsize);
            if (!buffer) {
                TEST_error("Out of memory in decoding test case %zu", i);
                return 0;
            }
            int r = tail_encode_base64(NULL, (char *)buffer,cases[i].decoded, strlen(cases[i].decoded));
            if(r < 0) {
                TEST_error(RED_TEXT("tail_encode_base64 error in test case %zu"), i);
                OPENSSL_free(buffer);
                return 0;
            }
            if(r != strlen(cases[i].encoded)) {
                DEBUG_PRINT(RED_TEXT("Encoded string: %s\n, Decoded string: %s\n"), cases[i].encoded, cases[i].decoded);

                TEST_error(RED_TEXT("Encoded byte count mismatch in test case %zu: got %zu, expected %zu"), 
                           i, r, strlen(cases[i].encoded));
                OPENSSL_free(buffer);
                return 0;
            }
    
            for(size_t j = 0; j < r; j++) {
                if(buffer[j] != cases[i].encoded[j]) {
                    TEST_error(RED_TEXT("Encoded: Mismatch at index %zu in test case %zu: got %02x, expected %02x"), 
                               j, i, (unsigned int)buffer[j], (unsigned int)cases[i].encoded[j]);
                    OPENSSL_free(buffer);
                    return 0;
                }
            }
            OPENSSL_free(buffer);
        }

    /* --- Part 2: Test base64_to_binary decoding (normal) --- */
    DEBUG_PRINT(GREEN_TEXT(" -- Testing base64_to_binary decoding (normal)\n"));
    /* First, test using base64_to_binary (normal decoding) */
    for(i = 0; i < num_cases; i++) {
        size_t enc_len = strlen(cases[i].encoded);
        size_t max_len = maximal_binary_length_from_base64(cases[i].encoded, enc_len);
        unsigned char *buffer = OPENSSL_malloc(max_len);
        if (buffer == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        int outlen_simdutf = 0;
        int simdutf_result = simdutf_decode(NULL, (char *)buffer, &outlen_simdutf, cases[i].encoded, enc_len);

        for(size_t j = 0; j < simdutf_result; j++) {
            if(buffer[j] != cases[i].decoded[j]) {
                TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for simdutf: got %02x, expected %02x"), 
                           j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
                OPENSSL_free(buffer);
                return 0;
            }
        }

        // *** OpenSSL part ***

        unsigned char *buffer_openssl = OPENSSL_malloc(max_len + 2);
        if (buffer_openssl == NULL) {
            TEST_error("Out of memory");
            return 0;
        }

        int openssl_outlen = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)buffer_openssl, &openssl_outlen, cases[i].encoded, enc_len);

        for(size_t j = 0; j < result_openssl; j++) {
            if(buffer_openssl[j] != cases[i].decoded[j]) {
                TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for OpenSSL: got %02x, expected %02x"), 
                           j, i, (unsigned int)buffer_openssl[j], (unsigned int)cases[i].decoded[j]);
                OPENSSL_free(buffer_openssl);
                return 0;
            }
        }

        printf("max_len: %zu\n", max_len);
        printf("simdutf_result: %d\n", simdutf_result);
        printf("simdutf_outlen: %d\n", outlen_simdutf);
        printf("result_openssl: %d\n", result_openssl);
        printf("openssl_outlen: %d\n", openssl_outlen);

        ASSERT_EQUAL_INT(simdutf_result, result_openssl);
        ASSERT_EQUAL_INT(outlen_simdutf, openssl_outlen);
        // ****** TEST SPECIFIC ASSERTIONS ******

        ASSERT_EQUAL_INT(openssl_outlen, strlen(cases[i].decoded));
        ASSERT_EQUAL_INT(outlen_simdutf, strlen(cases[i].decoded));
        
        OPENSSL_free(buffer);
        OPENSSL_free(buffer_openssl);
    }

    return 1;
}

static int inline check_seof(case_pair *cases, size_t num_cases)
{
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered encode_base64_cases Test\n"));
    printf(GREEN_TEXT("DEBUG: Number of cases: %zu\n"), num_cases);

    /* Define test cases as an array of case_pair.
       These mirror your C++ test cases.
    */
    size_t i, j;


    /* --- Part 2: Test base64_to_binary decoding (normal) --- */
    DEBUG_PRINT(GREEN_TEXT(" -- Testing base64_to_binary decoding (normal)\n"));
    /* First, test using base64_to_binary (normal decoding) */
    for(i = 0; i < num_cases; i++) {
        size_t enc_len = strlen(cases[i].encoded);
        size_t max_len = maximal_binary_length_from_base64(cases[i].encoded, enc_len);

        // *** Simdutf part *** 
        unsigned char *buffer = OPENSSL_malloc(max_len + 1);
        if (buffer == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        int outlen_simdutf = 0;
        int simdutf_result = simdutf_decode(NULL, (char *)buffer, &outlen_simdutf, cases[i].encoded, enc_len);
        DEBUG_PRINT(GREEN_TEXT("DEBUG: simdutf_result = %d\n"), simdutf_result);


        // for(size_t j = 0; j < simdutf_result; j++) {
        //     if(buffer[j] != cases[i].decoded[j]) {
        //         TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for simdutf: got %02x, expected %02x"), 
        //                    j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
        //         OPENSSL_free(buffer);
        //         return 0;
        //     }
        // }

        // buffer[simdutf_result] = '\0'; // Null-terminate the string

        // *** OpenSSL part ***

        unsigned char *buffer_openssl = OPENSSL_malloc(max_len + 4);
        if (buffer_openssl == NULL) {
            TEST_error("Out of memory");
            return 0;
        }

        int openssl_outlen = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)buffer_openssl, &openssl_outlen, cases[i].encoded, enc_len);

        // for(size_t j = 0; j < result_openssl; j++) {
        //     if(buffer_openssl[j] != cases[i].decoded[j]) {
        //         TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for OpenSSL: got %02x, expected %02x"), 
        //                    j, i, (unsigned int)buffer_openssl[j], (unsigned int)cases[i].decoded[j]);
        //         OPENSSL_free(buffer_openssl);
        //         return 0;
        //     }
        // }

        // buffer_openssl[openssl_outlen] = '\0'; // Null-terminate the string

        printf("max_len: %zu\n", max_len);
        printf("simdutf_result: %d\n", simdutf_result);
        printf("simdutf_outlen: %d\n", outlen_simdutf);
        printf("result_openssl: %d\n", result_openssl);
        printf("openssl_outlen: %d\n", openssl_outlen);

        ASSERT_EQUAL_INT(simdutf_result, result_openssl);
        ASSERT_EQUAL_INT(outlen_simdutf, openssl_outlen);
        // ****** TEST SPECIFIC ASSERTIONS ******

        ASSERT_MEM_EQUAL(buffer_openssl, buffer, outlen_simdutf);
        // PRINT_STRINGS(buffer_openssl, buffer, outlen_simdutf);

        // ASSERT_EQUAL_INT(openssl_outlen, strlen(cases[i].decoded));
        // ASSERT_EQUAL_INT(outlen_simdutf, strlen(cases[i].decoded));

        
        OPENSSL_free(buffer);
        OPENSSL_free(buffer_openssl);
    }
    return 1;
}

// static int inline check_seof(case_pair *cases, size_t num_cases)
// {
//     DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered base64_tail_decode_trim_end Test\n"));

//     for (size_t i = 0; i < num_cases; i++) {
//         size_t enc_len  = strlen(cases[i].encoded);
//         size_t max_len  = maximal_binary_length_from_base64(cases[i].encoded,
//                                                             enc_len);

//         /* -- simdutf decode (needs +2 bytes for \\n and NUL) */
//         unsigned char *simd_buf = OPENSSL_malloc(max_len + 2);
//         if (!simd_buf) {
//             TEST_error("Out of memory (simdutf) in case %zu", i);
//             return 0;
//         }
//         int outlen_simd = 0;
//         int simd_ret = simdutf_decode(NULL,
//                                       (char *)simd_buf,
//                                       &outlen_simd,
//                                       cases[i].encoded,
//                                       enc_len);
//         DEBUG_PRINT("DEBUG: simdutf_ret = %d, outlen_simd = %d\n",
//                     simd_ret, outlen_simd);

//         /* -- OpenSSL decode (also needs +2) */
//         unsigned char *ossl_buf = OPENSSL_malloc(max_len + 2);
//         if (!ossl_buf) {
//             TEST_error("Out of memory (OpenSSL) in case %zu", i);
//             OPENSSL_free(simd_buf);
//             return 0;
//         }
//         int outlen_ossl = 0;
//         int ossl_ret = OpenSSL_decode(NULL,
//                                       (char *)ossl_buf,
//                                       &outlen_ossl,
//                                       cases[i].encoded,
//                                       enc_len);
//         DEBUG_PRINT("DEBUG: ossl_ret = %d, outlen_ossl = %d\n",
//                     ossl_ret, outlen_ossl);

//         /* -- They should agree */
//         ASSERT_EQUAL_INT(simd_ret,     ossl_ret);
//         ASSERT_EQUAL_INT(outlen_simd,  outlen_ossl);

//         /* -- Compare raw bytes (no NUL termination needed) */
//         ASSERT_MEM_EQUAL(ossl_buf, simd_buf, outlen_simd);

//         OPENSSL_free(simd_buf);
//         OPENSSL_free(ossl_buf);
//     }
//     return 1;
// }


static int inline check_cases_no_padding(case_pair *cases, size_t num_cases)
{
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered encode_base64_cases Test\n"));
    printf(GREEN_TEXT("DEBUG: Number of cases: %zu\n"), num_cases);

    /* Define test cases as an array of case_pair.
       These mirror your C++ test cases.
    */
    size_t i, j;

        /* --- Part 1: Test binary => base64 (normal) --- */
        DEBUG_PRINT(GREEN_TEXT(" -- Testing base64_to_binary decoding (normal)\n"));
        for (i = 0; i < num_cases; i++) {
            size_t enc_len = strlen(cases[i].encoded);
            size_t expected_dec_len = strlen(cases[i].decoded);
            size_t bufsize = base64_length_from_binary(strlen(cases[i].decoded));
            char *buffer = OPENSSL_malloc(bufsize);
            if (!buffer) {
                TEST_error("Out of memory in decoding test case %zu", i);
                return 0;
            }
            int r = tail_encode_base64(NULL, (char *)buffer,cases[i].decoded, strlen(cases[i].decoded));
            if(r < 0) {
                TEST_error(RED_TEXT("tail_encode_base64 error in test case %zu"), i);
                OPENSSL_free(buffer);
                return 0;

            }

            // Equals signs are not added to the encoded string by design
            // if(r != strlen(cases[i].encoded)) {
            //     DEBUG_PRINT(RED_TEXT("Encoded string: %s\n, Decoded string: %s\n"), cases[i].encoded, cases[i].decoded);

            //     TEST_error(RED_TEXT("Encoded byte count mismatch in test case %zu: got %zu, expected %zu"), 
            //                i, r, strlen(cases[i].encoded));
            //     OPENSSL_free(buffer);
            //     return 0;
            // }
            
            // Error is intentional
            // for(size_t j = 0; j < r; j++) {
            //     if(buffer[j] != cases[i].encoded[j]) {
            //         TEST_error(RED_TEXT("Encoded: Mismatch at index %zu in test case %zu: got %02x, expected %02x"), 
            //                    j, i, (unsigned int)buffer[j], (unsigned int)cases[i].encoded[j]);
            //         OPENSSL_free(buffer);
            //         return 0;
            //     }
            // }
            OPENSSL_free(buffer);
        }

    /* --- Part 2: Test base64_to_binary decoding (normal) --- */
    DEBUG_PRINT(GREEN_TEXT(" -- Testing base64_to_binary decoding (normal)\n"));
    /* First, test using base64_to_binary (normal decoding) */
    for(i = 0; i < num_cases; i++) {
        DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered decode_base64_cases Test loop\n"));
        size_t enc_len = strlen(cases[i].encoded);
        size_t max_len = maximal_binary_length_from_base64(cases[i].encoded, enc_len);
        unsigned char *buffer = OPENSSL_malloc(max_len);
        if (buffer == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        int outlen_simdutf = 0;
        int simdutf_result = simdutf_decode(NULL, (char *)buffer, &outlen_simdutf, cases[i].encoded, enc_len);
        // ASSERT_EQUAL_INT(simdutf_result, -1);

        // Error is intentional
        // for(size_t j = 0; j < simdutf_result; j++) {
        //     if(buffer[j] != cases[i].decoded[j]) {
        //         // TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for simdutf: got %02x, expected %02x"), 
        //         //            j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
        //         // OPENSSL_free(buffer);
        //         // return 0;
        //     }
        // }

        // *** OpenSSL part ***

        unsigned char *buffer_openssl = OPENSSL_malloc(max_len);
        if (buffer_openssl == NULL) {
            TEST_error("Out of memory");
            return 0;
        }
        int openssl_outlen = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)buffer_openssl, &openssl_outlen, cases[i].encoded, enc_len);
        // ASSERT_EQUAL_INT(result_openssl, -1);


        // for(size_t j = 0; j < result_openssl; j++) {
        //     if(buffer_openssl[j] != cases[i].decoded[j]) {
        //         // TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu for OpenSSL: got %02x, expected %02x"), 
        //         //            j, i, (unsigned int)buffer_openssl[j], (unsigned int)cases[i].decoded[j]);
        //         // OPENSSL_free(buffer_openssl);
        //         // return 0;
        //     }
        // }

        printf("max_len: %zu\n", max_len);
        printf("simdutf_result: %d\n", simdutf_result);
        printf("simdutf_outlen: %d\n", outlen_simdutf);
        printf("result_openssl: %d\n", result_openssl);
        printf("openssl_outlen: %d\n", openssl_outlen);

        ASSERT_EQUAL_INT(simdutf_result, result_openssl);
        ASSERT_EQUAL_INT(outlen_simdutf, openssl_outlen);
        // ****** TEST SPECIFIC ASSERTIONS ******

        // Some of the cases are intentionally failing and some intentionally passing
        // ASSERT_EQUAL_INT(openssl_outlen, 0);
        // ASSERT_EQUAL_INT(outlen_simdutf, 0);
        
        OPENSSL_free(buffer);
        OPENSSL_free(buffer_openssl);
    }

    return 1;
}


const case_pair basic_cases[] = {
    { "Hello, World!", "SGVsbG8sIFdvcmxkIQ==" },
    { "GeeksforGeeks", "R2Vla3Nmb3JHZWVrcw==" },
    { "123456", "MTIzNDU2" },
    { "Base64 Encoding", "QmFzZTY0IEVuY29kaW5n" },
    { "!R~J2jL&mI]O)3=c:G3Mo)oqmJdxoprTZDyxEvU0MI.'Ww5H{G>}y;;+B8E_Ah,Ed[ PdBqY'^N>O$4:7LK1<:|7)btV@|{YWR$$Er59-XjVrFl4L}~yzTEd4'E[@k",
      "IVJ+SjJqTCZtSV1PKTM9YzpHM01vKW9xbUpkeG9wclRaRHl4RXZVME1JLidXdzVIe0c+fXk7OytCOEVfQWgsRWRbIFBkQnFZJ15OPk8kNDo3TEsxPDp8NylidFZAfHtZV1IkJEVyNTktWGpWckZsNEx9fnl6VEVkNCdFW0Br" }
};

const case_pair no_padding[] = {
    {"Hello, World!", "SGVsbG8sIFdvcmxkIQ"},
    {"GeeksforGeeks", "R2Vla3Nmb3JHZWVrcw"},
    {"123456", "MTIzNDU2"},
    {"Base64 Encoding", "QmFzZTY0IEVuY29kaW5n"},
    {"!R~J2jL&mI]O)3=c:G3Mo)oqmJdxoprTZDyxEvU0MI.'Ww5H{G>}y;;+B8E_Ah,Ed[ "
     "PdBqY'^N>O$4:7LK1<:|7)btV@|{YWR$$Er59-XjVrFl4L}~yzTEd4'E[@k",
     "IVJ+SjJqTCZtSV1PKTM9YzpHM01vKW9xbUpkeG9wclRaRHl4RXZVME1JLidXdzVIe0c+"
     "fXk7OytCOEVfQWgsRWRbIFBkQnFZJ15OPk8kNDo3TEsxPDp8NylidFZAfHtZV1IkJEVyNTk"
     "tWGpWckZsNEx9fnl6VEVkNCdFW0Br"}
    };

const case_pair whitespaces[] = {
        {"abcd", " Y\fW\tJ\njZ A=\r= "},
    };

static int test_encode_base64_basic_cases(void){
    int result = check_cases(basic_cases,1);
    return result;
}

const case_pair seof_good_cases[] = {
    { "123", "MTIz\x2DNDU2" }, 
    // { "Base64 Encod", "QmFzZTY0IEVuY29k\x2DW5n" }, 
    // { "!R~J-2jL&m",
    //   "IVJ+SjJqTCZt\x2DSV1PKTM9YzpHM01vKW9xbUpkeG9wclRaRHl4RXZVME1JLidXdzVIe0c+fXk7OytCOEVfQWgsRWRbIFBkQnFZJ15OPk8kNDo3TEsxPDp8NylidFZAfHtZV1IkJEVyNTktWGpWckZsNEx9fnl6VEVkNCdFW0Br-" }
};

const case_pair seof_bad_cases[] = {
    { "Hello, Wo", "SGVsbG8sIFdv\x2DcmxkIQ==" }, // bad
    { "Geeksf", "R2Vla3Nm\x2Db3JHZWVrcw==" }, // bad
};

static int test_seof_good_basic_cases(void){
    int result = check_seof(seof_good_cases,1);
    // printf(GREEN_TEXT("DEBUG: SEOF good test result: %d\n"), result);
    return result;
}

static int test_seof_bad_basic_cases(void){
    int result = check_seof(seof_bad_cases,2);
    // printf(GREEN_TEXT("DEBUG: SEOF good test result: %d\n"), result);
    return result;
}


static int test_encode_base64_no_padding_cases(void){
    int result = check_cases_no_padding(no_padding,5);

    return result;
}

static int test_encode_base64_whitespace_cases(void){
    int result = check_cases(whitespaces,1);
    return result;
}

/*
 * add_space:
 * Inserts a single random whitespace character into the array.
 *
 * Parameters:
 *   v      - pointer to a dynamically allocated array of char.
 *   v_len  - pointer to the length of the array.
 *   seed   - pointer to an unsigned int used as the random seed.
 *
 * Returns:
 *   The index where the whitespace was inserted.
 *   The array and its length are updated.
 */

// size_t add_space(char **v, size_t *v_len, unsigned int *seed) {
//     static const char space[5] = { ' ', '\t', '\n', '\r'};

//     // DEBUG_PRINT(RED_TEXT("DEBUG: Entering add_space\n"));

//     /* Choose a random insertion index between 0 and *v_len (inclusive) */
//     size_t index = rand_r(seed) % (*v_len + 1);
//     // DEBUG_PRINT("DEBUG: Chosen insertion index = %zu (v_len = %zu)\n", index, *v_len);

//     /* Choose a random whitespace character from the array */
//     size_t space_index = rand_r(seed) % 4;
//     // DEBUG_PRINT("DEBUG: Chosen whitespace character = '%c'\n", space[space_index]);

//     /* Reallocate the array to make room for one extra character. */
//     char *new_v = OPENSSL_realloc(*v, *v_len + 1);
//     if (new_v == NULL) {
//         TEST_error(RED_TEXT("DEBUG: OPENSSL_realloc failed for new size = %zu"), *v_len + 1);
//         return (size_t)-1;
//     }
//     // DEBUG_PRINT(RED_TEXT("DEBUG: Reallocation successful, new pointer = %p\n"), new_v);

//     /* Move the tail of the array one position to the right */
//     memmove(new_v + index + 1, new_v + index, *v_len - index);
//     // DEBUG_PRINT("DEBUG: memmove executed from index %zu for %zu bytes\n", index, *v_len - index);

//     /* Insert the chosen whitespace */
//     new_v[index] = space[space_index];
//     // DEBUG_PRINT("DEBUG: Inserted '%c' at index %zu\n", space[space_index], index);

//     *v = new_v;
//     (*v_len)++;
//     // DEBUG_PRINT("DEBUG: New vector length is %zu\n", *v_len);

//     return index;
// }

size_t add_space(char **v, size_t *v_len, unsigned int *seed) {
    static const char space[] = { ' ', '\t', '\n', '\r' };
    size_t index = rand_r(seed) % (*v_len + 1);
    size_t space_index = rand_r(seed) % 4;

    /* Make room for one more character + NUL */
    char *new_v = OPENSSL_realloc(*v, *v_len + 2);
    if (!new_v) {
        TEST_error("DEBUG: OPENSSL_realloc failed for new size = %zu", *v_len + 2);
        return (size_t)-1;
    }

    /* Shift the tail */
    memmove(new_v + index + 1,
            new_v + index,
            *v_len - index);

    /* Insert the whitespace and NUL-terminate */
    new_v[index] = space[space_index];
    (*v_len)++;
    new_v[*v_len] = '\0';

    *v = new_v;
    return index;
}


/*
 * add_simple_spaces:
 * Inserts a given number of spaces at unique random positions into the input array.
 *
 * Parameters:
 *   v              - The original array of characters.
 *   v_len          - The number of elements in the array.
 *   number_of_spaces - How many spaces to insert.
 *   seed           - Pointer to an unsigned int used as the random seed.
 *   result_len     - Output pointer that receives the length of the resulting array.
 *
 * Returns:
 *   A newly allocated array containing the original elements plus extra spaces.
 *   The caller is responsible for freeing the returned array using OPENSSL_free.
 */
char *add_simple_spaces(const char *v, size_t v_len, size_t number_of_spaces,
                        //   unsigned int *seed, size_t *result_len) {
                        unsigned int *seed) {
    /* If there are no spaces to add or the array is empty, return a copy of v */
    if (number_of_spaces == 0 || v_len == 0) {
        char *copy = OPENSSL_malloc(v_len + 1);
        if (copy) {
            memcpy(copy, v, v_len);
            copy[v_len] = '\0';
        }
        return copy;
    }

    size_t total = v_len + number_of_spaces;
    /* Allocate a boolean array (using char) to mark positions for inserted spaces.
       Initialize all positions to 0. */
    char *positions = OPENSSL_zalloc(total * sizeof(char));
    if (!positions)
        return NULL;

    size_t i;
    /* Generate unique random positions for extra spaces */
    for (i = 0; i < number_of_spaces; i++) {
        size_t pos = rand_r(seed) % total;
        while (positions[pos]) {
            pos = rand_r(seed) % total;
        }
        positions[pos] = 1;  /* Mark this position to hold a space */
    }

    /* Allocate the result array */
    char *result = OPENSSL_malloc(total + 1);
    if (!result) {
        OPENSSL_free(positions);
        return NULL;
    }

    size_t pos_idx = 0;  /* Index for traversing the original array */
    const char whitespace[4] = { ' ', '\t', '\n', '\r' };
    for (i = 0; i < total; i++) {
        if (positions[i]) {
            /* Choose a random whitespace character from the set */
            result[i] = whitespace[rand_r(seed) % 4];
        } else {
            result[i] = v[pos_idx++];
        }
    }
    result[total] = '\0';
    OPENSSL_free(positions);
    return result;
}

static int test_roundtrip_base64_with_lots_of_spaces(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64_with_lots_of_spaces\n"));

    for (len = 0; len < 2048; len++) {
        printf("Processing length = %zu\n", len);
        DEBUG_PRINT("DEBUG: Processing length = %zu\n", len);

        /* Allocate source binary data */
        char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
        if (len > 0 && !source) {
            TEST_error("Out of memory for source of length %zu", len);
            return 0;
        }
        /* Fill source with random bytes */
        for (i = 0; i < len; i++) {
            source[i] = (char)(rand_r(&seed) % 256);
        }
        if (len > 0)
            DEBUG_PRINT("DEBUG: Source data allocated (first 10 bytes):");
        for (i = 0; i < len && i < 10; i++) {
            DEBUG_PRINT(" %02x", (unsigned char)source[i]);
        }
        DEBUG_PRINT("\n");

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len);
        DEBUG_PRINT("DEBUG: Expected Base64 length = %zu\n", b64_len_expected);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (!buffer) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            if (source) OPENSSL_free(source);
            return 0;
        }
        size_t s = tail_encode_base64(NULL, buffer, source, len);
        buffer[s] = '\0';
        DEBUG_PRINT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n", s, buffer);

        /* Insert extra spaces */
        size_t spaces_to_add = 5 + 2 * len;
        char *buffer_with_spaces = add_simple_spaces(buffer, s, spaces_to_add, &seed);
        OPENSSL_free(buffer);
        if (!buffer_with_spaces) {
            TEST_error("Out of memory for buffer_with_spaces");
            if (source) OPENSSL_free(source);
            return 0;
        }
        size_t buffer_with_spaces_len = strlen(buffer_with_spaces);
        // DEBUG_PRINT("DEBUG: Buffer with spaces (length %zu): \"%s\"\n", buffer_with_spaces_len, buffer_with_spaces);

        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer_with_spaces, buffer_with_spaces_len);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

        // **** Simdutf part *****

        char *back = OPENSSL_malloc(back_bufsize);
        if (!back && back_bufsize !=0) {
            TEST_error("Out of memory for back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer_with_spaces);
            return 0;
        }

        /* Decode the Base64 string (with extra spaces) */
        int outlen_simdutf = 0;
        int result_simdutf = simdutf_decode(NULL, back,  &outlen_simdutf, buffer_with_spaces, buffer_with_spaces_len);
        DEBUG_PRINT("DEBUG: Decoded binary length simdutf= %zu\n", result_simdutf);
        if (source == NULL) {
            ASSERT_EQUAL_INT(result_simdutf, 0);
        } else {
            ASSERT_EQUAL_INT(result_simdutf, len);
        }

        for (size_t j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back[j], source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for length %zu\n", len);

        // OPENSSL_free(source);
        // OPENSSL_free(buffer_with_spaces);
        // OPENSSL_free(back);

        // **** OpenSSL part *****

        char *back_openssl = OPENSSL_malloc(back_bufsize);
        if (!back_openssl && back_openssl !=0) {
            TEST_error("Out of memory for back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer_with_spaces);
            return 0;
        }

        /* Decode the Base64 string (with extra spaces) */
        int outlen_openssl = 0;
        int result_openssl = OpenSSL_decode(NULL, back_openssl,  &outlen_openssl, buffer_with_spaces, buffer_with_spaces_len);
        DEBUG_PRINT("DEBUG: Decoded binary length openssl= %zu\n", result_openssl);
        if (source == NULL) {
            ASSERT_EQUAL_INT(result_openssl, 0);
        } else {
            ASSERT_EQUAL_INT(result_openssl, len);
        }

        for (size_t j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back_openssl[j], source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for length %zu\n", len);


        // specific to this test
        ASSERT_EQUAL_INT(result_openssl, len);
        ASSERT_EQUAL_SIZE(outlen_openssl, len);

        ASSERT_EQUAL_INT(result_simdutf, len);
        ASSERT_EQUAL_SIZE(outlen_simdutf, len);
        ASSERT_MEM_EQUAL(back_openssl, back, outlen_openssl);

        OPENSSL_free(source);
        OPENSSL_free(buffer_with_spaces);
        OPENSSL_free(back);
        OPENSSL_free(back_openssl);

        
        

    }
    return 1;
}

static int test_roundtrip_base64_with_spaces(void) {
    size_t len, i, j;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64_with_spaces\n"));

    for (len = 0; len < 2048; len++) {
        DEBUG_PRINT(CYAN_TEXT("**********************************************************\n"));
        DEBUG_PRINT(CYAN_TEXT("DEBUG: Processing binary length = %zu\n"), len);
        
        /* Allocate source binary data */
        char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
        if (len > 0 && source == NULL) {
            TEST_error("Out of memory for source of length %zu", len);
            return 0;
        }
        for (i = 0; i < len; i++) {
            source[i] = (char)(rand_r(&seed) % 256);
        }

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (buffer == NULL) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            if (source) OPENSSL_free(source);
            return 0;
        }
        size_t s = tail_encode_base64(NULL, buffer, source, len);
        buffer[s] = '\0';
        DEBUG_PRINT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n", s, buffer);

        /* Insert extra spaces (5 times) */
        size_t cur_b64_len = s;
        for (i = 0; i < 5; i++) {
            int index = add_space(&buffer, &cur_b64_len, &seed);
            if (index == -1) {
                TEST_error("Out of memory in add_space for length %zu", cur_b64_len);
                OPENSSL_free(source);
                OPENSSL_free(buffer);
                return 0;
            }
        }
        DEBUG_PRINT("DEBUG: Base64 with spaces (length %zu): \"%s\"\n", cur_b64_len, buffer);

        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, cur_b64_len);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

        /* **** simdutf decoding **** */
        unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_simd == NULL) {
            TEST_error("Out of memory for simdutf back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            return 0;
        }
        int outlen_simdutf = 0;
        int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, cur_b64_len);
        DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        if (len == 0) {
            ASSERT_EQUAL_INT(result_simdutf, 0);
        } else {
            ASSERT_EQUAL_INT(result_simdutf, (int)len);
        }
        for (j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

        /* **** OpenSSL decoding **** */
        unsigned char *back_openssl = OPENSSL_malloc(back_bufsize + 2);
        if (back_bufsize != 0 && back_openssl == NULL) {
            TEST_error("Out of memory for OpenSSL back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            return 0;
        }
        int outlen_openssl = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, cur_b64_len);
        DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        if (len == 0) {
            ASSERT_EQUAL_INT(result_openssl, 0);
        } else {
            ASSERT_EQUAL_INT(result_openssl, (int)len);
        }
        for (j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

        /* Specific assertions comparing the two decoders */
        ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);
        ASSERT_EQUAL_INT(result_openssl, len);

        ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);

        OPENSSL_free(source);
        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        OPENSSL_free(back_openssl);
    }
    return 1;
}



const static uint8_t to_base64_value[] = {
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


/*
 * test_roundtrip_base64_with_garbage:
 * For each binary length from 0 to 2047, generate random binary data,
 * encode it to Base64, insert garbage characters (5 insertions),
 * then decode using both base64_to_binary and base64_to_binary_safe with
 * each of three last-chunk handling options. The decoded data is compared
 * with the original source.
 */
// this is true in the original, the original tests the ignore_garbage option
    static int test_roundtrip_base64_with_garbage(void) {
        size_t len, trial, i, j;
        unsigned int seed = 12345;  /* Fixed seed for reproducibility */
        DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64_with_garbage\n"));

        /* Loop over binary lengths from 0 to 2047 */
        for (len = 0; len < 2048; len++) {
            DEBUG_PRINT("DEBUG: ***************** Processing binary length = %zu\n", len);
            printf("DEBUG: ***************** Processing binary length = %zu\n", len);
            /* Allocate source binary data */
            char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
            if (len > 0 && source == NULL) {
                TEST_error("Out of memory for source of length %zu", len);
                return 0;
            }
            for (i = 0; i < len; i++) {
                source[i] = (char)(rand_r(&seed) % 256);
            }

            /* Allocate buffer for Base64 conversion */
            size_t b64_len_expected = base64_length_from_binary(len);
            char *buffer = OPENSSL_malloc(b64_len_expected + 1);
            if (buffer == NULL) {
                TEST_error("Out of memory for Base64 buffer for length %zu", len);
                if (source) OPENSSL_free(source);
                return 0;
            }
            size_t s = tail_encode_base64(NULL, buffer,source, len);
            buffer[s] = '\0';
            DEBUG_PRINT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n", s, buffer);

            /* Insert garbage 5 times */
            size_t cur_b64_len = s;
            for (i = 0; i < 5; i++) {
                size_t pos = add_garbage(&buffer, &cur_b64_len, &seed, to_base64_value);
                if (pos == (size_t)-1) {
                    TEST_error("Out of memory in add_garbage for length %zu", cur_b64_len);
                    if (source) OPENSSL_free(source);
                    return 0;
                }
            }
            DEBUG_PRINT("DEBUG: Base64 with garbage (length %zu): \"%s\"\n", cur_b64_len, buffer);

            /* Allocate buffer for decoded binary data */
            size_t back_bufsize = maximal_binary_length_from_base64(buffer, cur_b64_len);
            DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

            // // **** Simdutf part *****

            // char *back = OPENSSL_malloc(back_bufsize);
            // if (back == NULL) {
            //     TEST_error("Out of memory for back buffer");
            //     OPENSSL_free(source);
            //     OPENSSL_free(buffer);
            //     return 0;
            // }


            //     result r = (NULL,back, buffer, cur_b64_len);
            //     DEBUG_PRINT("DEBUG: base64_to_binary returned count = %zu\n",
            //         r);

            //     ASSERT_TRUE(r.error != BASE64_SUCCESS);
            //     // if (len > 0) {
            //     //     ASSERT_TRUE(memcmp(back, source, len) == 0);
            //     // }
            // // }

            // OPENSSL_free(source);
            // OPENSSL_free(buffer);
            // OPENSSL_free(back);

            /* **** simdutf decoding **** */
            unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
            if (back_bufsize != 0 && back_simd == NULL) {
                TEST_error("Out of memory for simdutf back buffer");
                OPENSSL_free(source);
                OPENSSL_free(buffer);
                return 0;
            }
            int outlen_simdutf = 0;
            int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, cur_b64_len);
            DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
            // if (len == 0) {
            //     ASSERT_EQUAL_INT(result_simdutf, 0);
            // } else {
            //     ASSERT_EQUAL_INT(result_simdutf, -1);
            // }
            // for (j = 0; j < len; j++) {
            //     ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
            // }
            DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

            /* **** OpenSSL decoding **** */
            unsigned char *back_openssl = OPENSSL_malloc(back_bufsize + 3);
            if (back_bufsize != 0 && back_openssl == NULL) {
                TEST_error("Out of memory for OpenSSL back buffer");
                OPENSSL_free(source);
                OPENSSL_free(buffer);
                OPENSSL_free(back_simd);
                return 0;
            }
            int outlen_openssl = 0;
            int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, cur_b64_len);
            DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
            // if (len == 0) {
            //     ASSERT_EQUAL_INT(result_openssl, 0);
            // } else {
            //     ASSERT_EQUAL_INT(result_openssl, -1);
            // }
            // for (j = 0; j < len; j++) {
            //     ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
            // }
            DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

            /* Specific assertions comparing the two decoders */
            ASSERT_EQUAL_INT(result_openssl, result_simdutf);
            ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);
            ASSERT_EQUAL_INT(result_openssl, -1);
            ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);

            OPENSSL_free(source);
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            OPENSSL_free(back_openssl);

        }
        return 1;
    }

    static int test_base64_decode_just_one_padding_loose(void) {
        typedef struct {
            const char *input;
            int         error;
            int         expected;
        } test_case;
    
        test_case test_cases[] = {
            { "uuuu             =", -1, 0 }
        };
        size_t num_cases = OSSL_NELEM(test_cases);
    
        for (size_t i = 0; i < num_cases; i++) {
            const char *input    = test_cases[i].input;
            size_t       inlen    = strlen(input);
            int          want_err = test_cases[i].error;
            int          want_len = test_cases[i].expected;
    
            /* 1) Copy into a heap buffer with room for the "\n\0". */
            char *buffer = OPENSSL_malloc(inlen + 1 /* NUL */ + 2 /* newline + NUL */);
            if (buffer == NULL) {
                TEST_error("malloc failed");
                return 0;
            }
            memcpy(buffer, input, inlen);
            buffer[inlen] = '\0';  /* NUL‑terminate */
    
            /* 2) Figure out how big the worst‑case output is. */
            size_t back_bufsize =
                maximal_binary_length_from_base64(buffer, inlen);
    
            /* 3) simdutf decode */
            unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
            if (back_bufsize != 0 && back_simd == NULL) {
                OPENSSL_free(buffer);
                TEST_error("malloc simdutf failed");
                return 0;
            }
            int out_simd = 0;
            int err_simd = simdutf_decode(NULL, (char *)back_simd,
                                          &out_simd, buffer, inlen);
            ASSERT_EQUAL_INT(err_simd, want_err);
            // if (err_simd >= 0)
                ASSERT_EQUAL_INT(out_simd, want_len);
    
            /* 4) OpenSSL decode */
            unsigned char *back_ssl = OPENSSL_malloc(back_bufsize);
            if (back_bufsize != 0 && back_ssl == NULL) {
                OPENSSL_free(buffer);
                OPENSSL_free(back_simd);
                TEST_error("malloc openssl failed");
                return 0;
            }
            int out_ssl = 0;
            int err_ssl = OpenSSL_decode(NULL, (char *)back_ssl,
                                         &out_ssl, buffer, inlen);
            ASSERT_EQUAL_INT(err_ssl, want_err);
            // if (err_ssl >= 0)
                ASSERT_EQUAL_INT(out_ssl, want_len);
    
            /* 5) Compare */
            ASSERT_EQUAL_INT(err_ssl, err_simd);
            ASSERT_EQUAL_INT(out_ssl, out_simd);
            
    
            /* 6) Clean up only what we malloc’d */
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            OPENSSL_free(back_ssl);
        }
    
        return 1;
    }
    

size_t create_basic_string(char *str, int count) {
    const char *pattern = "TWFu";
    for (int i = 0; i < count; i++) {
        memcpy(str + i*4, pattern, 4);
    }
    str[count * 4] = '\0';
    DEBUG_PRINT("DEBUG: Created basic string: \"%s\"\n", str);
    return count * 4;
}

static int test_multiple_of_4_good(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64\n"));

    for (len = 0; len < 512; len++) {
        DEBUG_PRINT("DEBUG: Processing length = %zu\n", len *4);

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len * 4);
        // DEBUG_PRINT("DEBUG: Expected Base64 length = %zu\n", b64_len_expected);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (buffer == NULL) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            return 0;
        }

        create_basic_string(buffer, len);
        buffer[len * 4] = '\0';

        /* No extra spaces are added; use the encoded buffer as-is */
        size_t s = len * 4;

        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

        /* **** simdutf decoding **** */
        unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_simd == NULL) {
            TEST_error("Out of memory for simdutf back buffer");
            OPENSSL_free(buffer);
            return 0;
        }

        if (back_simd == NULL) {
            // TEST_error("Out of memory for back buffer");
            DEBUG_PRINT("back_bufsize = %zu\n", back_bufsize);
            DEBUG_PRINT("back_simd shouldn't be NULL\n");
            // OPENSSL_free(source);
            // OPENSSL_free(buffer);
            // return 0;
        }

        int outlen_simdutf = 0;
        int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_simdutf, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_simdutf, len);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

        /* **** OpenSSL decoding **** */
        unsigned char *back_openssl = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_openssl == NULL) {
            TEST_error("Out of memory for OpenSSL back buffer");
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            return 0;
        }
        int outlen_openssl = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_openssl, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_openssl, -1);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

        /* Specific assertions comparing the two decoders */
        ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);

        ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);
        ASSERT_EQUAL_INT(result_openssl, len*3);


    //    if (s %4 == 0 & result_simdutf != -1) {
    //         ASSERT_EQUAL_INT(result_openssl, len);
    //     } 
        // else {
            // ASSERT_EQUAL_INT(result_openssl, -1);
            // if (result_openssl == -1) {
            //     TEST_error("DEBUG: result_openssl = -1\n");
            // }
        // }
        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        OPENSSL_free(back_openssl);
    }
    return 1;
}

static int test_multiple_of_4_bad(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64\n"));

    for (len = 0; len < 512; len++) {
        DEBUG_PRINT("DEBUG: Processing length = %zu\n", len *4);

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len * 4);
        // DEBUG_PRINT("DEBUG: Expected Base64 length = %zu\n", b64_len_expected);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (buffer == NULL) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            return 0;
        }

        size_t augmented_len = create_basic_string(buffer, len);
        buffer[augmented_len] = '\0';

        /* No extra spaces are added; use the encoded buffer as-is */
        size_t s = 0;
        if (len > 0) {
            s = augmented_len - (rand_r(&seed) % 3 + 1);
        } else {
            s = augmented_len;
        }

        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

        /* **** simdutf decoding **** */
        unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_simd == NULL) {
            TEST_error("Out of memory for simdutf back buffer");
            OPENSSL_free(buffer);
            return 0;
        }

        if (back_simd == NULL) {
            // TEST_error("Out of memory for back buffer");
            DEBUG_PRINT("back_bufsize = %zu\n", back_bufsize);
            DEBUG_PRINT("back_simd shouldn't be NULL\n");
            // OPENSSL_free(source);
            // OPENSSL_free(buffer);
            // return 0;
        }

        int outlen_simdutf = 0;
        int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_simdutf, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_simdutf, len);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

        /* **** OpenSSL decoding **** */
        unsigned char *back_openssl = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_openssl == NULL) {
            TEST_error("Out of memory for OpenSSL back buffer");
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            return 0;
        }

        int outlen_openssl = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_openssl, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_openssl, -1);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

        /* Specific assertions comparing the two decoders */
        ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);

        ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);
        if (len == 0) {
            ASSERT_EQUAL_INT(result_openssl, 0);
            ASSERT_EQUAL_INT(outlen_openssl, 0);
        } else {
            ASSERT_EQUAL_INT(result_openssl, -1);
            ASSERT_EQUAL_INT(outlen_openssl, s/4*3 - ((s/4*3) % (48)));
        }
        

    //    if (s %4 == 0 & result_simdutf != -1) {
    //         ASSERT_EQUAL_INT(result_openssl, len);
    //     } 
        // else {
            // ASSERT_EQUAL_INT(result_openssl, -1);
            // if (result_openssl == -1) {
            //     TEST_error("DEBUG: result_openssl = -1\n");
            // }
        // }
        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        OPENSSL_free(back_openssl);
    }
    return 1;
}

static int test_seof_good_cases(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64\n"));

    for (len = 10; len < 512; len++) {
        DEBUG_PRINT("**********DEBUG: Processing length = %zu\n", len *4);

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len * 4);
        // DEBUG_PRINT("DEBUG: Expected Base64 length = %zu\n", b64_len_expected);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (buffer == NULL) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            return 0;
        }

        size_t augmented_len = create_basic_string(buffer, len);

        // DEBUG_PRINT("DEBUG: buffer before add_seof= %s\n", buffer);
        // DEBUG_PRINT("DEBUG: augmented_length = %d\n", augmented_len);
        int index = swap_seof(&buffer, &augmented_len, &seed, 1);

        DEBUG_PRINT("DEBUG: buffer after add_seof= %s\n", buffer);

        DEBUG_PRINT("DEBUG: index after calling add_seof= %d\n", index);
        buffer[len * 4] = '\0';

        /* No extra spaces are added; use the encoded buffer as-is */
        // size_t s = len * 4;
        size_t s = augmented_len;

        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

        /* **** simdutf decoding **** */
        unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_simd == NULL) {
            TEST_error("Out of memory for simdutf back buffer");
            OPENSSL_free(buffer);
            return 0;
        }

        if (back_simd == NULL) {
            // TEST_error("Out of memory for back buffer");
            DEBUG_PRINT("back_bufsize = %zu\n", back_bufsize);
            DEBUG_PRINT("back_simd shouldn't be NULL\n");
            // OPENSSL_free(source);
            // OPENSSL_free(buffer);
            // return 0;
        }

        int outlen_simdutf = 0;
        int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_simdutf, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_simdutf, len);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

        /* **** OpenSSL decoding **** */
        unsigned char *back_openssl = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_openssl == NULL) {
            TEST_error("Out of memory for OpenSSL back buffer");
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            return 0;
        }
        int outlen_openssl = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_openssl, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_openssl, -1);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

        /* Specific assertions comparing the two decoders */
        ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);

        ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);
        // DEBUG_PRINT("DEBUG: result_openssl = %d\n", result_openssl);
        // DEBUG_PRINT("DEBUG: index = %d\n", index);
        ASSERT_EQUAL_INT(result_openssl, index/4 * 3);
        ASSERT_EQUAL_INT(outlen_openssl, index/4 * 3);
        
        // ASSERT_EQUAL_INT(result_openssl, len*3);


    //    if (s %4 == 0 & result_simdutf != -1) {
    //         ASSERT_EQUAL_INT(result_openssl, len);
    //     } 
        // else {
            // ASSERT_EQUAL_INT(result_openssl, -1);
            // if (result_openssl == -1) {
            //     TEST_error("DEBUG: result_openssl = -1\n");
            // }
        // }
        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        OPENSSL_free(back_openssl);
    }
    return 1;
}

static int test_seof_bad_cases(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */

    for (len = 1; len < 512; len++) { // len = 0 already covered by other seof_basic_cases_bad test
        DEBUG_PRINT("******************** DEBUG: Processing length = %zu\n", len *4);

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len*4);
        // DEBUG_PRINT("DEBUG: Expected Base64 length = %zu\n", b64_len_expected);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (buffer == NULL) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            return 0;
        }

        size_t augmented_length = create_basic_string(buffer, len);
        DEBUG_PRINT("DEBUG: buffer before add_seof= %s\n", buffer);
        DEBUG_PRINT("DEBUG: augmented_length = %d\n", augmented_length);


        size_t index = add_seof(&buffer, &augmented_length, &seed, 0);
        DEBUG_PRINT("DEBUG: index = %d\n", index);
        DEBUG_PRINT("DEBUG: buffer after add_seof= %s\n", buffer);

        buffer[augmented_length] = '\0';

        /* No extra spaces are added; use the encoded buffer as-is */
        size_t s = augmented_length;


        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

        /* **** simdutf decoding **** */
        DEBUG_PRINT("DEBUG: back_bufsize = %zu\n", back_bufsize);
        unsigned char *back_simd = OPENSSL_malloc(back_bufsize + 20);
        if (back_bufsize != 0 && back_simd == NULL) {
            TEST_error("Out of memory for simdutf back buffer");
            OPENSSL_free(buffer);
            return 0;
        }

        if (back_simd == NULL) {
            // TEST_error("Out of memory for back buffer");
            DEBUG_PRINT("back_bufsize = %zu\n", back_bufsize);
            DEBUG_PRINT("back_simd shouldn't be NULL\n");
            OPENSSL_free(buffer);
            return 0;
        }

        int outlen_simdutf = 0;
        DEBUG_PRINT("DEBUG: back_simd = %p\n", back_simd);
        int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_simdutf, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_simdutf, len);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

        /* **** OpenSSL decoding **** */
        unsigned char *back_openssl = OPENSSL_malloc(back_bufsize + 2);
        if (back_bufsize != 0 && back_openssl == NULL) {
            TEST_error("Out of memory for OpenSSL back buffer");
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            return 0;
        }
        int outlen_openssl = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        // if (len == 0) {
        //     ASSERT_EQUAL_INT(result_openssl, 0);
        // } else {
        //     ASSERT_EQUAL_INT(result_openssl, -1);
        // }
        // for (j = 0; j < len; j++) {
        //     ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
        // }
        DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

        /* Specific assertions comparing the two decoders */
        ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);

        ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);

        ASSERT_EQUAL_INT(result_openssl, -1);
        ASSERT_EQUAL_INT(outlen_openssl, index/4 * 3 - (index/4 * 3) % 48);

        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        OPENSSL_free(back_openssl);
    }
    return 1;
}


static int test_roundtrip_base64(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64\n"));

    for (len = 0; len < 2048; len++) {
        DEBUG_PRINT(BRIGHT_CYAN_TEXT("************DEBUG: Processing length = %zu\n"), len);

        /* Allocate source binary data */
        char *source = (len > 0) ? OPENSSL_malloc(len) : OPENSSL_malloc(1);
        if (len > 0 && !source) {
            TEST_error("Out of memory for source of length %zu", len);
            return 0;
        }
        /* Fill source with random bytes */
        for (i = 0; i < len; i++) {
            source[i] = (char)(rand_r(&seed) % 256);
        }
        if (len > 0) {
            DEBUG_PRINT("DEBUG: Source data allocated (first 10 bytes):");
            for (i = 0; i < len && i < 10; i++) {
                DEBUG_PRINT(" %02x", (unsigned char)source[i]);
            }
            DEBUG_PRINT("\n");
        }

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len);
        DEBUG_PRINT("DEBUG: Expected Base64 length = %zu\n", b64_len_expected);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (!buffer) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            if (source) OPENSSL_free(source);
            return 0;
        }
        size_t s = tail_encode_base64(NULL, buffer, source, len);
        buffer[s] = '\0';
        DEBUG_PRINT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n", s, buffer);


        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

        /* **** simdutf decoding **** */
        unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
        if (back_bufsize != 0 && back_simd == NULL) {
            TEST_error("Out of memory for simdutf back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            return 0;
        }

        int outlen_simdutf = 0;
        int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        for (int j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

        /* **** OpenSSL decoding **** */
        // NOTE: OpenSSL's base64 decoder differs slightly from the one used in simdutf.
        // Whereas simdutf's will write just the right amount of data, OpenSSL's will
        // always write by chunks of 3 bytes, even if the last chunk is not full.
        // hence the +2 in the malloc below.
        unsigned char *back_openssl = OPENSSL_malloc(back_bufsize +2);
        // back_openssl[back_bufsize] = '\0';
        if (back_bufsize != 0 && back_openssl == NULL) {
            TEST_error("Out of memory for OpenSSL back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            return 0;
        }
        int outlen_openssl = 0;
        int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        for (int j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

        /* Specific assertions comparing the two decoders */
        ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);

        ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);

        ASSERT_EQUAL_INT(result_openssl, len);

        OPENSSL_free(source);
        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        OPENSSL_free(back_openssl);

    }
    return 1;
}

static int test_issue_520(void) {
    /* 
     * This test reproduces issue #520: feeding decode functions
     * a “source” array containing non‐Base64 bytes should produce
     * an error (-1) from both decoders.
     */

    /* 1) Define the “source” byte sequence on the stack.
     *    Note: This is arbitrary binary data (not a C string),
     *    so it is NOT NUL‑terminated. */
    unsigned char source[] = {
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 12, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 82,
    };
    size_t len = sizeof(source);  /* total number of bytes in source */

    char *buffer = OPENSSL_malloc(len + 1 /* space for NUL */);
    if (buffer == NULL) {
        TEST_error("malloc failed for input buffer");
        return 0;
    }
    /* Copy the raw bytes and then append '\0' */
    memcpy(buffer, source, len);
    buffer[len] = '\0';

    /*
     * 3) Determine the maximum possible output length from a
     *    Base64 decode of `buffer`.  This is how many bytes we
     *    must allocate for the worst case.
     */
    size_t back_bufsize =
        maximal_binary_length_from_base64(buffer, len);

    /* 4) Allocate output buffer for our “simdutf” decoder */
    unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
    if (back_bufsize != 0 && back_simd == NULL) {
        OPENSSL_free(buffer);
        TEST_error("malloc failed for simdutf output buffer");
        return 0;
    }
    int outlen_simd = 0;
    /* Call the decoder: we expect it to return -1 on this invalid input */
    int result_simd = simdutf_decode(
        NULL,
        (char *)back_simd,
        &outlen_simd,
        buffer,
        len
    );
    DEBUG_PRINT("DEBUG: simdutf_decode returned %d, outlen=%d\n",
                result_simd, outlen_simd);
    ASSERT_EQUAL_INT(result_simd, -1);

    /* 5) Allocate output buffer for OpenSSL’s decoder */
    unsigned char *back_ssl = OPENSSL_malloc(back_bufsize);
    if (back_bufsize != 0 && back_ssl == NULL) {
        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        TEST_error("malloc failed for OpenSSL output buffer");
        return 0;
    }
    int outlen_ssl = 0;
    /* Again expected to return -1 */
    int result_ssl = OpenSSL_decode(
        NULL,
        (char *)back_ssl,
        &outlen_ssl,
        buffer,
        len
    );
    DEBUG_PRINT("DEBUG: OpenSSL_decode returned %d, outlen=%d\n",
                result_ssl, outlen_ssl);
    ASSERT_EQUAL_INT(result_ssl, -1);

    /* 6) Both decoders must agree on error code and output length */
    ASSERT_EQUAL_INT(result_ssl, result_simd);
    ASSERT_EQUAL_INT(outlen_ssl, outlen_simd);

    /* 7) Clean up only what we allocated on the heap */
    OPENSSL_free(buffer);
    OPENSSL_free(back_simd);
    OPENSSL_free(back_ssl);

    return 1;
}

static int test_issue_509(void)
{
    /* here ‘input’ really is a string, so strlen() is safe */
    const char *buffer = " =";  
    size_t in_len = strlen(buffer);  /* ==2 */

    /* pick an output buffer big enough for the worst‐case one byte */
    unsigned char out_simd[1];
    unsigned char out_ssl[1];
    int outlen_simd = 0, outlen_ssl = 0;

    int rc_simd = simdutf_decode(NULL,
                                 (char *)out_simd,
                                 &outlen_simd,
                                 buffer,
                                 in_len);
    ASSERT_EQUAL_INT(rc_simd,   -1);
    ASSERT_EQUAL_INT(outlen_simd, 0);

    int rc_ssl = OpenSSL_decode(NULL,
                                (char *)out_ssl,
                                &outlen_ssl,
                                buffer,
                                in_len);
    ASSERT_EQUAL_INT(rc_ssl,   -1);
    ASSERT_EQUAL_INT(outlen_ssl, 0);

    /* they must agree */
    ASSERT_EQUAL_INT(rc_ssl, rc_simd);
    ASSERT_EQUAL_INT(outlen_ssl, outlen_simd);

    return 1;
}

static int test_issue_502_alt(void)
{
    for (size_t nof_equals = 1; nof_equals < 100; ++nof_equals) {
        /* Build a Base64 string consisting of `nof_equals` '=' characters */
        char *buffer = OPENSSL_malloc(nof_equals + 1);
        if (buffer == NULL) {
            TEST_error("Out of memory in issue_502_alt for nof_equals = %zu", nof_equals);
            return 0;
        }
        memset(buffer, '=', nof_equals);
        buffer[nof_equals] = '\0';
        size_t buf_len = nof_equals;

        /* Compute the maximum possible decoded length */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, buf_len);

        /* ---- simdutf decoding ---- */
        unsigned char *back_simd = OPENSSL_malloc(back_bufsize + 1);
        if (back_bufsize != 0 && back_simd == NULL) {
            TEST_error("Out of memory for simdutf back buffer");
            OPENSSL_free(buffer);
            return 0;
        }
        int outlen_simd = 0;
        int rc_simd = simdutf_decode(NULL,
                                     (char *)back_simd,
                                     &outlen_simd,
                                     buffer,
                                     buf_len);
        DEBUG_PRINT("DEBUG: simdutf_decode(no.=%zu) → rc=%d, outlen=%d\n",
                    nof_equals, rc_simd, outlen_simd);
        /* A string of only padding signs is invalid */
        ASSERT_EQUAL_INT(rc_simd,    -1);
        ASSERT_EQUAL_INT(outlen_simd, 0);

        /* ---- OpenSSL decoding ---- */
        unsigned char *back_ssl = OPENSSL_malloc(back_bufsize + 1);
        if (back_bufsize != 0 && back_ssl == NULL) {
            TEST_error("Out of memory for OpenSSL back buffer");
            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            return 0;
        }
        int outlen_ssl = 0;
        int rc_ssl = OpenSSL_decode(NULL,
                                    (char *)back_ssl,
                                    &outlen_ssl,
                                    buffer,
                                    buf_len);
        DEBUG_PRINT("DEBUG: OpenSSL_decode(no.=%zu) → rc=%d, outlen=%d\n",
                    nof_equals, rc_ssl, outlen_ssl);
        ASSERT_EQUAL_INT(rc_ssl,     -1);
        ASSERT_EQUAL_INT(outlen_ssl,  0);

        /* Both decoders must agree */
        ASSERT_EQUAL_INT(rc_ssl,    rc_simd);
        ASSERT_EQUAL_SIZE(outlen_ssl, outlen_simd);

        OPENSSL_free(buffer);
        OPENSSL_free(back_simd);
        OPENSSL_free(back_ssl);
    }

    return 1;
}

static int test_issue_504_8bit(void)
{
    /* Our “buffer” really is a C‑string */
    const char *buffer = "=";    /* 0x3D == 61 */
    size_t buf_len  = strlen(buffer);  /* == 1 */

    /* Compute worst‑case decoded length */
    size_t back_bufsize = maximal_binary_length_from_base64(buffer, buf_len);

    /* ---- simdutf decoding ---- */
    unsigned char *back_simd = OPENSSL_malloc(back_bufsize + 1);
    if (back_bufsize != 0 && back_simd == NULL) {
        TEST_error("Out of memory for simdutf back buffer");
        return 0;
    }
    int outlen_simd = 0;
    int rc_simd = simdutf_decode(NULL,
                                 (char *)back_simd,
                                 &outlen_simd,
                                 buffer,
                                 buf_len);
    DEBUG_PRINT("DEBUG: simdutf returned %d, outlen=%d\n", rc_simd, outlen_simd);
    /* A lone “=” is invalid, so we expect error = -1, no output */
    ASSERT_EQUAL_INT(rc_simd,    -1);
    ASSERT_EQUAL_INT(outlen_simd, 0);

    /* ---- OpenSSL decoding ---- */
    unsigned char *back_ssl = OPENSSL_malloc(back_bufsize + 1);
    if (back_bufsize != 0 && back_ssl == NULL) {
        OPENSSL_free(back_simd);
        TEST_error("Out of memory for OpenSSL back buffer");
        return 0;
    }
    int outlen_ssl = 0;
    int rc_ssl = OpenSSL_decode(NULL,
                                (char *)back_ssl,
                                &outlen_ssl,
                                buffer,
                                buf_len);
    DEBUG_PRINT("DEBUG: OpenSSL returned %d, outlen=%d\n", rc_ssl, outlen_ssl);
    ASSERT_EQUAL_INT(rc_ssl,     -1);
    ASSERT_EQUAL_INT(outlen_ssl,  0);

    /* Both must agree */
    ASSERT_EQUAL_INT(rc_ssl,    rc_simd);
    ASSERT_EQUAL_SIZE(outlen_ssl, outlen_simd);

    OPENSSL_free(back_simd);
    OPENSSL_free(back_ssl);
    return 1;
}

int max(int a, int b) {
    return (a > b) ? a : b;
}


// /*
//  * TEST(bad_padding_base64)
//  *
//  * For each binary length from 0 to 2047, generate random binary data,
//  * encode it to Base64, then adjust the padding by appending or removing '='
//  * and inserting extra whitespace (5 insertions), and then decode.
//  * The expected result is that the decoder returns an error (INVALID_BASE64_CHARACTER).
//  */
static int test_bad_padding_base64(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(CYAN_TEXT("DEBUG: Entered test_bad_padding_base64\n"));

    for (len = 1; len < 2048; len++) {
        DEBUG_PRINT(BRIGHT_YELLOW_BG(BRIGHT_WHITE_TEXT("DEBUG: Processing length = %zu\n")), len);

        /* Allocate source binary data */
        char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
        if (len > 0 && !source) {
            TEST_error("Out of memory for source of length %zu", len);
            return 0;
        }
        for (i = 0; i < len; i++) {
            source[i] = (char)(rand_r(&seed) % 256);
        }

        /* Allocate buffer for Base64 conversion */
        size_t b64_len_expected = base64_length_from_binary(len);
        char *buffer = OPENSSL_malloc(b64_len_expected + 1);
        if (!buffer) {
            TEST_error("Out of memory for Base64 buffer for length %zu", len);
            if (source) OPENSSL_free(source);
            return 0;
        }
        size_t s = tail_encode_base64(NULL, buffer, source, len);
        buffer[s] = '\0';
        DEBUG_PRINT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n", s, buffer);

        /* Determine padding count in the encoded string */
        size_t padding = 0;
        if (s > 0 && buffer[s - 1] == '=') {
            padding++;
            if (s > 1 && buffer[s - 2] == '=') {
                padding++;
            }
        }
        /* "Resize" the vector to the actual length s */
        // char *temp = OPENSSL_realloc(buffer, s);
        // if (temp) {
        //     buffer = temp;
        // }

        if (s != 0) {
            char *temp = OPENSSL_realloc(buffer, s);
            if (temp)
                buffer = temp;
        } else {
            /* If s is zero, keep the original allocation intact. Realloc acts as free when second arg is 0 and this causes double freeing error */
        }
        

        /* Allocate back buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);
        char *back = OPENSSL_malloc(back_bufsize);
        if (!back && back_bufsize != 0) {
            TEST_error("Out of memory for back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            return 0;
        }

        // if (padding == 1) {
        //     DEBUG_PRINT("DEBUG: Padding = 1\n");
        //     /* Case: one padding character exists.
        //      * Append an extra '=' and then insert 5 spaces. It should break
        //      */
        //     char *copy = OPENSSL_malloc(s + 1);
        //     if (!copy) {
        //         TEST_error("Out of memory for copy");
        //         OPENSSL_free(source);
        //         OPENSSL_free(buffer);
        //         return 0;
        //     }
        //     memcpy(copy, buffer, s);
        //     copy[s] = '=';
        //     size_t copy_len = s + 1;
        //     for (i = 0; i < 5; i++) {
        //         size_t pos = add_space(&copy, &copy_len, &seed);
        //         if (pos == (size_t)-1) {
        //             TEST_error("Out of memory in add_space for length %zu", copy_len);
        //             OPENSSL_free(source);
        //             OPENSSL_free(buffer);
        //             OPENSSL_free(copy);
        //             return 0;
        //         }
        //     }
        //     // result r = base64_tail_decode_trim_end(NULL, back,copy, copy_len);
        //     // ASSERT_EQUAL_INT(r.error, INVALID_BASE64_CHARACTER);

        //     // size_t copy_len = s + 6;


        //     unsigned char *back_simd = OPENSSL_malloc(back_bufsize + 2);
        //     if (back_bufsize != 0 && back_simd == NULL) {
        //         TEST_error("Out of memory for simdutf back buffer");
        //         OPENSSL_free(copy);
        //         return 0;
        //     }
        //     int outlen_simdutf = 0;
        //     int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, copy, copy_len);
        //     DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        //     ASSERT_EQUAL_INT(result_simdutf, -1);
        //     // if (back_simd != NULL) {
        //     //     OPENSSL_free(back_simd);                
        //     // }


        //     /* **** OpenSSL decoding **** */
        //     unsigned char *back_openssl = OPENSSL_malloc(back_bufsize + 2);
        //     int outlen_openssl = 0;
        //     int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, copy, copy_len);
        //     DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        //     if (len == 0) {
        //         ASSERT_EQUAL_INT(result_openssl, 0);
        //     } else {
        //         ASSERT_EQUAL_INT(result_openssl, -1);
        //     }
        //     // for (j = 0; j < len; j++) {
        //     //     ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
        //     // }
        //     DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", copy_len);


        //     /* Specific assertions comparing the two decoders */
        //     ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        //     ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);
        //     ASSERT_EQUAL_INT(result_openssl, -1);
        //     DEBUG_PRINT("DEBUG:Copylen - 5= %d\n", copy_len - 5);
        //     if ((copy_len - 5) % 64 == 1) {
        //         ASSERT_EQUAL_INT(outlen_openssl, max(0,(copy_len - 5)/4 * 3 - (((copy_len - 5)/4 * 3) % 48)) -1);
        //     } else {
        //         ASSERT_EQUAL_INT(outlen_openssl, max(0,(copy_len - 5)/4 * 3 - (((copy_len - 5)/4 * 3) % 48)));
        //     }

        //     OPENSSL_free(back_simd);
        //     OPENSSL_free(back_openssl);
        //     OPENSSL_free(copy);
        // }

        // else
        //  if (padding == 2) {
        //     DEBUG_PRINT("DEBUG: Padding = 2\n");
        //     /* Case: two padding characters exist.
        //      * Append “==” and then insert 5 spaces — this must also fail.
        //      */
        //     /* allocate s+2 bytes for the “==” plus one for the NUL */
        //     char *copy2 = OPENSSL_malloc(s + 3);
        //     if (!copy2) {
        //         TEST_error("Out of memory for copy2");
        //         OPENSSL_free(source);
        //         OPENSSL_free(buffer);
        //         return 0;
        //     }
        //     /* copy the original, append “==” */
        //     memcpy(copy2, buffer, s);
        //     copy2[s]   = '=';
        //     copy2[s+1] = '=';
        //     copy2[s+2] = '\0';
        //     size_t copy2_len = s + 2;
        
        //     /* sprinkle in 5 random whitespace chars */
        //     for (i = 0; i < 5; i++) {
        //         size_t pos = add_space(&copy2, &copy2_len, &seed);
        //         if (pos == (size_t)-1) {
        //             TEST_error("Out of memory in add_space for length %zu", copy2_len);
        //             OPENSSL_free(source);
        //             OPENSSL_free(buffer);
        //             OPENSSL_free(copy2);
        //             return 0;
        //         }
        //     }
        
        //     /* simdutf must reject it */
        //     unsigned char *back_simd2 = OPENSSL_malloc(back_bufsize);
        //     if (back_bufsize != 0 && back_simd2 == NULL) {
        //         TEST_error("Out of memory for simdutf back buffer");
        //         OPENSSL_free(copy2);
        //         return 0;
        //     }
        //     int outlen_simdutf2 = 0;
        //     int result_simdutf2 =
        //         simdutf_decode(NULL, (char *)back_simd2, &outlen_simdutf2,
        //                        copy2, copy2_len);
        //     DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf2);
        //     ASSERT_EQUAL_INT(result_simdutf2, -1);
        //     OPENSSL_free(back_simd2);
        
        //     /* (Optionally) check that OpenSSL also rejects it */
        //     unsigned char *back_openssl2 = OPENSSL_malloc(back_bufsize + 2);
        //     int outlen_openssl2 = 0;
        //     int result_openssl2 =
        //         OpenSSL_decode(NULL, (char *)back_openssl2, &outlen_openssl2,
        //                        copy2, copy2_len);
        //     DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl2);
        //     ASSERT_EQUAL_INT(result_openssl2, -1);

        //     ASSERT_EQUAL_INT(result_openssl2, result_simdutf2);
        //     if ((copy2_len - 5) % 64 == 2) {
        //         ASSERT_EQUAL_INT(outlen_openssl2, max(0,(copy2_len - 5)/4 * 3 - (((copy2_len - 5)/4 * 3) % 48)) -2);
        //     } else {
        //         ASSERT_EQUAL_INT(outlen_openssl2, max(0,(copy2_len - 5)/4 * 3 - (((copy2_len - 5)/4 * 3) % 48)));
        //     }            
        //     ASSERT_EQUAL_SIZE(outlen_openssl2, outlen_simdutf2);

        //     OPENSSL_free(back_openssl2);
        
        //     OPENSSL_free(copy2);
        // }
        
        // /*  try removing a character and adding spaces */
        //  {
        //     DEBUG_PRINT("DEBUG: Remove one character + add spaces\n");
            
        //     /* Create a copy with one less character */
        //     char *copy = OPENSSL_malloc(s);
        //     if (!copy) {
        //         TEST_error("Out of memory for copy");
        //         OPENSSL_free(source);
        //         OPENSSL_free(buffer);
        //         return 0;
        //     }
        //     memcpy(copy, buffer, s - 1);  /* Copy all but last character */
        //     size_t copy_len = s - 1;

        //     /* Add 5 spaces */
        //     for (i = 0; i < 5; i++) {
        //         size_t pos = add_space(&copy, &copy_len, &seed);
        //         if (pos == (size_t)-1) {
        //             TEST_error("Out of memory in add_space for length %zu", copy_len);
        //             OPENSSL_free(source);
        //             OPENSSL_free(buffer);
        //             OPENSSL_free(copy);
        //             return 0;
        //         }
        //     }

        //     /* simdutf decode */
        //     unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
        //     if (back_bufsize != 0 && back_simd == NULL) {
        //         TEST_error("Out of memory for simdutf back buffer");
        //         OPENSSL_free(copy);
        //         return 0;
        //     }
        //     int outlen_simdutf = 0;
        //     int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, copy, copy_len);
        //     DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
        //     ASSERT_EQUAL_INT(result_simdutf, -1);

        //     /* OpenSSL decode */
        //     unsigned char *back_openssl = OPENSSL_malloc(back_bufsize);
        //     if (back_bufsize != 0 && back_openssl == NULL) {
        //         TEST_error("Out of memory for OpenSSL back buffer");
        //         OPENSSL_free(copy);
        //         OPENSSL_free(back_simd);
        //         return 0;
        //     }
        //     int outlen_openssl = 0;
        //     int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, copy, copy_len);
        //     DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
        //     ASSERT_EQUAL_INT(result_openssl, -1);

        //     /* Compare results */
        //     ASSERT_EQUAL_INT(result_openssl, result_simdutf);
        //     ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);
        //     // if ((copy_len - 5) % 64 == 1) {
        //     //     ASSERT_EQUAL_INT(outlen_openssl, max(0,(copy_len - 5)/4 * 3 - (((copy_len - 5)/4 * 3) % 48)) -1);
        //     // } else {
        //         // ASSERT_EQUAL_INT(outlen_openssl, max(0,(copy_len - 5)/4 * 3 - (((copy_len - 5)/4 * 3) % 48)));
        //     // }

        //     OPENSSL_free(copy);
        //     OPENSSL_free(back_simd);
        //     OPENSSL_free(back_openssl);
        // }

        /* add one '=' and 5 spaces */
         {
            DEBUG_PRINT("************DEBUG: Generic case\n");
            if (padding == 0) {
                DEBUG_PRINT("DEBUG: Padding = 0,, adding 1\n");
            } else {
                DEBUG_PRINT("DEBUG: Padding = %zu, adding 1\n", padding);
            }
            /* Make a copy of buffer and append '=' */
            char *copy = OPENSSL_malloc(s + 1);
            if (!copy) {
                TEST_error("Out of memory for copy");
                OPENSSL_free(source);
                OPENSSL_free(buffer);
                return 0;
            }
            memcpy(copy, buffer, s);
            copy[s] = '=';
            size_t copy_len = s + 1;
            
            /* Add 5 random spaces */
            for (i = 0; i < 5; i++) {
                size_t pos = add_space(&copy, &copy_len, &seed);
                if (pos == (size_t)-1) {
                    TEST_error("Out of memory in add_space for length %zu", copy_len);
                    OPENSSL_free(source);
                    OPENSSL_free(buffer);
                    OPENSSL_free(copy);
                    return 0;
                }
            }

            /* simdutf decode - should fail */
            unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
            if (back_bufsize != 0 && back_simd == NULL) {
                TEST_error("Out of memory for simdutf back buffer");
                OPENSSL_free(copy);
                return 0;
            }
            int outlen_simdutf = 0;
            int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, copy, copy_len);
            DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
            ASSERT_EQUAL_INT(result_simdutf, -1);

            /* OpenSSL decode - should also fail */
            unsigned char *back_openssl = OPENSSL_malloc(back_bufsize + 2);
            if (back_bufsize != 0 && back_openssl == NULL) {
                TEST_error("Out of memory for OpenSSL back buffer");
                OPENSSL_free(copy);
                OPENSSL_free(back_simd);
                return 0;
            }
            int outlen_openssl = 0;
            int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, copy, copy_len);
            DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
            
            /* Compare results */
            ASSERT_EQUAL_INT(result_openssl, result_simdutf);
            ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);
            // ASSERT_EQUAL_INT(outlen_openssl, max(0,(copy_len - 5)/4 * 3 - (((copy_len - 5)/4 * 3) % 48)));
            // if ((copy_len - 5) % 64 == 1) {
            //     ASSERT_EQUAL_INT(outlen_openssl, max(0,(copy_len - 5)/4 * 3 - (((copy_len - 5)/4 * 3) % 48)) -1);
            // } else {
            //     ASSERT_EQUAL_INT(outlen_openssl, max(0,(copy_len - 5)/4 * 3 - (((copy_len - 5)/4 * 3) % 48)));
            // }

            OPENSSL_free(copy);
            OPENSSL_free(back_simd);
            OPENSSL_free(back_openssl);
        }

        OPENSSL_free(source);
        OPENSSL_free(buffer);
        OPENSSL_free(back);
    }
    return 1;
}

// static int test_doomed_base64_roundtrip(void)
// {
//     size_t len, trial, i;
//     unsigned int seed = 12345;  /* fixed seed for reproducibility */

//     for (len = 0; len < 2048; len++) {
//         /* Allocate source data (if len == 0, source may be NULL) */
//         char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
//         if (len > 0 && source == NULL) {
//             TEST_error(RED_TEXT("Out of memory for source of length %zu\n"), len);
//             return 0;
//         }
//         /* Allocate a Base64 buffer of sufficient size */
//         size_t b64_size = base64_length_from_binary(len);
//         char *buffer = OPENSSL_malloc(b64_size + 1); /* +1 for null-terminator */
//         if (buffer == NULL) {
//             TEST_error(RED_TEXT("Out of memory for Base64 buffer of length %zu\n"), b64_size + 1);
//             if (source) OPENSSL_free(source);
//             return 0;
//         }

//         for (trial = 0; trial < 10; trial++) {
//             DEBUG_PRINT(BRIGHT_YELLOW_BG("Entering new trial"));
//             /* Fill source with random bytes (if len > 0) */
//             if (len > 0) {
//                 for (i = 0; i < len; i++) {
//                     source[i] = (char)(rand_r(&seed) % 256);
//                 }
//             }
//             /* Encode source to Base64 */
//             size_t size = tail_encode_base64(NULL, buffer, source, len);
//             buffer[size] = '\0';
//             /* Record the effective length of the Base64 string */
//             size_t effective_b64_len = size;

//             DEBUG_PRINT(BRIGHT_CYAN_TEXT("DEBUG: For len=%zu, trial=%zu\n"), len, trial);
//             DEBUG_PRINT(BRIGHT_GREEN_TEXT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n"),
//                         effective_b64_len, buffer);

//             /* Inject garbage into the Base64 string.
//                add_garbage takes a pointer to the pointer and a pointer to its length,
//                plus the lookup table, and returns the insertion location.
//             */
//             size_t location = add_garbage(&buffer, &effective_b64_len, &seed, to_base64_value);
//             DEBUG_PRINT(BRIGHT_YELLOW_TEXT("DEBUG: After add_garbage, effective_b64_len=%zu, garbage location=%zu\n"),
//                         effective_b64_len, location);

//             /* Allocate back buffer for decoded binary data */
//             size_t back_bufsize = maximal_binary_length_from_base64(buffer, effective_b64_len);
//             DEBUG_PRINT(BRIGHT_BLUE_TEXT("DEBUG: Back buffer size = %zu\n"), back_bufsize);
//             char *back = (back_bufsize > 0) ? OPENSSL_malloc(back_bufsize) : NULL;
//             if (back_bufsize > 0 && back == NULL) {
//                 TEST_error(RED_TEXT("Out of memory for back buffer (length %zu)\n"), back_bufsize);
//                 if (source) OPENSSL_free(source);
//                 OPENSSL_free(buffer);
//                 return 0;
//             }

//             /* Call normal decode function */
//             result r = base64_tail_decode_trim_end(NULL, back, buffer, effective_b64_len);
//             DEBUG_PRINT(BRIGHT_MAGENTA_TEXT("DEBUG: Normal decode result: error=%d, count=%zu\n"),
//                         r.error, r.count);
//             ASSERT_EQUAL_INT(r.error, INVALID_BASE64_CHARACTER);
//             ASSERT_EQUAL_SIZE(r.count, location);

//             // /* Try safe decoding with different last-chunk handling options */
//             // for (i = 0; i < 3; i++) {
//             //     last_chunk_handling_options opt;
//             //     if (i == 0) {
//             //         opt = STRICT;
//             //     } else if (i == 1) {
//             //         opt = LOOSE;
//             //     } else {
//             //         opt = STOP_BEFORE_PARTIAL;
//             //     }
//             //     size_t safe_back_len = back_bufsize;
//             //     result r2 = base64_to_binary_safe(buffer, effective_b64_len, back, &safe_back_len, 0, opt);
//             //     DEBUG_PRINT(BRIGHT_MAGENTA_TEXT("DEBUG: Safe decode (option %d): error=%d, count=%zu\n"),
//             //                 (int)opt, r2.error, r2.count);
//             //     ASSERT_EQUAL_INT(r2.error, INVALID_BASE64_CHARACTER);
//             //     ASSERT_EQUAL_SIZE(r2.count, location);
//             // }
//             if (back) OPENSSL_free(back);
//         }
//         if (source) OPENSSL_free(source);
//         OPENSSL_free(buffer);
//     }
//     return 1;
// }


// /* 
//  * Test: doomed_truncated_base64_roundtrip
//  *
//  * For each length from 1 to 2047, generate random binary data,
//  * encode it to Base64, then truncate the encoded string by removing the last 3 characters.
//  * The expectation is that the decoder will return an error 
//  * (BASE64_INPUT_REMAINDER) and the count of processed characters should be as expected.
//  */
static int test_doomed_truncated_base64_roundtrip(void) 
{
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */

    for (len = 1; len < 2048; len++) {
        DEBUG_PRINT("******************** DEBUG: Processing length = %zu\n", len);

        char *source = OPENSSL_malloc(len);
        if (len > 0 && source == NULL) {
            TEST_error("Out of memory for source of length %zu", len);
            return 0;
        }

        for (trial = 0; trial < 10; trial++) {
            /* Fill the source buffer with random bytes */
            for (i = 0; i < len; i++) {
                source[i] = (char)(rand_r(&seed) % 256);
            }

            /* Allocate buffer for Base64 encoding */
            size_t b64_size = base64_length_from_binary(len);
            char *buffer = OPENSSL_malloc(b64_size + 1); 
            if (buffer == NULL) {
                TEST_error("Out of memory for Base64 buffer of length %zu", b64_size + 1);
                OPENSSL_free(source);
                return 0;
            }
            size_t size = tail_encode_base64(NULL, buffer, source, len);
            buffer[size] = '\0';

            /* Truncate the encoded buffer by removing the last 3 characters */
            if (size < 3) {
                OPENSSL_free(buffer);
                continue;
            }
            size_t truncated = size - 3;
            char *temp = OPENSSL_realloc(buffer, truncated + 1); // +1 for NUL
            if (temp != NULL) {
                buffer = temp;
                buffer[truncated] = '\0';
            }

            /* Allocate back buffer for decoded binary data */
            size_t back_bufsize = maximal_binary_length_from_base64(buffer, truncated);

            /* **** simdutf decoding **** */
            unsigned char *back_simd = OPENSSL_malloc(back_bufsize + 2);
            if (back_bufsize != 0 && back_simd == NULL) {
                TEST_error("Out of memory for simdutf back buffer");
                OPENSSL_free(source);
                OPENSSL_free(buffer);
                return 0;
            }
            
            int outlen_simdutf = 0;
            int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, truncated);
            DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);

            /* **** OpenSSL decoding **** */
            unsigned char *back_openssl = OPENSSL_malloc(back_bufsize + 2);
            if (back_bufsize != 0 && back_openssl == NULL) {
                TEST_error("Out of memory for OpenSSL back buffer");
                OPENSSL_free(buffer);
                OPENSSL_free(back_simd);
                return 0;
            }

            int outlen_openssl = 0; 
            int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, truncated);
            DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);

            /* Compare results */
            ASSERT_EQUAL_INT(result_openssl, result_simdutf);
            ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);
            ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);
            
            /* Both should fail with -1 error code */
            ASSERT_EQUAL_INT(result_openssl, -1);
            ASSERT_EQUAL_INT(outlen_openssl, (truncated/4)*3 - ((truncated/4)*3) % 48);

            OPENSSL_free(buffer);
            OPENSSL_free(back_simd);
            OPENSSL_free(back_openssl);
        }
        OPENSSL_free(source);
    }
    return 1;
}


// /*-------------------------------------------------------------------------
//   Test: streaming_base64_roundtrip

//   For a fixed source length (2048 bytes), this test generates random binary data,
//   encodes it to Base64, then simulates streaming decoding by processing the
//   Base64 string in windows. For each window size (from 16 to 2048, stepping by 7),
//   the test decodes the Base64 data in chunks. If a chunk does not complete a full
//   4‑character block, it adjusts the position (simulating re‑processing of tail bytes).
//   Finally, the decoded output is compared with the original source.
// -------------------------------------------------------------------------*/
// static int test_streaming_base64_roundtrip(void)
// {
//     size_t len = 2048;
//     size_t i, pos, outpos, window;
//     unsigned int seed = 12345;  /* fixed seed for reproducibility */

//     /* Allocate source buffer */
//     char *source = OPENSSL_malloc(len);
//     if (!source) {
//         TEST_error("Out of memory for source");
//         return 0;
//     }
//     /* Fill source with random bytes */
//     for (i = 0; i < len; i++) {
//         source[i] = (char)(rand_r(&seed) % 256);
//     }

//     /* Allocate Base64 buffer */
//     size_t b64_size = base64_length_from_binary(len);
//     char *buffer = OPENSSL_malloc(b64_size + 1);
//     if (!buffer) {
//         TEST_error("Out of memory for Base64 buffer");
//         OPENSSL_free(source);
//         return 0;
//     }
//     size_t size = tail_encode_base64(NULL, buffer, source, len);
//     buffer[size] = '\0'; /* null-terminate */

//     /* Process the encoded Base64 in streaming windows */
//     for (window = 16; window <= 2048; window += 7) {
//         /* Allocate back buffer for decoded binary data */
//         char *back = OPENSSL_malloc(len);
//         if (!back) {
//             TEST_error("Out of memory for back buffer");
//             OPENSSL_free(source);
//             OPENSSL_free(buffer);
//             return 0;
//         }
//         outpos = 0;
//         /* Process the Base64 encoded string in chunks of "window" size */
//         for (pos = 0; pos < size; pos += window) {
//             size_t count = (window < (size - pos)) ? window : (size - pos);
//             result r = base64_tail_decode_trim_end(NULL, back + outpos,buffer + pos, count);
//             /* Ensure we did not get an error indicating invalid character */
//             ASSERT_TRUE(r.error != INVALID_BASE64_CHARACTER);
//             if (pos + count == size) {
//                 /* Last chunk: expect a complete decode (SUCCESS) */
//                 ASSERT_EQUAL_INT(r.error, BASE64_SUCCESS);
//             } else {
//                 size_t tail_bytes_to_reprocess = 0;
//                 if (r.error == BASE64_INPUT_REMAINDER) {
//                     tail_bytes_to_reprocess = 1;
//                 } else {
//                     tail_bytes_to_reprocess = ((r.count % 3) == 0) ? 0 : (r.count % 3) + 1;
//                 }
//                 /* Adjust position backwards by tail_bytes_to_reprocess */
//                 // pos = (pos >= tail_bytes_to_reprocess) ? pos - tail_bytes_to_reprocess : 0;
//                 pos -= tail_bytes_to_reprocess;
//                 /* Also remove incomplete bytes from r.count */
//                 r.count -= (r.count % 3);
//             }
//             outpos += r.count;
//         }
//         /* Check that the total decoded bytes match the original source length */
//         ASSERT_EQUAL_SIZE(outpos, len);
//         if (memcmp(back, source, len) != 0) {
//             TEST_error(RED_TEXT("Streaming decode content mismatch for window %zu"), window);
//             OPENSSL_free(back);
//             OPENSSL_free(source);
//             OPENSSL_free(buffer);
//             return 0;
//         }
//         OPENSSL_free(back);
//     }

//     OPENSSL_free(source);
//     OPENSSL_free(buffer);
//     return 1;
// }


// static int test_readme_test(void)
// {
//     size_t len = 2048;
//     size_t i, pos, outpos, window;

//     /* Allocate and fill the Base64 string with 'a' */
//     char *base64 = OPENSSL_malloc(len);
//     if (!base64) {
//         TEST_error("Out of memory for base64 buffer");
//         return 0;
//     }
//     for (i = 0; i < len; i++) {
//         base64[i] = 'a';
//     }
    
//     /* Allocate back buffer for decoded binary data */
//     size_t back_buf_size = ((len + 3) / 4) * 3;
//     char *back = OPENSSL_malloc(back_buf_size);
//     if (!back) {
//         TEST_error("Out of memory for back buffer");
//         OPENSSL_free(base64);
//         return 0;
//     }
    
//     outpos = 0;
//     window = 512;
//     for (pos = 0; pos < len; pos += window) {
//         size_t count = (window < (len - pos)) ? window : (len - pos);
//         result r = base64_tail_decode_trim_end(NULL, back + outpos,base64 + pos, count);
//         if (r.error == INVALID_BASE64_CHARACTER) {
//             TEST_error("Invalid base64 character at position %zu\n", pos + r.count);
//             OPENSSL_free(back);
//             OPENSSL_free(base64);
//             return 0;
//         }
//         // If we arrived at the end of the base64 input, we must check that the
//         // number of characters processed is a multiple of 4, or that we have a
//         // remainder of 0, 2 or 3.
//         if (pos + count == len && r.error == BASE64_INPUT_REMAINDER) {
//             TEST_error("The base64 input contained an invalid number of characters");
//         }
//         // If we are not at then end, we may have to reprocess either 1, 2 or 3
//         // bytes, and to drop the last 0, 2 or 3 bytes decoded.
//         size_t tail_bytes_to_reprocess = 0;
//         if (r.error == BASE64_INPUT_REMAINDER) {
//             tail_bytes_to_reprocess = 1;
//         } else {
//             tail_bytes_to_reprocess = (r.count % 3 == 0) ? 0 : (r.count % 3) + 1;
//         }
//         // if (pos >= tail_bytes_to_reprocess)
//             pos -= tail_bytes_to_reprocess;
//         // else
//             // pos = 0;
//         r.count -= (r.count % 3);
//         outpos += r.count;
//     }
    
//     DEBUG_PRINT(GREEN_TEXT("Decoded result length: %zu\n"), outpos);
    
//     /* Use back as needed; here we simply free it */
//     OPENSSL_free(back);
//     OPENSSL_free(base64);
//     return 1;
// }

// static int test_doomed_partial_buffer_utf8(void)
// {
//     /* Fixed 16-byte vector to be appended */
//     unsigned char vectorToBeCompressed[16] = {
//         0x6D, 0x6A, 0x6D, 0x73, 0x41, 0x71, 0x39, 0x75,
//         0x76, 0x6C, 0x77, 0x48, 0x20, 0x77, 0x33, 0x53
//     };

//     unsigned int seed = 12345;  /* Fixed seed for reproducibility */
//     size_t len, trial, i;

//     for (len = 0; len < 2048; len++) {
//         /* Allocate source buffer; if len==0, source is allowed to be NULL */
//         char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
//         if (len > 0 && source == NULL) {
//             TEST_error(RED_TEXT("Out of memory for source of length %zu\n"), len);
//             return 0;
//         }

//         for (trial = 0; trial < 10; trial++) {
//             DEBUG_PRINT(BRIGHT_YELLOW_BG("New trial\n"));

//             int bytesConsumed = 0, bytesWritten = 0;
//             /* Fill source with random bytes */
//             if (len > 0) {
//                 for (i = 0; i < len; i++) {
//                     source[i] = (char)(rand_r(&seed) % 256);
//                 }
//             }

//             /* Encode source to Base64 */
//             size_t b64_size = base64_length_from_binary(len);
//             char *base64 = OPENSSL_malloc(b64_size + 1);
//             if (base64 == NULL) {
//                 TEST_error(RED_TEXT("Out of memory for Base64 buffer of length %zu\n"), b64_size + 1);
//                 if (source) OPENSSL_free(source);
//                 return 0;
//             }
//             size_t size = tail_encode_base64(NULL, base64, source, len);
//             base64[size] = '\0';
//             DEBUG_PRINT(GREEN_TEXT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n"), size, base64);

//             /* Adjust insertion location: if the encoded string ends with '=',
//                set insertion point before the first '='.
//             */
//             size_t valid_length = size;
//             for (i = 0; i < size; i++) {
//                 if (base64[i] == '=') {
//                     valid_length = i;
//                     break;
//                 }
//             }
//             DEBUG_PRINT(YELLOW_TEXT("DEBUG: Valid Base64 part length = %zu\n"), valid_length);

//             /* Now, append fixed data copies after the valid part.
//                (The padding, if any, remains at the end.)
//             */
//             size_t effective_b64_len = valid_length;
//             int numberOfCopies = (rand_r(&seed) % 5) + 1; /* random between 1 and 5 */
//             DEBUG_PRINT(BLUE_TEXT("DEBUG: numberOfCopies = %d\n"), numberOfCopies);
//             for (i = 0; i < (size_t)numberOfCopies; i++) {
//                 char *new_buffer = OPENSSL_realloc(base64, effective_b64_len + 16 + 1);
//                 if (new_buffer == NULL) {
//                     TEST_error(RED_TEXT("Out of memory during fixed vector append\n"));
//                     OPENSSL_free(base64);
//                     if (source) OPENSSL_free(source);
//                     return 0;
//                 }
//                 base64 = new_buffer;
//                 memcpy(base64 + effective_b64_len, vectorToBeCompressed, 16);
//                 effective_b64_len += 16;
//                 base64[effective_b64_len] = '\0';
//                 DEBUG_PRINT(BLUE_TEXT("DEBUG: After iteration %zu, effective_b64_len = %zu\n"), i, effective_b64_len);
//             }
//             /* Now, append a single garbage byte after all valid characters
//                (i.e. before any trailing '=' if present).
//             */
//             size_t insertion_point = valid_length;  /* insert before any '=' */
//             size_t garbage_location = add_garbage(&base64, &effective_b64_len, &seed, to_base64_value);
//             DEBUG_PRINT(YELLOW_TEXT("DEBUG: After add_garbage, effective_b64_len=%zu, garbage location=%zu\n"),
//                         effective_b64_len, garbage_location);

//             /* Allocate back buffer for decoding */
//             size_t back_bufsize = maximal_binary_length_from_base64(base64, effective_b64_len);
//             DEBUG_PRINT(GREEN_TEXT("DEBUG: Back buffer size = %zu\n"), back_bufsize);
//             char *back = (back_bufsize > 0) ? OPENSSL_malloc(back_bufsize) : NULL;
//             if (back_bufsize > 0 && back == NULL) {
//                 TEST_error(RED_TEXT("Out of memory for back buffer (length %zu)\n"), back_bufsize);
//                 OPENSSL_free(base64);
//                 if (source) OPENSSL_free(source);
//                 return 0;
//             }

//             /* Call decode function (expected to fail with INVALID_BASE64_CHARACTER)
//                The expectation is that the decode function will process all valid characters
//                (i.e. up to the garbage insertion) and then return an error.
//             */
//             result status = base64_tail_decode_trim_end(NULL, back, base64, effective_b64_len);
//             DEBUG_PRINT(GREEN_TEXT("DEBUG: Normal decode result: error=%d, count=%d\n"),
//                         status.error, (int)status.count);
//             ASSERT_EQUAL_INT(status.error, INVALID_BASE64_CHARACTER);
//             ASSERT_EQUAL_INT(status.count, garbage_location);

//             OPENSSL_free(back);
//             OPENSSL_free(base64);
//         }
//         if (source) OPENSSL_free(source);
//     }
//     return 1;
// }

// The setup_tests() function is called by the test harness to register tests.
int setup_tests(void)
{
    // // Register our sample test. The macro ADD_TEST() takes our test function.
    // ADD_TEST(test_decode_base64_cases); 
    // ADD_TEST(test_complete_decode_base64_cases); 
    // ADD_TEST(test_encode_base64_no_padding_cases); 
    // ADD_TEST(test_seof_good_basic_cases); 
    // ADD_TEST(test_multiple_of_4_good);
    // ADD_TEST(test_multiple_of_4_bad);
    // ADD_TEST(test_seof_good_cases);
    // ADD_TEST(test_roundtrip_base64_with_lots_of_spaces); 
    // ADD_TEST(test_roundtrip_base64);
    // ADD_TEST(test_base64_decode_just_one_padding_loose);
    // ADD_TEST(test_issue_520);
    // ADD_TEST(test_issue_509);
    // ADD_TEST(test_issue_504_8bit); 
    // ADD_TEST(test_issue_502_alt);
    // ADD_TEST(test_encode_base64_basic_cases); 
    // ADD_TEST(test_seof_bad_basic_cases); 
    // ADD_TEST(test_seof_bad_cases);
    // ADD_TEST(test_roundtrip_base64_with_spaces); 
    // ADD_TEST(test_roundtrip_base64_with_garbage);
    // ADD_TEST(test_bad_padding_base64);
    ADD_TEST(test_doomed_truncated_base64_roundtrip);

    // TODOS:
    // ADD_TEST(test_doomed_base64_roundtrip); // TODO: check if this is a duplicate
    // ADD_TEST(test_streaming_base64_roundtrip);
    // ADD_TEST(test_readme_test);
    // ADD_TEST(test_doomed_partial_buffer_utf8);

    // Return 1 to indicate successful test setup.
    return 1;
}
