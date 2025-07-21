
// /*
//  * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
//  *
//  * Licensed under the Apache License 2.0 (the "License").  You may not use
//  * this file except in compliance with the License.  You can obtain a copy
//  * in the file LICENSE in the source distribution or at
//  * https://www.openssl.org/source/license.html
//  */

// // Include the test framework header
// #include "testutil.h"
// #include <openssl/evp.h>

// #define DEBUG 0 // Set to 1 to enable debug prints, 0 to disable

// #define BUFMAX 0xa0000          /* Encode at most 640kB. */
// #define RED_TEXT(str)     "\033[31m" str "\033[0m"
// #define GREEN_TEXT(str)   "\033[32m" str "\033[0m"
// #define YELLOW_TEXT(str)  "\033[33m" str "\033[0m"
// #define BLUE_TEXT(str)    "\033[34m" str "\033[0m"
// #define MAGENTA_TEXT(str) "\033[35m" str "\033[0m"
// #define CYAN_TEXT(str)    "\033[36m" str "\033[0m"

// // Standard Colors
// #define BLACK_TEXT(str)   "\033[30m" str "\033[0m"
// #define WHITE_TEXT(str)   "\033[37m" str "\033[0m"

// // Bright Colors
// #define BRIGHT_RED_TEXT(str)     "\033[91m" str "\033[0m"
// #define BRIGHT_GREEN_TEXT(str)   "\033[92m" str "\033[0m"
// #define BRIGHT_YELLOW_TEXT(str)  "\033[93m" str "\033[0m"
// #define BRIGHT_BLUE_TEXT(str)    "\033[94m" str "\033[0m"
// #define BRIGHT_MAGENTA_TEXT(str) "\033[95m" str "\033[0m"
// #define BRIGHT_CYAN_TEXT(str)    "\033[96m" str "\033[0m"
// #define BRIGHT_WHITE_TEXT(str)   "\033[97m" str "\033[0m"


// // Background Colors (Bright)
// #define BRIGHT_BLACK_BG(str)   "\033[100m" str "\033[0m"
// #define BRIGHT_RED_BG(str)     "\033[101m" str "\033[0m"
// #define BRIGHT_GREEN_BG(str)   "\033[102m" str "\033[0m"
// #define BRIGHT_YELLOW_BG(str)  "\033[103m" str "\033[0m"
// #define BRIGHT_BLUE_BG(str)    "\033[104m" str "\033[0m"
// #define BRIGHT_MAGENTA_BG(str) "\033[105m" str "\033[0m"
// #define BRIGHT_CYAN_BG(str)    "\033[106m" str "\033[0m"
// #define BRIGHT_WHITE_BG(str)   "\033[107m" str "\033[0m"

// #define BOLD_TEXT(str)       "\033[1m" str "\033[0m"
// #define UNDERLINE_TEXT(str)  "\033[4m" str "\033[0m"
// #define BLINK_TEXT(str)      "\033[5m" str "\033[0m"  // May not work on all terminals


// #if DEBUG
//     #define DEBUG_PRINT(fmt, ...) \
//         do { \
//             fprintf(stderr, fmt, ##__VA_ARGS__); \
//             fflush(stderr); \
//         } while (0)
// #else
//     #define DEBUG_PRINT(fmt, ...) do {} while (0)
// #endif


// /* Example: ASSERT_EQUAL for integers */
// #define ASSERT_EQUAL_INT(actual, expected) do {                      \
//     if ((actual) != (expected)) {                                      \
//         TEST_error(RED_TEXT("Assertion failed: %s != %s, got %d, expected %d"), \
//                    #actual, #expected, (int)(actual), (int)(expected));\
//         return 0;                                                    \
//     }                                                                \
// } while(0)

// #define ASSERT_NOT_EQUAL_INT(actual, expected) do {                      \
//     if ((actual) == (expected)) {                                      \
//         TEST_error(RED_TEXT("Assertion failed: %s == %s, got %d, didn't want %d"), \
//                    #actual, #expected, (int)(actual), (int)(expected));\
//         OPENSSL_free(buffer);                                                    \
//         return 0;                                                    \
//     }                                                                \
// } while(0)

// /* Macro with an extra message */
// #define ASSERT_EQUAL_INT_MSG(actual, expected, msg) do {                   \
//     if ((actual) != (expected)) {                                          \
//         TEST_error(RED_TEXT("Assertion failed: %s != %s, got %d, expected %d. %s"), \
//                    #actual, #expected, (int)(actual), (int)(expected), msg);  \
//         return 0;                                                        \
//     }                                                                    \
// } while(0)

// /* ASSERT_EQUAL for size_t values */
// #define ASSERT_EQUAL_SIZE(actual, expected) do {                     \
//     if ((actual) != (expected)) {                                      \
//         TEST_error(RED_TEXT("Assertion failed: %s != %s, got %zu, expected %zu"), \
//                    #actual, #expected, (actual), (expected));         \
//         return 0;                                                    \
//     }                                                                \
// } while(0)

// /* ASSERT_EQUAL_HEX: for comparing two byte values with an index context */
// #define ASSERT_EQUAL_HEX(idx, actual, expected) do {                 \
//     if ((unsigned int)(actual) != (unsigned int)(expected)) {          \
//         TEST_error(RED_TEXT("Mismatch at index %zu: got %02x, expected %02x"), \
//                    (idx), (unsigned int)(actual), (unsigned int)(expected)); \
//         return 0;                                                    \
//     }                                                                \
// } while(0)

// #define ASSERT_TRUE(cond) do {                        \
//     if (!(cond)) {                                    \
//         TEST_error(RED_TEXT("Assertion failed: %s is false at %s:%d"), \
//                    #cond, __FILE__, __LINE__);          \
//         return 0;                                   \
//     }                                               \
// } while(0)

// #define PRINT_STRINGS(expected, actual, len) do {                         \
//     size_t _i;                                                            \
//     /* Print as regular strings */                                        \
//     printf("Expected buffer (%s) as string: \"%s\"\n", #expected, (expected)); \
//     printf("Actual buffer   (%s) as string: \"%s\"\n", #actual, (actual));   \
//     /* Print as hexadecimal */                                            \
//     printf("Expected buffer (%s) as hex: ", #expected);                    \
//     for (_i = 0; _i < (len); _i++) {                                       \
//         printf("%02x ", (unsigned int)(expected)[_i]);                    \
//     }                                                                     \
//     printf("\n");                                                         \
//     printf("Actual buffer   (%s) as hex: ", #actual);                      \
//     for (_i = 0; _i < (len); _i++) {                                       \
//         printf("%02x ", (unsigned int)(actual)[_i]);                      \
//     }                                                                     \
//     printf("\n");                                                         \
// } while(0)


// #define ASSERT_MEM_EQUAL(expected, actual, len) do {                         \
//     size_t _i, _mismatch_index = (size_t)(-1);                               \
//     for (_i = 0; _i < (len); _i++) {                                         \
//         if ((expected)[_i] != (actual)[_i]) {                                \
//             _mismatch_index = _i;                                            \
//             break;                                                         \
//         }                                                                    \
//     }                                                                        \
//     if (_mismatch_index != (size_t)(-1)) {                                   \
//         printf("Memory mismatch detected:\n");                             \
//         printf("Expected buffer:\n");                                         \
//         for (_i = 0; _i < (len); _i++) {                                     \
//             printf("%02x ", (unsigned int)(expected)[_i]);                   \
//             if ((_i + 1) % 9 == 0) printf("\n");                           \
//         }                                                                    \
//         if (_i % 9) printf("\n");                                          \
//         printf("Actual buffer:\n");                                      \
//         for (_i = 0; _i < (len); _i++) {                                     \
//             printf("%02x ", (unsigned int)(actual)[_i]);                     \
//             if ((_i + 1) % 9 == 0) printf("\n");                           \
//         }                                                                    \
//         if (_i % 9) printf("\n");                                          \
//         printf("Memory mismatch at index %zu: got %02x, expected %02x\n",     \
//                _mismatch_index,                                              \
//                (unsigned int)(actual)[_mismatch_index],                      \
//                (unsigned int)(expected)[_mismatch_index]);                   \
//         return 0;                                                            \
//         }                                                                        \
//     } while(0)




// size_t base64_length_from_binary(size_t length) {
//     return (length + 2)/3 * 4; // We use padding to make the length a multiple of 4.
//   }

// int EVP_DecodeUpdate_test(EVP_ENCODE_CTX *ctx,
//     const unsigned char *in, int inl, int expected_outl) {

//     /* Create new contexts if needed */
//     EVP_ENCODE_CTX *simdutf_ctx = ctx ? ctx : EVP_ENCODE_CTX_new();
//     EVP_ENCODE_CTX *openssl_ctx = ctx ? ctx : EVP_ENCODE_CTX_new();

//     if (!simdutf_ctx || !openssl_ctx) {
//         EVP_ENCODE_CTX_free(simdutf_ctx);
//         EVP_ENCODE_CTX_free(openssl_ctx);
//         return -1;
//     }

//     /* Calculate how much of the input to process now */
//     size_t cut_len = inl;
//     /* Process random amount up to 64 bytes, leaving remainder in context */
//     unsigned int seed = 12345;
//     cut_len = rand_r(&seed) % (64 + 1); 

//     if (!simdutf_ctx || !openssl_ctx) {
//         EVP_ENCODE_CTX_free(simdutf_ctx);
//         EVP_ENCODE_CTX_free(openssl_ctx);
//         return -1;
//     }
//     // Allocate separate buffers for each decoder
//     unsigned char *decodeUpdate_openssl = OPENSSL_malloc(inl + 2);
//     unsigned char *decodeUpdate_simdutf = OPENSSL_malloc(inl + 2);
//     if (!decodeUpdate_openssl || !decodeUpdate_simdutf) {
//         OPENSSL_free(decodeUpdate_openssl);
//         OPENSSL_free(decodeUpdate_simdutf);
//         return -1;
//     }

//     int decodeUpdate_outl_openssl = 0;
//     int decodeUpdate_outl_simdutf = 0;



//     // TODO:: It seemed that OpenSSL treats 0x00 (null byte) as a EOF
//     // By accident (+1 error), I ran  over the intended strings unto a null byte. 
//     // A null terminated string should return 0, and not 1. 
//     // for (int process_len = 0; process_len <= 64 && process_len < inl; process_len++) {
//         size_t process_len = 0;

//         /* Store processed data in context */
//         DEBUG_PRINT(GREEN_TEXT("DEBUG: Storing %zu bytes in context\n"), process_len);

//         #if DEBUG
//             DEBUG_PRINT(YELLOW_TEXT("DEBUG: Highlighting character at process_len: %02x"), in[process_len]);
//             DEBUG_PRINT("\n");
//             DEBUG_PRINT("Source data (first few bytes):\n");
//             for (size_t i = 0; i <= inl; i++) {
//                 if (i == process_len) {
//                     DEBUG_PRINT(BRIGHT_RED_BG("%02x "), in[i]);
//                 } else {
//                     DEBUG_PRINT("%02x ", in[i]); 
//                 }
//             }
//             DEBUG_PRINT("\nAs string: ");
//             for (size_t i = 0; i <= inl; i++) {
//                 if (i == process_len) {
//                     if (isprint(in[i])) {
//                         DEBUG_PRINT(BRIGHT_RED_BG("%c"), in[i]);
//                     } else {
//                         DEBUG_PRINT(BRIGHT_RED_BG("."));
//                     }
//                 } else {
//                     if (isprint(in[i])) {
//                         DEBUG_PRINT("%c", in[i]);
//                     } else {
//                         DEBUG_PRINT(".");
//                     }
//                 }
//             }
//             DEBUG_PRINT("\n");
//         #endif


//         set_evp_encode_ctx(simdutf_ctx,  process_len,48, 0, 0, in, process_len);
//         set_evp_encode_ctx(openssl_ctx,  process_len,48, 0, 0, in, process_len);

//         // Run both decoders
//         int decodeUpdate_ret_openssl = EVP_DecodeUpdate_OpenSSL(openssl_ctx, decodeUpdate_openssl, &decodeUpdate_outl_openssl, in + process_len, inl - process_len);
//         int decodeUpdate_ret_simdutf = EVP_DecodeUpdate_simdutf(simdutf_ctx, decodeUpdate_simdutf, &decodeUpdate_outl_simdutf, in + process_len, inl - process_len);

//         // // Compare results
//         // ASSERT_EQUAL_INT(decodeUpdate_outl_openssl, decodeUpdate_outl_simdutf);
//         ASSERT_EQUAL_INT(decodeUpdate_ret_openssl, decodeUpdate_ret_simdutf);
//         ASSERT_MEM_EQUAL(decodeUpdate_openssl, decodeUpdate_simdutf, decodeUpdate_outl_openssl);

//         /* Compare contexts */
//         // ASSERT_TRUE(EVP_ENCODE_CTX_cmp(simdutf_ctx, openssl_ctx));
//     // }

//     // Clean up
//     OPENSSL_free(decodeUpdate_openssl);
//     OPENSSL_free(decodeUpdate_simdutf);

//     EVP_ENCODE_CTX_free(simdutf_ctx);
//     EVP_ENCODE_CTX_free(openssl_ctx);

//     return 1;
// }

// const static uint8_t to_base64_value[] = {
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 64,  64,  255, 64, 64,  255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 64,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,  255,
//     255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255,
//     255, 255, 255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
//     10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
//     25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,
//     34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
//     49,  50,  51,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
//     255};


// static int test_roundtrip_base64(void) {
//     size_t len, trial, i;
//     unsigned int seed = 12345;  /* Fixed seed for reproducibility */
//     DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64\n"));
//     printf("test");

//     for (len = 0; len < 2048; len++) {
//         DEBUG_PRINT(BRIGHT_CYAN_TEXT("************DEBUG: Processing length = %zu\n"), len);

//         /* Allocate source binary data */
//         char *source = (len > 0) ? OPENSSL_malloc(len) : OPENSSL_malloc(1);
//         if (len > 0 && !source) {
//             TEST_error("Out of memory for source of length %zu", len);
//             return 0;
//         }
//         /* Fill source with random bytes */
//         for (i = 0; i < len; i++) {
//             source[i] = (char)(rand_r(&seed) % 256);
//         }
//         if (len > 0) {
//             DEBUG_PRINT("DEBUG: Source data allocated (first 10 bytes):");
//             for (i = 0; i < len && i < 10; i++) {
//                 DEBUG_PRINT(" %02x", (unsigned char)source[i]);
//             }
//             DEBUG_PRINT("\n");
//         }

//         /* Allocate buffer for Base64 conversion */
//         size_t b64_len_expected = base64_length_from_binary(len);
//         DEBUG_PRINT("DEBUG: Expected Base64 length = %zu\n", b64_len_expected);
//         char *buffer = OPENSSL_malloc(b64_len_expected + 1);
//         if (!buffer) {
//             TEST_error("Out of memory for Base64 buffer for length %zu", len);
//             if (source) OPENSSL_free(source);
//             return 0;
//         }
//         size_t s = tail_encode_base64(NULL, buffer, source, len);
//         buffer[s] = '\0';
//         DEBUG_PRINT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n", s, buffer);


//         /* Allocate buffer for decoded binary data */
//         size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
//         DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);

//         /* **** simdutf decoding **** */
//         unsigned char *back_simd = OPENSSL_malloc(back_bufsize);
//         if (back_bufsize != 0 && back_simd == NULL) {
//             TEST_error("Out of memory for simdutf back buffer");
//             OPENSSL_free(source);
//             OPENSSL_free(buffer);
//             return 0;
//         }

//         int outlen_simdutf = 0;
//         int result_simdutf = simdutf_decode(NULL, (char *)back_simd, &outlen_simdutf, buffer, s);
//         DEBUG_PRINT("DEBUG: Decoded binary length simdutf = %d\n", result_simdutf);
//         for (int j = 0; j < len; j++) {
//             ASSERT_EQUAL_HEX(j, back_simd[j], (unsigned char)source[j]);
//         }
//         DEBUG_PRINT("DEBUG: Source and decoded data match for simdutf for length %zu\n", len);

//         /* **** OpenSSL decoding **** */
//         // NOTE: OpenSSL's base64 decoder differs slightly from the one used in simdutf.
//         // Whereas simdutf's will write just the right amount of data, OpenSSL's will
//         // always write by chunks of 3 bytes, even if the last chunk is not full.
//         // hence the +2 in the malloc below.
//         unsigned char *back_openssl = OPENSSL_malloc(back_bufsize +2);
//         // back_openssl[back_bufsize] = '\0';
//         if (back_bufsize != 0 && back_openssl == NULL) {
//             TEST_error("Out of memory for OpenSSL back buffer");
//             OPENSSL_free(source);
//             OPENSSL_free(buffer);
//             OPENSSL_free(back_simd);
//             return 0;
//         }
//         int outlen_openssl = 0;
//         int result_openssl = OpenSSL_decode(NULL, (char *)back_openssl, &outlen_openssl, buffer, s);
//         DEBUG_PRINT("DEBUG: Decoded binary length openssl = %d\n", result_openssl);
//         for (int j = 0; j < len; j++) {
//             ASSERT_EQUAL_HEX(j, back_openssl[j], (unsigned char)source[j]);
//         }
//         DEBUG_PRINT("DEBUG: Source and decoded data match for OpenSSL for length %zu\n", len);

//         /* Specific assertions comparing the two decoders */
//         ASSERT_EQUAL_INT(result_openssl, result_simdutf);
//         ASSERT_EQUAL_SIZE(outlen_openssl, outlen_simdutf);

//         ASSERT_MEM_EQUAL(back_openssl, back_simd, outlen_openssl);

//         ASSERT_EQUAL_INT(result_openssl, len);

//         OPENSSL_free(source);
//         OPENSSL_free(back_simd);
//         OPENSSL_free(back_openssl);

//         int e = EVP_DecodeUpdate_test(NULL, buffer, s, NULL);
//         OPENSSL_free(buffer);
//         if (e != 1) {
//             return 0;
//         }
//     }
//     return 1;
// }

// int setup_tests(void)
// {

//     ADD_TEST(test_roundtrip_base64);


//     // Return 1 to indicate successful test setup.
//     return 1;
// }

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



static int test_hello(void)
{
    TEST_info("Hello, OpenSSL test framework!");
    return 1;  // success
}



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
    // ADD_TEST(test_hello);
    ADD_TEST(test_encode_line_lengths);
    // ADD_TEST(test_encode_line_lengths);
    return 1;
}
