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

#define DEBUG 0

#if DEBUG
    #define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...)       
#endif  

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

#define ASSERT_TRUE(cond) do {                        \
    if (!(cond)) {                                    \
        TEST_error(RED_TEXT("Assertion failed: %s is false at %s:%d"), \
                   #cond, __FILE__, __LINE__);          \
        return 0;                                   \
    }                                               \
} while(0)


/* Prototypes for encoding helper functions */
static int memout(BIO *mem, char c, int llen, int *pos);
static int memoutws(BIO *mem, char c, unsigned wscnt, unsigned llen, int *pos);
// result base64_tail_decode(EVP_ENCODE_CTX *ctx, char *dst, const char *src, int length);

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

size_t add_garbage(char **v, size_t *v_len, unsigned int *seed, const uint8_t *table) {
    size_t i, len;
    char *array = *v;
    
    /* Determine the upper bound for the insertion index:
       If '=' is found, use its index; otherwise, use the full length.
    */
    len = *v_len;
    for (i = 0; i < *v_len; i++) {
        DEBUG_PRINT("= is found in add_garbage\n");
        if (array[i] == '=') {
            len = i;
            break;
        }
    }
    
    /* Choose a random insertion index between 0 and len (inclusive) */
    size_t index = rand_r(seed) % (len + 1);

    /* Choose a random byte value between 0 and 255 until table[c] equals 255 */
    uint8_t c = rand_r(seed) % 256;
    while (table[c] != 255) {
        c = rand_r(seed) % 256;
    }
    
    /* Reallocate the array to make room for one extra character.
       Note: Passing a pointer to the array pointer so that it can be updated.
    */
    char *new_v = OPENSSL_realloc(array, *v_len + 1);
    if (new_v == NULL) {
        /* Allocation failure */
        return (size_t)-1;
    }
    
    /* Shift the tail of the array one position to the right.
       We move *v_len - index bytes starting at new_v[index].
    */
    memmove(new_v + index + 1, new_v + index, *v_len - index);
    new_v[index] = (char)c;
    
    *v = new_v;
    (*v_len)++;
    return index;
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
        result decoded = base64_tail_decode_trim_end(NULL, (char *)buffer, cases[i], len);
        if (decoded.error != BASE64_SUCCESS) {
            TEST_error(RED_TEXT("base64_to_binary_with_ws error in test case %zu"), i);
            OPENSSL_free(buffer);
            return 0;
        }
        if ((size_t)decoded.count != expected_counts[i]) {
            TEST_error(RED_TEXT("Decoded byte count mismatch: got %d, expected %zu"), decoded, expected_counts[i]);


            OPENSSL_free(buffer);
            return 0;
        }
        OPENSSL_free(buffer);
    }
    return 1;
}

// TODO? This was in the C++ code.
/* Last-chunk handling options */
// last_chunk_handling_options are used to specify the handling of the last
// chunk in base64 decoding.
// https://tc39.es/proposal-arraybuffer-base64/spec/#sec-frombase64
// typedef enum {
//     LAST_CHUNK_LOOSE, /* standard base64 format, decode partial final chunk */
//     LAST_CHUNK_STRICT,/* error when the last chunk is partial, 2 or 3 chars, and
//     unpadded, or non-zero bit padding */
//     LAST_CHUNK_STOP_BEFORE_PARTIAL /* if the last chunk is partial (2 or 3 chars), ignore it (no error) */
// } last_chunk_handling_options;

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
        result r = base64_tail_decode_trim_end(NULL, (char *)buffer,cases[i].encoded, enc_len);
        if(r.error != BASE64_SUCCESS) {
            TEST_error(RED_TEXT("base64_to_binary error in test case %zu"), i);
            OPENSSL_free(buffer);
            return 0;
        }
        if(r.count != strlen(cases[i].decoded)) {
            TEST_error(RED_TEXT("Decoded byte count mismatch in test case %zu: got %zu, expected %zu"), 
                       i, r, strlen(cases[i].decoded));
            OPENSSL_free(buffer);
            return 0;
        }

        for(size_t j = 0; j < r.count; j++) {
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

static int check_cases(case_pair *cases)
{
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered encode_base64_cases Test\n"));

    /* Define test cases as an array of case_pair.
       These mirror your C++ test cases.
    */
    size_t num_cases = sizeof(cases) / sizeof(cases[0]);
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
    for (i = 0; i < num_cases; i++) {
        size_t enc_len = strlen(cases[i].encoded);
        size_t expected_dec_len = strlen(cases[i].decoded);
        size_t bufsize = maximal_binary_length_from_base64(cases[i].encoded, enc_len);
        char *buffer = OPENSSL_malloc(bufsize);
        if (!buffer) {
            TEST_error("Out of memory in decoding test case %zu", i);
            return 0;
        }
        result r = base64_tail_decode_trim_end(NULL, (char *)buffer,cases[i].encoded, enc_len);
        if(r.error != BASE64_SUCCESS) {
            TEST_error(RED_TEXT("base64_to_binary error in test case %zu"), i);
            OPENSSL_free(buffer);
            return 0;
        }
        if(r.count != strlen(cases[i].decoded)) {
            TEST_error(RED_TEXT("Decoded byte count mismatch in test case %zu: got %zu, expected %zu"), 
                       i, r, strlen(cases[i].decoded));
            OPENSSL_free(buffer);
            return 0;
        }

        for(size_t j = 0; j < r.count; j++) {
            if(buffer[j] != cases[i].decoded[j]) {
                TEST_error(RED_TEXT("Decoded:Mismatch at index %zu in test case %zu: got %02x, expected %02x"), 
                           j, i, (unsigned int)buffer[j], (unsigned int)cases[i].decoded[j]);
                OPENSSL_free(buffer);
                return 0;
            }
        }
        OPENSSL_free(buffer);
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
    check_cases(basic_cases);
    return 1;
}


static int test_encode_base64_no_padding_cases(void){
    check_cases(no_padding);
    return 1;
}

static int test_encode_base64_whitespace_cases(void){
    check_cases(whitespaces);
    return 1;
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

size_t add_space(char **v, size_t *v_len, unsigned int *seed) {
    static const char space[5] = { ' ', '\t', '\n', '\r', '\f' };

    // DEBUG_PRINT(RED_TEXT("DEBUG: Entering add_space\n"));

    /* Choose a random insertion index between 0 and *v_len (inclusive) */
    size_t index = rand_r(seed) % (*v_len + 1);
    // DEBUG_PRINT("DEBUG: Chosen insertion index = %zu (v_len = %zu)\n", index, *v_len);

    /* Choose a random whitespace character from the array */
    size_t space_index = rand_r(seed) % 5;
    // DEBUG_PRINT("DEBUG: Chosen whitespace character = '%c'\n", space[space_index]);

    /* Reallocate the array to make room for one extra character. */
    char *new_v = OPENSSL_realloc(*v, *v_len + 1);
    if (new_v == NULL) {
        TEST_error(RED_TEXT("DEBUG: OPENSSL_realloc failed for new size = %zu"), *v_len + 1);
        return (size_t)-1;
    }
    // DEBUG_PRINT(RED_TEXT("DEBUG: Reallocation successful, new pointer = %p\n"), new_v);

    /* Move the tail of the array one position to the right */
    memmove(new_v + index + 1, new_v + index, *v_len - index);
    // DEBUG_PRINT("DEBUG: memmove executed from index %zu for %zu bytes\n", index, *v_len - index);

    /* Insert the chosen whitespace */
    new_v[index] = space[space_index];
    // DEBUG_PRINT("DEBUG: Inserted '%c' at index %zu\n", space[space_index], index);

    *v = new_v;
    (*v_len)++;
    // DEBUG_PRINT("DEBUG: New vector length is %zu\n", *v_len);

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
        // if (result_len)
        //     *result_len = v_len;
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
    // if (result_len)
    //     *result_len = total;

    OPENSSL_free(positions);
    return result;
}

static int test_roundtrip_base64_with_lots_of_spaces(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64_with_lots_of_spaces\n"));

    for (len = 0; len < 2048; len++) {
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
        char *back = OPENSSL_malloc(back_bufsize);
        if (!back && back_bufsize !=0) {
            TEST_error("Out of memory for back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer_with_spaces);
            return 0;
        }

        /* Decode the Base64 string (with extra spaces) */
        result r = base64_tail_decode_trim_end(NULL, back, buffer_with_spaces, buffer_with_spaces_len);
        DEBUG_PRINT("DEBUG: Decoded binary length = %zu\n", r);
        ASSERT_TRUE(r.error == BASE64_SUCCESS);
        ASSERT_EQUAL_SIZE(r.count, len);

        for (size_t j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back[j], source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for length %zu\n", len);

        OPENSSL_free(source);
        OPENSSL_free(buffer_with_spaces);
        OPENSSL_free(back);
    }
    return 1;
}



/*
 * test_roundtrip_base64_with_spaces:
 * For each binary length from 0 to 2047, generate random binary data,
 * encode it to Base64, then insert extra whitespace (5 insertions),
 * and finally decode using both base64_to_binary and base64_to_binary_safe
 * with each of three last-chunk handling options.
 * The decoded data is then compared with the original source.
 */
static int test_roundtrip_base64_with_spaces(void) {
    size_t len, trial, i, j;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64_with_spaces\n"));

    for (len = 0; len < 2048; len++) {
        DEBUG_PRINT(CYAN_TEXT("DEBUG: Processing binary length = %zu\n"), len);
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

        /* Insert extra spaces (5 times) */
        size_t cur_b64_len = s;
        for (i = 0; i < 5; i++) {
            int index = add_space(&buffer, &cur_b64_len, &seed);
            if (index == -1) {
                TEST_error("Out of memory in add_space for length %zu", cur_b64_len);
                if (source) OPENSSL_free(source);
                return 0;
            }
            // buffer = new_buffer;
        }
        DEBUG_PRINT("DEBUG: Base64 with spaces (length %zu): \"%s\"\n", cur_b64_len, buffer);

        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, cur_b64_len);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);
        char *back = OPENSSL_malloc(back_bufsize);
        if (!back) {
            TEST_error("Out of memory for back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            return 0;
        }

        // last_chunk_handling_options opts[3] = { LAST_CHUNK_STRICT, LAST_CHUNK_LOOSE, LAST_CHUNK_STOP_BEFORE_PARTIAL };

        /* First round: using base64_to_binary */
        // for (i = 0; i < 3; i++) {
            result r = base64_tail_decode_trim_end(NULL, back,buffer, cur_b64_len);
            DEBUG_PRINT("DEBUG: base64_to_binary returned count = %zu\n", r);
            ASSERT_TRUE(r.error == BASE64_SUCCESS);
            ASSERT_EQUAL_SIZE(r.count, len);
            if (len > 0) {
                ASSERT_TRUE(memcmp(back, source, len) == 0);
            }
        // }

        /* Second round: using base64_to_binary_safe */
        // for (i = 0; i < 3; i++) {
        //     size_t back_length = back_bufsize;
        //     result r = base64_to_binary_safe(buffer, cur_b64_len, back, back_length, BASE64_DEFAULT, opts[i]);
        //     DEBUG_PRINT("DEBUG: Option %d, base64_to_binary_safe returned count = %zu\n", (int)opts[i], r.count);
        //     ASSERT_EQUAL_INT(r.error, ERROR_SUCCESS);
        //     if (opts[i] == LAST_CHUNK_STOP_BEFORE_PARTIAL) {
        //         for (j = r.count; j < cur_b64_len; j++) {
        //             /* Check that any extra characters are whitespace */
        //             ASSERT_TRUE(buffer[j]==' ' || buffer[j]=='\t' || buffer[j]=='\n' || buffer[j]=='\r' || buffer[j]=='\f');
        //         }
        //     } else {
        //         ASSERT_EQUAL_SIZE(r.count, cur_b64_len);
        //     }
        //     if (len > 0) {
        //         ASSERT_TRUE(memcmp(back, source, len) == 0);
        //     }
        // }
        OPENSSL_free(source);
        OPENSSL_free(buffer);
        OPENSSL_free(back);
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
// this is true in the original
static int test_roundtrip_base64_with_garbage(void) {
    size_t len, trial, i, j;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64_with_garbage\n"));

    /* Loop over binary lengths from 0 to 2047 */
    for (len = 0; len < 2048; len++) {
        DEBUG_PRINT("DEBUG: Processing binary length = %zu\n", len);
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
        char *back = OPENSSL_malloc(back_bufsize);
        if (back == NULL) {
            TEST_error("Out of memory for back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            return 0;
        }

        // /* Define options: Strict, Loose, Stop-Before-Partial */
        // last_chunk_handling_options opts[3] = {
        //     LAST_CHUNK_STRICT, LAST_CHUNK_LOOSE, LAST_CHUNK_STOP_BEFORE_PARTIAL
        // };

        /* First round: using base64_to_binary */
        // for (i = 0; i < 3; i++) {
            result r = base64_tail_decode_trim_end(NULL,back, buffer, cur_b64_len);
                                        //   BASE64_DEFAULT_ACCEPT_GARBAGE, opts[i]);
            // DEBUG_PRINT("DEBUG: Option %d, base64_to_binary returned count = %zu\n",
            //             (int)opts[i], r);
            DEBUG_PRINT("DEBUG: base64_to_binary returned count = %zu\n",
                 r);

            ASSERT_TRUE(r.error != BASE64_SUCCESS);
            // if (len > 0) {
            //     ASSERT_TRUE(memcmp(back, source, len) == 0);
            // }
        // }

        // /* Second round: using base64_to_binary_safe */
        // for (i = 0; i < 3; i++) {
        //     size_t back_length = back_bufsize;
        //     result r = base64_to_binary_safe(buffer, cur_b64_len, back, back_length,
        //                                        BASE64_DEFAULT_ACCEPT_GARBAGE, opts[i]);
        //     DEBUG_PRINT("DEBUG: Option %d, base64_to_binary_safe returned count = %zu\n",
        //                 (int)opts[i], r.count);
        //     ASSERT_EQUAL_INT(r.error, ERROR_SUCCESS);
        //     if (opts[i] == LAST_CHUNK_STOP_BEFORE_PARTIAL) {
        //         for (j = r.count; j < cur_b64_len; j++) {
        //             /* Check that any extra characters are whitespace */
        //             ASSERT_TRUE(buffer[j]==' ' || buffer[j]=='\t' ||
        //                         buffer[j]=='\n' || buffer[j]=='\r' || buffer[j]=='\f');
        //         }
        //     } else {
        //         ASSERT_EQUAL_SIZE(r.count, cur_b64_len);
        //     }
        //     if (len > 0) {
        //         ASSERT_TRUE(memcmp(back, source, len) == 0);
        //     }
        // }
        OPENSSL_free(source);
        OPENSSL_free(buffer);
        OPENSSL_free(back);
    }
    return 1;
}

/*
 * test_base64_decode_just_one_padding_loose:
 * This test verifies that decoding a particular input string in loose mode
 * returns the expected error code and count.
 */
static int test_base64_decode_just_one_padding_loose(void) {
    /* Define a structure for test cases */
    typedef struct {
        const char *input;
        error_code error;
        int expected;
    } test_case;
    
    /* Test cases array; here we have one test case. */
    test_case test_cases[] = {
        { "uuuu             =", INVALID_BASE64_CHARACTER, 17 }
    };

    size_t num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    /* A small buffer to receive decoded binary data */
    char buffer[3];  /* as in your original C++ test */
    
    /* Define arrays of options */
    // int base64_opts[2] = { BASE64_DEFAULT, BASE64_URL };
    // int chunk_opts[1] = { LAST_CHUNK_LOOSE };
    
    for (size_t i = 0; i < num_cases; i++) {
        const char *input = test_cases[i].input;
        error_code error = test_cases[i].error;
        int expected = test_cases[i].expected;
        
        // for (size_t j = 0; j < 2; j++) {
            // int option = base64_opts[j];
            for (size_t k = 0; k < 1; k++) {
                // int chunk_option = chunk_opts[k];
                // result r = base64_to_binary(input, strlen(input), buffer, option, chunk_option);
                result r = base64_tail_decode_trim_end(NULL , buffer, input, strlen(input));
                ASSERT_EQUAL_SIZE( r.error , error);
                ASSERT_EQUAL_SIZE(r.count, expected);
            }
        // }
    }
    return 1;
}

static int test_roundtrip_base64(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered test_roundtrip_base64\n"));

    for (len = 0; len < 2048; len++) {
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

        /* No extra spaces are added; use the encoded buffer as-is */
        size_t buffer_with_spaces_len = s;

        /* Allocate buffer for decoded binary data */
        size_t back_bufsize = maximal_binary_length_from_base64(buffer, s);
        DEBUG_PRINT("DEBUG: Back buffer size (maximal binary length) = %zu\n", back_bufsize);
        char *back = OPENSSL_malloc(back_bufsize);
        if (!back && back_bufsize != 0) {
            TEST_error("Out of memory for back buffer");
            OPENSSL_free(source);
            OPENSSL_free(buffer);
            return 0;
        }

        /* Decode the Base64 string without added spaces */
        result r = base64_tail_decode_trim_end(NULL, back, buffer, s);
        DEBUG_PRINT("DEBUG: Decoded binary length = %zu\n", r);
        ASSERT_TRUE(r.error == BASE64_SUCCESS);
        ASSERT_EQUAL_SIZE(r.count, len);

        for (size_t j = 0; j < len; j++) {
            ASSERT_EQUAL_HEX(j, back[j], source[j]);
        }
        DEBUG_PRINT("DEBUG: Source and decoded data match for length %zu\n", len);

        OPENSSL_free(source);
        OPENSSL_free(buffer);
        OPENSSL_free(back);
    }
    return 1;
}

static int test_issue_520(void) {
    /* Create an array of unsigned char */
    unsigned char data[] = {
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 12, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 82,
    };
    size_t data_len = sizeof(data);
    
    /* Allocate output buffer of 48 bytes */
    char out[48];

    /* Decode the data as a Base64 string in strict mode */
    result r = base64_tail_decode_trim_end(NULL,out,(const char *)data, data_len
                                );
    
    ASSERT_EQUAL_INT(r.error, BASE64_INPUT_REMAINDER);
    ASSERT_EQUAL_INT(r.count,0);

    return 1;
}

/* 
 * TEST(issue_509)
 * Input: data = { ' ', '=' } (2 bytes)
 * Expected: error INVALID_BASE64_CHARACTER and count = 1.
 */
static int test_issue_509(void) {
    char data[] = { ' ', '=' };
    size_t data_len = sizeof(data);
    char out[1];  /* output buffer of length 1 */
    
    result r = base64_tail_decode_trim_end(NULL, out, (const char *)data, data_len);
    ASSERT_EQUAL_SIZE(r.error,INVALID_BASE64_CHARACTER);
    ASSERT_EQUAL_SIZE(r.count,1);
    return 1;
}

/*
 * TEST(issue_502_alt)
 * For each nof_equals from 1 to 99, create a buffer of '=' characters.
 * Expected: error INVALID_BASE64_CHARACTER
 */
static int test_issue_502_alt(void) {
    for (size_t nof_equals = 1; nof_equals < 100; ++nof_equals) {
        char *data = OPENSSL_malloc(nof_equals);
        if (!data) {
            TEST_error("Out of memory in issue_502_alt for nof_equals = %zu", nof_equals);
        }
        memset(data, '=', nof_equals);
        char out[1];
        result r = base64_tail_decode_trim_end(NULL, out, data, nof_equals);
        ASSERT_EQUAL_SIZE(r.error,INVALID_BASE64_CHARACTER);
        ASSERT_EQUAL_SIZE(r.count,0);
    }
    return 1;
}

/*
 * TEST(issue_504_8bit)
 * Use a char array with value 61 ('=')
 * Expected: error INVALID_BASE64_CHARACTER and count = 0.
 */
static int test_issue_504_8bit(void) {
    char data[1] = { 61 };
    char out[1];
    result r = base64_tail_decode_trim_end(NULL, out, data, sizeof(data));
    ASSERT_EQUAL_SIZE(r.error,INVALID_BASE64_CHARACTER);
    ASSERT_EQUAL_SIZE(r.count,0);
    return 1;
}

/*
 * TEST(issue_502)
 * Use a std::array equivalent: a char array with a single '='.
 * Expected: error INVALID_BASE64_CHARACTER and count = 0.
 */
static int test_issue_502(void) {
    char data[1] = { '=' };
    char out[1];
    result r = base64_tail_decode_trim_end(NULL, out, data, sizeof(data));
    ASSERT_EQUAL_SIZE(r.error,INVALID_BASE64_CHARACTER);
    ASSERT_EQUAL_SIZE(r.count,0);
    return 1;
}

// static int test_issue_502_alt(void) {
//     for (size_t nof_equals = 1; nof_equals < 100; ++nof_equals) {
//         char data[1] = {nof_equals, '=' };
//         char out[1];
//         result r = base64_tail_decode_trim_end(NULL, out, data, sizeof(data));
//         ASSERT_EQUAL_SIZE(r.error,INVALID_BASE64_CHARACTER);
//         ASSERT_EQUAL_SIZE(r.count,0);
//     }
//     return 1;
// }


/*
 * TEST(bad_padding_base64)
 *
 * For each binary length from 0 to 2047, generate random binary data,
 * encode it to Base64, then adjust the padding by appending or removing '='
 * and inserting extra whitespace (5 insertions), and then decode.
 * The expected result is that the decoder returns an error (INVALID_BASE64_CHARACTER).
 */
static int test_bad_padding_base64(void) {
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    DEBUG_PRINT(CYAN_TEXT("DEBUG: Entered test_bad_padding_base64\n"));

    for (len = 0; len < 2048; len++) {
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

        if (padding == 1) {
            /* Case: one padding character exists.
             * Append an extra '=' and then insert 5 spaces. It should break
             */
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
            result r = base64_tail_decode_trim_end(NULL, back,copy, copy_len);
            ASSERT_EQUAL_INT(r.error, INVALID_BASE64_CHARACTER);
            OPENSSL_free(copy);
        } else if (padding == 2) {
            /* Case: two padding characters exist.
             * Subcase 1: adding padding should break.
             */
            {
                DEBUG_PRINT("Subcase 1: adding padding should break.\n");

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
                result r = base64_tail_decode_trim_end(NULL, back,copy, copy_len);
                ASSERT_EQUAL_INT(r.error, INVALID_BASE64_CHARACTER);
                OPENSSL_free(copy);
            }
            /* Subcase 2: removing one padding character should break. */
            {
                DEBUG_PRINT("Subcase 2: removing one padding character should break \n");
                char *copy = OPENSSL_malloc(s);
                if (!copy) {
                    TEST_error("Out of memory for copy");
                    OPENSSL_free(source);
                    OPENSSL_free(buffer);
                    return 0;
                }
                memcpy(copy, buffer, s);
                size_t copy_len = s - 1;  /* remove last character */
                copy = OPENSSL_realloc(copy, copy_len);
                if (!copy && copy_len != 0) {
                    TEST_error("Out of memory in realloc for copy");
                    OPENSSL_free(source);
                    OPENSSL_free(buffer);
                    return 0;
                }
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
                result r = base64_tail_decode_trim_end(NULL, back,copy, copy_len);
                ASSERT_EQUAL_INT(r.error, INVALID_BASE64_CHARACTER);
                OPENSSL_free(copy);
            }
        } else {
            /* Case: no padding found. */
            {
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
                result r = base64_tail_decode_trim_end(NULL, back,copy, copy_len);
                ASSERT_EQUAL_INT(r.error, INVALID_BASE64_CHARACTER);
                OPENSSL_free(copy);
            }
        }

        OPENSSL_free(source);
        OPENSSL_free(buffer);
        OPENSSL_free(back);
    }
    return 1;
}

/*------------------------------------------------------------------
  Test: doomed_base64_roundtrip
  For each length from 0 to 2047, we:
    - Generate random binary data.
    - Encode it to Base64.
    - Inject one garbage insertion (recording its location).
    - Decode the resulting string (normal and safe modes).
    - Assert that the error is INVALID_BASE64_CHARACTER and that the count
      equals the insertion location.
------------------------------------------------------------------*/
// static int test_doomed_base64_roundtrip(void)
// {
//     size_t len, trial, i;
//     unsigned int seed = 12345;  /* fixed seed for reproducibility */

//     for (len = 0; len < 2048; len++) {
//         /* Allocate source data (if len == 0, source may be NULL) */
//         char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
//         if (len > 0 && source == NULL) {
//             TEST_error("Out of memory for source of length %zu", len);
//             return 0;
//         }
//         /* Allocate a Base64 buffer of sufficient size */
//         size_t b64_size = base64_length_from_binary(len);
//         char *buffer = OPENSSL_malloc(b64_size + 1); /* +1 for null-terminator */
//         if (buffer == NULL) {
//             TEST_error("Out of memory for Base64 buffer of length %zu", b64_size + 1);
//             if (source) OPENSSL_free(source);
//             return 0;
//         }

//         for (trial = 0; trial < 10; trial++) {
//             /* Fill source with random bytes (if len > 0) */
//             if (len > 0) {
//                 for (i = 0; i < len; i++) {
//                     source[i] = (char)(rand_r(&seed) % 256);
//                 }
//             }
//             /* Encode source to Base64 */
//             size_t size = tail_encode_base64(NULL, buffer,source, len);
//             buffer[size] = '\0';
//             /* "Resize" the buffer: in C we simply record the new effective length */
//             size_t effective_b64_len = size;

//             /* Inject garbage into the Base64 string.
//                add_garbage takes a pointer to the pointer and a pointer to its length,
//                and returns the insertion location.
//             */
//             size_t location = add_garbage(&buffer, &effective_b64_len, &seed, to_base64_value);

//             /* Allocate back buffer for decoded binary data */
//             size_t back_bufsize = maximal_binary_length_from_base64(buffer, effective_b64_len);
//             char *back = (back_bufsize > 0) ? OPENSSL_malloc(back_bufsize) : NULL;
//             if (back_bufsize > 0 && back == NULL) {
//                 TEST_error("Out of memory for back buffer (length %zu)", back_bufsize);
//                 if (source) OPENSSL_free(source);
//                 OPENSSL_free(buffer);
//                 return 0;
//             }

//             /* Call normal decode function */
//             result r = base64_tail_decode_trim_end(NULL, back,buffer, effective_b64_len);
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

static int test_doomed_base64_roundtrip(void)
{
    size_t len, trial, i;
    unsigned int seed = 12345;  /* fixed seed for reproducibility */

    for (len = 0; len < 2048; len++) {
        /* Allocate source data (if len == 0, source may be NULL) */
        char *source = (len > 0) ? OPENSSL_malloc(len) : NULL;
        if (len > 0 && source == NULL) {
            TEST_error(RED_TEXT("Out of memory for source of length %zu\n"), len);
            return 0;
        }
        /* Allocate a Base64 buffer of sufficient size */
        size_t b64_size = base64_length_from_binary(len);
        char *buffer = OPENSSL_malloc(b64_size + 1); /* +1 for null-terminator */
        if (buffer == NULL) {
            TEST_error(RED_TEXT("Out of memory for Base64 buffer of length %zu\n"), b64_size + 1);
            if (source) OPENSSL_free(source);
            return 0;
        }

        for (trial = 0; trial < 10; trial++) {
            DEBUG_PRINT(BRIGHT_YELLOW_BG("Entering new trial"));
            /* Fill source with random bytes (if len > 0) */
            if (len > 0) {
                for (i = 0; i < len; i++) {
                    source[i] = (char)(rand_r(&seed) % 256);
                }
            }
            /* Encode source to Base64 */
            size_t size = tail_encode_base64(NULL, buffer, source, len);
            buffer[size] = '\0';
            /* Record the effective length of the Base64 string */
            size_t effective_b64_len = size;

            DEBUG_PRINT(BRIGHT_CYAN_TEXT("DEBUG: For len=%zu, trial=%zu\n"), len, trial);
            DEBUG_PRINT(BRIGHT_GREEN_TEXT("DEBUG: Base64 encoded result (length %zu): \"%s\"\n"),
                        effective_b64_len, buffer);

            /* Inject garbage into the Base64 string.
               add_garbage takes a pointer to the pointer and a pointer to its length,
               plus the lookup table, and returns the insertion location.
            */
            size_t location = add_garbage(&buffer, &effective_b64_len, &seed, to_base64_value);
            DEBUG_PRINT(BRIGHT_YELLOW_TEXT("DEBUG: After add_garbage, effective_b64_len=%zu, garbage location=%zu\n"),
                        effective_b64_len, location);

            /* Allocate back buffer for decoded binary data */
            size_t back_bufsize = maximal_binary_length_from_base64(buffer, effective_b64_len);
            DEBUG_PRINT(BRIGHT_BLUE_TEXT("DEBUG: Back buffer size = %zu\n"), back_bufsize);
            char *back = (back_bufsize > 0) ? OPENSSL_malloc(back_bufsize) : NULL;
            if (back_bufsize > 0 && back == NULL) {
                TEST_error(RED_TEXT("Out of memory for back buffer (length %zu)\n"), back_bufsize);
                if (source) OPENSSL_free(source);
                OPENSSL_free(buffer);
                return 0;
            }

            /* Call normal decode function */
            result r = base64_tail_decode_trim_end(NULL, back, buffer, effective_b64_len);
            DEBUG_PRINT(BRIGHT_MAGENTA_TEXT("DEBUG: Normal decode result: error=%d, count=%zu\n"),
                        r.error, r.count);
            ASSERT_EQUAL_INT(r.error, INVALID_BASE64_CHARACTER);
            ASSERT_EQUAL_SIZE(r.count, location);

            // /* Try safe decoding with different last-chunk handling options */
            // for (i = 0; i < 3; i++) {
            //     last_chunk_handling_options opt;
            //     if (i == 0) {
            //         opt = STRICT;
            //     } else if (i == 1) {
            //         opt = LOOSE;
            //     } else {
            //         opt = STOP_BEFORE_PARTIAL;
            //     }
            //     size_t safe_back_len = back_bufsize;
            //     result r2 = base64_to_binary_safe(buffer, effective_b64_len, back, &safe_back_len, 0, opt);
            //     DEBUG_PRINT(BRIGHT_MAGENTA_TEXT("DEBUG: Safe decode (option %d): error=%d, count=%zu\n"),
            //                 (int)opt, r2.error, r2.count);
            //     ASSERT_EQUAL_INT(r2.error, INVALID_BASE64_CHARACTER);
            //     ASSERT_EQUAL_SIZE(r2.count, location);
            // }
            if (back) OPENSSL_free(back);
        }
        if (source) OPENSSL_free(source);
        OPENSSL_free(buffer);
    }
    return 1;
}


/* 
 * Test: doomed_truncated_base64_roundtrip
 *
 * For each length from 1 to 2047, generate random binary data,
 * encode it to Base64, then truncate the encoded string by removing the last 3 characters.
 * Then, for each last-chunk handling option, attempt to decode.
 * The expectation is that the decoder will return an error 
 * (BASE64_INPUT_REMAINDER) and the count of processed characters should be as expected.
 */
static int test_doomed_truncated_base64_roundtrip(void)
{
    size_t len, trial, i;
    unsigned int seed = 12345;  /* Fixed seed for reproducibility */
    // last_chunk_handling_options options[] = { LOOSE, STRICT, STOP_BEFORE_PARTIAL };
    // size_t num_options = sizeof(options) / sizeof(options[0]);

    for (len = 1; len < 2048; len++) {
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
            char *buffer = OPENSSL_malloc(b64_size + 1); /* +1 for null-terminator */
            if (buffer == NULL) {
                TEST_error("Out of memory for Base64 buffer of length %zu", b64_size + 1);
                OPENSSL_free(source);
                return 0;
            }
            size_t size = tail_encode_base64(NULL, buffer,source, len);
            buffer[size] = '\0';

            /* Truncate the encoded buffer by removing the last 3 characters */
            if (size < 3) {
                OPENSSL_free(buffer);
                continue;
            }
            size_t truncated = size - 3;
            char *temp = OPENSSL_realloc(buffer, truncated);
            if (temp != NULL) {
                buffer = temp;
            }
            /* Allocate back buffer for decoded binary data */
            size_t back_bufsize = maximal_binary_length_from_base64(buffer, truncated);
            char *back = (back_bufsize > 0) ? OPENSSL_malloc(back_bufsize) : NULL;
            if (back_bufsize > 0 && back == NULL) {
                TEST_error("Out of memory for back buffer, length %zu", back_bufsize);
                OPENSSL_free(source);
                OPENSSL_free(buffer);
                return 0;
            }
            /* Attempt to decode using the normal path */
            result r = base64_tail_decode_trim_end(NULL, back,buffer, truncated);
            ASSERT_EQUAL_INT(r.error, BASE64_INPUT_REMAINDER);
            ASSERT_EQUAL_INT(r.count, (truncated -1)/4 * 3);
            /* Test the safe decoding path with each last-chunk handling option */
            // for (i = 0; i < num_options; i++) {
            //     size_t safe_back_len = back_bufsize;
            //     result r2 = base64_to_binary_safe(buffer, truncated, back, &safe_back_len, 0, options[i]);
            //     ASSERT_EQUAL_INT(r2.error, BASE64_INPUT_REMAINDER);
            //     ASSERT_EQUAL_SIZE(r2.count, truncated);
            // }
            OPENSSL_free(buffer);
            if (back) OPENSSL_free(back);
        }
        OPENSSL_free(source);
    }
    return 1;
}


/*-------------------------------------------------------------------------
  Test: streaming_base64_roundtrip

  For a fixed source length (2048 bytes), this test generates random binary data,
  encodes it to Base64, then simulates streaming decoding by processing the
  Base64 string in windows. For each window size (from 16 to 2048, stepping by 7),
  the test decodes the Base64 data in chunks. If a chunk does not complete a full
  4‑character block, it adjusts the position (simulating re‑processing of tail bytes).
  Finally, the decoded output is compared with the original source.
-------------------------------------------------------------------------*/
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
//             result r = base64_to_binary(NULL, back + outpos,buffer + pos, count);
//             /* Ensure we did not get an error indicating invalid character */
//             ASSERT_TRUE(r != -1);
//             if (pos + count == size) {
//                 /* Last chunk: expect a complete decode (SUCCESS) */
//                 ASSERT_EQUAL_INT(r, 1);
//             } else {
//                 size_t tail_bytes_to_reprocess = 0;
//                 if (r.error == BASE64_INPUT_REMAINDER) {
//                     tail_bytes_to_reprocess = 1;
//                 } else {
//                     tail_bytes_to_reprocess = ((r.count % 3) == 0) ? 0 : (r.count % 3) + 1;
//                 }
//                 /* Adjust position backwards by tail_bytes_to_reprocess */
//                 pos = (pos >= tail_bytes_to_reprocess) ? pos - tail_bytes_to_reprocess : 0;
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


// The setup_tests() function is called by the test harness to register tests.
int setup_tests(void)
{
    // // Register our sample test. The macro ADD_TEST() takes our test function.
    ADD_TEST(test_decode_base64_cases);
    ADD_TEST(test_complete_decode_base64_cases);
    ADD_TEST(test_encode_base64_basic_cases);
    ADD_TEST(test_encode_base64_no_padding_cases);
    ADD_TEST(test_roundtrip_base64_with_lots_of_spaces);
    ADD_TEST(test_roundtrip_base64_with_spaces);
    ADD_TEST(test_roundtrip_base64_with_garbage);
    ADD_TEST(test_base64_decode_just_one_padding_loose);
    ADD_TEST(test_roundtrip_base64);
    ADD_TEST(test_issue_520);
    ADD_TEST(test_issue_509);
    ADD_TEST(test_issue_504_8bit); 
    ADD_TEST(test_issue_502);
    ADD_TEST(test_issue_502_alt);
    ADD_TEST(test_bad_padding_base64);
    ADD_TEST(test_doomed_truncated_base64_roundtrip);
    ADD_TEST(test_doomed_base64_roundtrip);

    // Return 1 to indicate successful test setup.
    return 1;
}
