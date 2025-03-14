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

#define DEBUG 1

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
int base64_tail_decode(EVP_ENCODE_CTX *ctx, char *dst, const char *src, int length);

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
        int decoded = base64_tail_decode_trim_end(NULL, (char *)buffer, cases[i], len);
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
        int r = base64_tail_decode_trim_end(NULL, (char *)buffer,cases[i].encoded, enc_len);
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

static int test_encode_base64_cases(void)
{
    DEBUG_PRINT(GREEN_TEXT("DEBUG: Entered encode_base64_cases Test\n"));

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
        int r = base64_tail_decode_trim_end(NULL, (char *)buffer,cases[i].encoded, enc_len);
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
        size_t r = base64_tail_decode_trim_end(NULL, back, buffer_with_spaces, buffer_with_spaces_len);
        DEBUG_PRINT("DEBUG: Decoded binary length = %zu\n", r);
        ASSERT_EQUAL_SIZE(r, len);

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
            int r = base64_tail_decode_trim_end(NULL, back,buffer, cur_b64_len);
            DEBUG_PRINT("DEBUG: base64_to_binary returned count = %zu\n", r);
            ASSERT_EQUAL_SIZE(r, len);
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

// The setup_tests() function is called by the test harness to register tests.
int setup_tests(void)
{
    // Register our sample test. The macro ADD_TEST() takes our test function.
    // ADD_TEST(test_decode_base64_cases);
    // ADD_TEST(test_complete_decode_base64_cases);
    // ADD_TEST(test_encode_base64_cases);
    // ADD_TEST(test_roundtrip_base64_with_lots_of_spaces);
    ADD_TEST(test_roundtrip_base64_with_spaces);


    // Return 1 to indicate successful test setup.
    return 1;
}
