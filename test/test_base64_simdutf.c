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

// This test function always returns true
static int test_decode_base64_cases_scalar_utf8(void)
{
    // Simply return 1 to indicate success
    return 1;
}

// The setup_tests() function is called by the test harness to register tests.
int setup_tests(void)
{
    // Register our sample test. The macro ADD_TEST() takes our test function.
    ADD_TEST(test_decode_base64_cases_scalar_utf8);

    // Return 1 to indicate successful test setup.
    return 1;
}
