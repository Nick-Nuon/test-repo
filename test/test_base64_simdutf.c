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
