/**
 * @file      mender-utils_test.cpp
 * @brief     Unit Tests for mender-utils.c
 *
 * Copyright Northern.tech AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

extern "C" {
#include "mender-utils.h"
}

using namespace std;

typedef struct {
    string input_string;
    string wildcard_string;
    bool   expected;
} TestWildCard;

TEST(MenderUtilsTest, WildcardComparison) {
    TestWildCard test_wildcard[] = { { "wow", "wow", true },
                                     { "abc_123_def_456_ghi", "abc_123_def_456_g", false },
                                     { "abc_123_def_456_ghi", "abc*def*ghi", true },
                                     { "abc_123_def_456_ghi", "abc*123*def*ghi", true },
                                     { "abc_123_def_456_ghi", "*def*456*", true },
                                     { "abc_123_def_456_ghi", "abc*789*ghi", false },
                                     { "hello_world", "hello*world", true },
                                     { "hello_world", "hello*worlds", false },
                                     { "a_b_c", "a*_*b*", true },
                                     { "a_b_c", "a*c*b", false },
                                     { "abc", "*a*bc*", true },
                                     { "abcabcabc", "a*c*a*c*", true },
                                     { "test_key_1", "test_*", true },
                                     { "test_key_1", "test_", false },
                                     { "best_test_key_1", "test_*", false },
                                     { "test_key_1", "", false },
                                     { "", "", true },
                                     { "abc", "*", true },
                                     { "", "abc", false },
                                     { "", "abc*", false },
                                     { "", "*", true },
                                     { "abc", "xyz", false },
                                     { "abc", "abc*", true },
                                     { "abc", "*abc", true },
                                     { "abc", "a*xyz", false },
                                     { "test_string", "test_*test_*", false },
                                     { "test_string", "test_*string*", true },
                                     { "test_test_key", "***", true } };

    for (size_t i = 0; i < sizeof(test_wildcard) / sizeof(test_wildcard[0]); i++) {
        bool result;
        mender_utils_compare_wildcard(test_wildcard[i].input_string.c_str(), test_wildcard[i].wildcard_string.c_str(), &result);
        EXPECT_EQ(result, test_wildcard[i].expected);
    }
}
