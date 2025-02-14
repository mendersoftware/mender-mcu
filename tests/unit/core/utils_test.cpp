/**
 * @file      utils_test.cpp
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
#include "utils.h"
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

TEST(MenderUtilsTest, StrStr) {
    string needle;
    string haystack;
    string check;

    /* Needle in haystack */
    needle   = "needle";
    haystack = "haystack with needle";
    check    = mender_utils_strrstr(haystack.c_str(), needle.c_str());
    EXPECT_STREQ(check.c_str(), needle.c_str());

    /* Two needles in haystack */
    needle   = "needle";
    haystack = "needle haystack needle";
    check    = mender_utils_strrstr(haystack.c_str(), needle.c_str());
    EXPECT_STREQ(check.c_str(), needle.c_str());

    /* Needle not in end of haystack */
    needle   = "needle";
    haystack = "haystack needle 1 needle 2 needle 3";
    check    = mender_utils_strrstr(haystack.c_str(), needle.c_str());
    EXPECT_STREQ(check.c_str(), "needle 3");

    /* Needle not in haystack */
    needle   = "nedle";
    haystack = "haystack with needle";
    EXPECT_EQ(mender_utils_strrstr(haystack.c_str(), needle.c_str()), nullptr);

    /* Empty needle */
    needle   = "";
    haystack = "haystack with needle";
    check    = mender_utils_strrstr(haystack.c_str(), needle.c_str());
    EXPECT_STRNE(check.c_str(), haystack.c_str());
}

TEST(MenderUtilsTest, StrDup) {
    const char *orig = "123456789";
    char       *result;

    result = mender_utils_strdup(orig);
    EXPECT_STREQ(result, orig);
    free(result);

    result = mender_utils_strndup(orig, 4);
    EXPECT_STREQ(result, "1234");
    free(result);

    result = mender_utils_strndup(orig, 9);
    EXPECT_STREQ(result, orig);
    free(result);
}

TEST(MenderUtilsTest, StringBeginsWith) {
    const string str = "string begins with";

    EXPECT_TRUE(mender_utils_strbeginswith(str.c_str(), "string"));

    EXPECT_TRUE(mender_utils_strbeginswith(str.c_str(), "string begin"));

    EXPECT_FALSE(mender_utils_strbeginswith(str.c_str(), " string"));

    EXPECT_FALSE(mender_utils_strbeginswith(str.c_str(), "string begins with "));

    EXPECT_FALSE(mender_utils_strbeginswith("", " "));

    EXPECT_TRUE(mender_utils_strbeginswith("", ""));

    EXPECT_FALSE(mender_utils_strbeginswith(str.c_str(), nullptr));
}

TEST(MenderUtilsTest, StringEndsWith) {
    const string str = "string ends with";

    EXPECT_TRUE(mender_utils_strendswith(str.c_str(), "with"));

    EXPECT_TRUE(mender_utils_strendswith(str.c_str(), "ends with"));

    EXPECT_FALSE(mender_utils_strendswith(str.c_str(), "with "));

    EXPECT_TRUE(mender_utils_strendswith(str.c_str(), "string ends with"));

    EXPECT_FALSE(mender_utils_strendswith("", " "));

    EXPECT_TRUE(mender_utils_strendswith("", ""));

    EXPECT_FALSE(mender_utils_strendswith(str.c_str(), nullptr));
}

TEST(MenderUtilsTest, DeploymentStatusToString) {
    typedef struct {
        mender_deployment_status_t deployment_status;
        string                     status_string;
    } DeploymentStatusString;
    DeploymentStatusString status[]
        = { { MENDER_DEPLOYMENT_STATUS_DOWNLOADING, "downloading" }, { MENDER_DEPLOYMENT_STATUS_INSTALLING, "installing" },
            { MENDER_DEPLOYMENT_STATUS_REBOOTING, "rebooting" },     { MENDER_DEPLOYMENT_STATUS_SUCCESS, "success" },
            { MENDER_DEPLOYMENT_STATUS_FAILURE, "failure" },         { MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED, "already-installed" } };

    string status_string;
    for (size_t i = 0; i < sizeof(status) / sizeof(status[0]); i++) {
        status_string = mender_utils_deployment_status_to_string(status[i].deployment_status);
        EXPECT_STREQ(status_string.c_str(), status[i].status_string.c_str());
    }
}

TEST(MenderUtilsTest, HexDumpToBytes) {
    string hexdump = "68657864756d7020746f206279746573"; /* "hexdump to bytes" */

    const size_t          n_bytes = 16;
    vector<unsigned char> bytes(n_bytes);
    bool                  ret = mender_utils_hexdump_to_bytes(hexdump.c_str(), bytes.data(), n_bytes);
    EXPECT_TRUE(ret);
    EXPECT_EQ(string(bytes.begin(), bytes.end()), "hexdump to bytes");

    /* Invalid hexdump */
    hexdump = "68657864756d7020746f206279t";
    ret     = mender_utils_hexdump_to_bytes(hexdump.c_str(), bytes.data(), n_bytes);
    EXPECT_FALSE(ret);

    /* NULL hexdump */
    ret = mender_utils_hexdump_to_bytes(nullptr, bytes.data(), n_bytes);
    EXPECT_FALSE(ret);
}

TEST(MenderUtilsTest, KeyValueList) {
    mender_err_t ret;

    mender_key_value_list_t *list = nullptr;

    ret = mender_utils_key_value_list_create_node("key3", "value3", &list);
    EXPECT_EQ(ret, MENDER_OK);
    ret = mender_utils_key_value_list_create_node("key2", "value2", &list);
    EXPECT_EQ(ret, MENDER_OK);
    ret = mender_utils_key_value_list_create_node("key1", "value1", &list);
    EXPECT_EQ(ret, MENDER_OK);

    /* Check that the nodes are indeed created */
    size_t i_node = 1;
    for (mender_key_value_list_t *item = list; item != nullptr; item = item->next) {
        EXPECT_STREQ(item->key, ("key" + to_string(i_node)).c_str());
        EXPECT_STREQ(item->value, ("value" + to_string(i_node)).c_str());
        i_node++;
    }

    /* Delete 'key1' */
    ret = mender_utils_key_value_list_delete_node(&list, "key1");
    EXPECT_EQ(ret, MENDER_OK);
    for (mender_key_value_list_t *item = list; item != nullptr; item = item->next) {
        EXPECT_STRNE(item->key, "key1");
    }

    /* Attempt to append key2 to the list with append unique -> assert only one key2 */
    mender_key_value_list_t *key_node = nullptr;
    ret                               = mender_utils_key_value_list_create_node("key2", "value2", &key_node);
    EXPECT_EQ(ret, MENDER_OK);
    ret = mender_utils_key_value_list_append_unique(&list, &key_node);
    EXPECT_EQ(ret, MENDER_OK);
    size_t key_counter = 0;
    for (mender_key_value_list_t *item = list; item != nullptr; item = item->next) {
        if (StringEqual(item->key, "key2")) {
            key_counter++;
        }
    }
    EXPECT_EQ(key_counter, 1);

    key_counter = 0;
    ret         = mender_utils_key_value_list_append(&list, &key_node);
    EXPECT_EQ(ret, MENDER_OK);
    for (mender_key_value_list_t *item = list; item != nullptr; item = item->next) {
        if (StringEqual(item->key, "key2")) {
            key_counter++;
        }
    }
    EXPECT_EQ(key_counter, 2);

    ret = mender_utils_key_value_list_free(list);
    EXPECT_EQ(ret, MENDER_OK);
}

TEST(MenderUtilsTest, KeyValueListToString) {
    /* Create list */
    mender_err_t             ret;
    mender_key_value_list_t *list = nullptr;

    ret = mender_utils_key_value_list_create_node("key3", "value3", &list);
    EXPECT_EQ(ret, MENDER_OK);
    ret = mender_utils_key_value_list_create_node("key2", "value2", &list);
    EXPECT_EQ(ret, MENDER_OK);
    ret = mender_utils_key_value_list_create_node("key1", "value1", &list);
    EXPECT_EQ(ret, MENDER_OK);

    char *key_value_str = nullptr;
    ret                 = mender_utils_key_value_list_to_string(list, &key_value_str);
    EXPECT_EQ(ret, MENDER_OK);
    EXPECT_STREQ(key_value_str, "key1\x1Fvalue1\x1Ekey2\x1Fvalue2\x1Ekey3\x1Fvalue3\x1E");

    free(key_value_str);
    ret = mender_utils_key_value_list_free(list);
    EXPECT_EQ(ret, MENDER_OK);
}

TEST(MenderUtilsTest, StringToKeyValueList) {
    mender_err_t ret;

    const string             key_value_str = "key1\x1Fvalue1\x1Ekey2\x1Fvalue2\x1Ekey3\x1Fvalue3\x1E";
    mender_key_value_list_t *list          = nullptr;
    ret                                    = mender_utils_string_to_key_value_list(key_value_str.c_str(), &list);
    EXPECT_EQ(ret, MENDER_OK);

    size_t i_node = 3;
    for (mender_key_value_list_t *item = list; item != nullptr; item = item->next) {
        EXPECT_STREQ(item->key, ("key" + to_string(i_node)).c_str());
        EXPECT_STREQ(item->value, ("value" + to_string(i_node)).c_str());
        i_node--;
    }

    ret = mender_utils_key_value_list_free(list);
    EXPECT_EQ(ret, MENDER_OK);
}

TEST(MenderUtilsTest, KeystoreFromJson) {
    const string json_str    = "{\"key1\": \"value1\", \"key2\": \"value2\"}";
    cJSON       *json_object = cJSON_Parse(json_str.c_str());

    mender_keystore_t *keystore = nullptr;
    mender_err_t       ret      = mender_utils_keystore_from_json(&keystore, json_object);
    EXPECT_EQ(ret, MENDER_OK);

    EXPECT_EQ(mender_utils_keystore_length(keystore), 2);

    EXPECT_STREQ(keystore[0].name, "key1");
    EXPECT_STREQ(keystore[0].value, "value1");
    EXPECT_STREQ(keystore[1].name, "key2");
    EXPECT_STREQ(keystore[1].value, "value2");

    cJSON_Delete(json_object);
    mender_utils_keystore_delete(keystore);
}

TEST(MenderUtilsTest, KeystoreToJson) {
    mender_keystore_t *keystore = mender_utils_keystore_new(2);

    mender_utils_keystore_set_item(keystore, 0, (char *)"key1", (char *)"value1");
    mender_utils_keystore_set_item(keystore, 1, (char *)"key2", (char *)"value2");

    cJSON       *json_object = nullptr;
    mender_err_t ret         = mender_utils_keystore_to_json(keystore, &json_object);

    EXPECT_EQ(ret, MENDER_OK);
    EXPECT_STREQ(cJSON_GetObjectItem(json_object, "key1")->valuestring, "value1");
    EXPECT_STREQ(cJSON_GetObjectItem(json_object, "key2")->valuestring, "value2");

    cJSON_Delete(json_object);
    mender_utils_keystore_delete(keystore);
}
