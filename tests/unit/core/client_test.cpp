/**
 * @file      client_test.cpp
 * @brief     Unit Tests for client.c
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
#include "mender/client.h"
}

using namespace std;
using namespace testing;

class MenderClientTest : public ::testing::Test {
protected:
    mender_client_config_t    config {};
    mender_client_callbacks_t callbacks {};

    void SetUp() override {
        config.device_type     = "test_device";
        callbacks.restart      = []() { return MENDER_OK; };
        callbacks.get_identity = [](MENDER_ARG_UNUSED const mender_identity_t **identity) { return MENDER_OK; };
    }
};

TEST_F(MenderClientTest, ClientInitWithValidStandardTier) {
    config.device_tier = MENDER_DEVICE_TIER_STANDARD;

    mender_err_t result = mender_client_init(&config, &callbacks);
    EXPECT_EQ(result, MENDER_OK);

    mender_client_exit();
}

TEST_F(MenderClientTest, ClientInitWithValidMicroTier) {
    config.device_tier = MENDER_DEVICE_TIER_MICRO;

    mender_err_t result = mender_client_init(&config, &callbacks);
    EXPECT_EQ(result, MENDER_OK);

    mender_client_exit();
}

TEST_F(MenderClientTest, ClientInitWithInvalidTier) {
    config.device_tier = "invalid_tier";

    mender_err_t result = mender_client_init(&config, &callbacks);
    EXPECT_EQ(result, MENDER_FAIL);
}

TEST_F(MenderClientTest, ClientInitWithEmptyTier) {
    config.device_tier = "";

    mender_err_t result = mender_client_init(&config, &callbacks);
    EXPECT_EQ(result, MENDER_OK);
    // This returns MENDER_OK because we first check if the client
    // config has set it, otherwise we use MENDER_DEVICE_TIER which
    // can be configured via Kconfig

    mender_client_exit();
}

TEST_F(MenderClientTest, ClientInitWithNullTier) {
    config.device_tier = nullptr;

    mender_err_t result = mender_client_init(&config, &callbacks);
    EXPECT_EQ(result, MENDER_OK);
    // This returns MENDER_OK because we first check if the client
    // config has set it, other wise we use MENDER_DEVICE_TIER which
    // can be configured via Kconfig

    mender_client_exit();
}

TEST_F(MenderClientTest, ClientInitNoTier) {
    mender_err_t result = mender_client_init(&config, &callbacks);
    EXPECT_EQ(result, MENDER_OK);
    // This returns MENDER_OK because we first check if the client
    // config has set it, other wise we use MENDER_DEVICE_TIER which
    // can be configured via Kconfig

    mender_client_exit();
}

TEST(DeviceTierValidationTest, ValidStandardTier) {
    EXPECT_EQ(mender_client_validate_device_tier(MENDER_DEVICE_TIER_STANDARD), MENDER_OK);
    EXPECT_EQ(mender_client_validate_device_tier(MENDER_DEVICE_TIER_MICRO), MENDER_OK);
    EXPECT_EQ(mender_client_validate_device_tier("standard"), MENDER_OK);
    EXPECT_EQ(mender_client_validate_device_tier("micro"), MENDER_OK);

    EXPECT_EQ(mender_client_validate_device_tier("invalid_tier"), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier("Standard"), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier("STANDARD"), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier("MICRO"), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier(" standard"), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier("standard "), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier(" micro "), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier(""), MENDER_FAIL);
    EXPECT_EQ(mender_client_validate_device_tier(nullptr), MENDER_FAIL);
}
