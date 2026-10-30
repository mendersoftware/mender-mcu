/**
 * @file      deployment_data_test.cpp
 * @brief     Unit Tests for deployment-data.c
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

#include "deployment-data.h"
#include "storage.h"

class MenderDeploymentDataTest : public ::testing::Test {
protected:
    mender_deployment_data_t *deployment_data = nullptr;

    void SetUp() override {
        ASSERT_EQ(MENDER_OK, mender_create_deployment_data("deployment-id", "artifact-name", &deployment_data));
        /* A new deployment data has a null state, which does not pass validation when stored */
        ASSERT_EQ(MENDER_OK, mender_deployment_data_set_state(deployment_data, MENDER_UPDATE_STATE_DOWNLOAD));
    }

    void TearDown() override {
        mender_delete_deployment_data(deployment_data);
        /* The posix storage writes the deployment data to the working directory */
        (void)mender_storage_delete_deployment_data();
    }
};

TEST_F(MenderDeploymentDataTest, NewDeploymentDataHasZeroStoreCount) {
    uint32_t count = 42;
    ASSERT_EQ(MENDER_OK, mender_deployment_data_get_state_data_store_count(deployment_data, &count));
    EXPECT_EQ(0u, count);
}

TEST_F(MenderDeploymentDataTest, SetDeploymentDataNumberTimesReturnsNumber) {
    const uint32_t times_set = 5;
    for (uint32_t i = 0; i < times_set; i++) {
        ASSERT_EQ(MENDER_OK, mender_set_deployment_data(deployment_data));
    }

    uint32_t count = 0;
    ASSERT_EQ(MENDER_OK, mender_deployment_data_get_state_data_store_count(deployment_data, &count));
    EXPECT_EQ(times_set, count);
}

TEST_F(MenderDeploymentDataTest, StoreCountSurvivesReload) {
    for (uint32_t i = 0; i < 3; i++) {
        ASSERT_EQ(MENDER_OK, mender_set_deployment_data(deployment_data));
    }

    mender_deployment_data_t *loaded = nullptr;
    ASSERT_EQ(MENDER_OK, mender_get_deployment_data(&loaded));

    uint32_t count = 0;
    EXPECT_EQ(MENDER_OK, mender_deployment_data_get_state_data_store_count(loaded, &count));
    EXPECT_EQ(3u, count);

    mender_delete_deployment_data(loaded);
}

TEST_F(MenderDeploymentDataTest, LoopDetectedWhenMaxStoreCountReached) {
    for (uint32_t i = 0; i < CONFIG_MENDER_MAX_STATE_DATA_STORE_COUNT; i++) {
        ASSERT_EQ(MENDER_OK, mender_set_deployment_data(deployment_data));
    }
    EXPECT_EQ(MENDER_LOOP_DETECTED, mender_set_deployment_data(deployment_data));
}

TEST(MenderDeploymentDataNullTest, GetStoreCountOnNullReturnsNotFound) {
    uint32_t count = 0;
    EXPECT_EQ(MENDER_NOT_FOUND, mender_deployment_data_get_state_data_store_count(nullptr, &count));
}
