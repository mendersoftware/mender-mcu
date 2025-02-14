/**
 * @file      artifact_test.cpp
 * @brief     Unit Tests for mender-artifact.c
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

#include <sys/stat.h>
#include <stdlib.h>
#include <filesystem>
#include <fstream>

#include "artifact.h"
#include "deployment-data.h"
#include "update-module.h"

using namespace std;
namespace fs = filesystem;

#ifndef __has_feature
// GCC does not have __has_feature
#define __has_feature(feature) 0
#endif

#if ((__has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)) || (__has_feature(thread_sanitizer) || defined(__SANITIZE_THREAD__)))
extern "C" {
/* https://github.com/google/sanitizers/wiki/AddressSanitizerFlags#run-time-flags
* Since we want to test cases where realloc will return null because of a
* too large size, we need to set allocator_may_return_null=1 */
const char *
__asan_default_options() {
    return "allocator_may_return_null=1";
}
const char *
__tsan_default_options() {
    return "allocator_may_return_null=1";
}
}
#endif

class MenderArtifactTest : public ::testing::Test {
protected:
    vector<uint8_t> artifact_data;
    void           *data;
    fs::path        artifact_path;
    fs::path        script_file_name;

    vector<uint8_t> CreateArtifact(string custom_script = "") {
        string script;
        if (custom_script.empty()) {
            script = R"(#! /bin/sh
            DIRNAME=$(dirname $0)
            echo foobar > ${DIRNAME}/testdata

            mender-artifact write module-image --compression none \
            --type unit-test -n unit-test-artifact --device-type unit-test \
            -f ${DIRNAME}/testdata -o ${DIRNAME}/unit-test-artifact.mender || exit 1)";
        } else {
            script = custom_script;
        }

        fs::path tmp_dir = fs::temp_directory_path();
        script_file_name = tmp_dir / "test-script.sh";

        ofstream os(script_file_name.c_str());

        os << script;
        os.close();

        chmod(script_file_name.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);
        system(script_file_name.c_str());

        artifact_path = tmp_dir / "unit-test-artifact.mender";
        ifstream file(artifact_path);
        return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    }

    void InitializeData(mender_update_module_t *update_module, mender_deployment_data_t *deployment_data, mender_artifact_download_data_t *mock_download_data) {
        mender_create_deployment_data("id", "unit-test-artifact", &deployment_data);

        update_module->artifact_type = "unit-test";
        update_module->callbacks[MENDER_UPDATE_STATE_DOWNLOAD]
            = [](MENDER_ARG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_u data) { return MENDER_OK; };
        mender_update_module_register(update_module);

        mock_download_data->deployment    = deployment_data;
        mock_download_data->update_module = update_module;
    }

    mender_update_module_t          *update_module;
    mender_deployment_data_t        *deployment_data;
    mender_artifact_download_data_t *mock_download_data;

    void SetUp() {
        update_module      = (mender_update_module_t *)mender_malloc(sizeof(mender_update_module_t));
        deployment_data    = (mender_deployment_data_t *)mender_malloc(sizeof(mender_deployment_data_t));
        mock_download_data = (mender_artifact_download_data_t *)mender_malloc(sizeof(mender_artifact_download_data_t));
        InitializeData(update_module, deployment_data, mock_download_data);
        artifact_data = CreateArtifact();
        data          = (void *)artifact_data.data();
    }
    void TearDown() {
        fs::remove(script_file_name);
        fs::remove(artifact_path);
        DESTROY_AND_NULL(mender_delete_deployment_data, mock_download_data->deployment);
        mender_free(deployment_data);
        mender_free(mock_download_data);
        mender_update_module_unregister_all();
    }
};

TEST_F(MenderArtifactTest, CreateCtx) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(64);
    EXPECT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->input.size, 64);
    EXPECT_EQ(ctx->input.size, ctx->input.orig_size);
    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, GetCtx) {
    /* No existing context */
    mender_artifact_ctx_t *ctx;
    EXPECT_EQ(MENDER_FAIL, mender_artifact_get_ctx(&ctx));

    ctx = mender_artifact_create_ctx(64);

    mender_artifact_ctx_t *ctx2;
    EXPECT_EQ(MENDER_OK, mender_artifact_get_ctx(&ctx2));

    EXPECT_EQ(ctx, ctx2);
    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, ProcessData) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(1024);

    /* Process artifact data */
    EXPECT_EQ(MENDER_OK, mender_artifact_process_data(ctx, data, artifact_data.size(), mock_download_data));

    /* Number of payloads in the artifact, expect 1 */
    EXPECT_EQ(ctx->payloads.size, 1);

    /* Type of payload, expect `unit-test` */
    mender_artifact_payload_t *payload = ctx->payloads.values;
    EXPECT_STREQ(payload->type, "unit-test");

    /* The original context size was too small, so the new one should be larger
     * than the original isze */
    EXPECT_GT(ctx->input.size, ctx->input.orig_size);

    /* Should be 0/NULL, as there are no artifacts currently
     * being parsed */
    EXPECT_EQ(ctx->file.size, 0);
    EXPECT_EQ(ctx->file.index, 0);
    EXPECT_STREQ(ctx->file.name, NULL);

    /* One thing should be provided, the artifact name */
    mender_key_value_list_t *provides = ctx->artifact_info.provides;
    EXPECT_STREQ(provides->value, "unit-test-artifact");

    /* Should depend on one thing, the artifact type */
    mender_key_value_list_t *depends = ctx->artifact_info.depends;
    EXPECT_STREQ(depends->value, "unit-test");

    /* Check the stream state */
    EXPECT_EQ(ctx->stream_state, MENDER_ARTIFACT_STREAM_STATE_PARSING_HEADER);

    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, ProcessData_TooLargeSize) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(1024);

    /* If ctx->file.size (expected_size) is too big, the realloc will fail,
     * and we'll attempt to realloc ctx->input.length + input_length (new_size)
     * instead. This checks that the data is correctly copied to the internal buffer,
     * even though the expected size is too big */
    ctx->file.size = 99999999999999999;
    EXPECT_EQ(MENDER_OK, mender_artifact_process_data(ctx, data, artifact_data.size(), mock_download_data));

    mender_artifact_release_ctx(ctx);

    ctx = mender_artifact_create_ctx(1024);

    /* If the input size is too big, we're not able to realloc, and should fail */
    ctx->input.length = 99999999999999999;
    EXPECT_EQ(MENDER_FAIL, mender_artifact_process_data(ctx, data, artifact_data.size(), mock_download_data));

    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, ProcessData_EmptyInput) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(1024);

    EXPECT_EQ(MENDER_OK, mender_artifact_process_data(ctx, NULL, 0, mock_download_data));

    EXPECT_EQ(ctx->input.size, ctx->input.orig_size);
    EXPECT_EQ(ctx->file.size, 0);
    EXPECT_EQ(ctx->file.index, 0);
    EXPECT_STREQ(ctx->file.name, NULL);

    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, ProcessData_InvalidData) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(1024);
    vector<uint8_t>        invalid_data(1240, 'A');

    EXPECT_EQ(MENDER_FAIL, mender_artifact_process_data(ctx, (void *)invalid_data.data(), invalid_data.size(), mock_download_data));

    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, ProcessData_EmptyDownloadData) {
    mender_artifact_ctx_t          *ctx        = mender_artifact_create_ctx(1024);
    mender_artifact_download_data_t empty_data = { NULL, NULL, NULL, (mender_err_t)0 };

    EXPECT_EQ(MENDER_FAIL, mender_artifact_process_data(ctx, data, artifact_data.size(), &empty_data));

    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, CheckIntegrity) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(1024);

    /* Process artifact data */
    EXPECT_EQ(MENDER_OK, mender_artifact_process_data(ctx, data, artifact_data.size(), mock_download_data));

    EXPECT_EQ(MENDER_OK, mender_artifact_check_integrity(ctx));

    /* We can't call check_integrity on the same context twice, as it modifies the context
     * Therefore we create a new one and corrupt that */
    mender_artifact_ctx_t *ctx2 = mender_artifact_create_ctx(1024);
    /* Process artifact data */
    EXPECT_EQ(MENDER_OK, mender_artifact_process_data(ctx2, data, artifact_data.size(), mock_download_data));

    mender_artifact_checksum_t *checksum = ctx2->artifact_info.checksums;
    /* Corrupt the artifact checksum */
    checksum->manifest[0] = '\x1F';
    EXPECT_EQ(MENDER_FAIL, mender_artifact_check_integrity(ctx2));

    mender_artifact_release_ctx(ctx);
    mender_artifact_release_ctx(ctx2);
}

TEST_F(MenderArtifactTest, IsCompressed) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(1024);

    string script = R"(#! /bin/sh
    DIRNAME=$(dirname $0)
    echo foobar > ${DIRNAME}/testdata

    mender-artifact write module-image --type unit-test \
    -n unit-test-artifact --device-type unit-test \
    -f ${DIRNAME}/testdata -o ${DIRNAME}/unit-test-artifact.mender || exit 1)";
    artifact_data = CreateArtifact(script);
    data          = (void *)artifact_data.data();

    /* Process artifact data */
    EXPECT_EQ(MENDER_FAIL, mender_artifact_process_data(ctx, data, artifact_data.size(), mock_download_data));

    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, ArtifactWithMetaData) {
    mender_artifact_ctx_t *ctx = mender_artifact_create_ctx(1024);

    string script = R"(#! /bin/sh
    DIRNAME=$(dirname $0)
    echo foobar > ${DIRNAME}/testdata
    echo {\"datastring\": \"foobar\", \"datanumber\": 1.0} > ${DIRNAME}/meta-data

    mender-artifact write module-image --type unit-test --compression none \
    -n unit-test-artifact --device-type unit-test --meta-data ${DIRNAME}/meta-data \
    -f ${DIRNAME}/testdata -o ${DIRNAME}/unit-test-artifact.mender || exit 1)";
    artifact_data = CreateArtifact(script);
    data          = (void *)artifact_data.data();

    /* Process artifact data */
    EXPECT_EQ(MENDER_OK, mender_artifact_process_data(ctx, data, artifact_data.size(), mock_download_data));

    cJSON *meta_data = ctx->payloads.values->meta_data;
    /* create a cjson object to compare with */
    cJSON *expected_meta_data = cJSON_Parse("{\"datanumber\": 1.0, \"datastring\": \"foobar\"}");
    EXPECT_TRUE(cJSON_Compare(meta_data, expected_meta_data, true));

    cJSON_Delete(expected_meta_data);
    mender_artifact_release_ctx(ctx);
}

TEST_F(MenderArtifactTest, GetDeviceType) {
    mender_artifact_ctx_t *ctx         = mender_artifact_create_ctx(1024);
    const char            *device_type = ""; /* initalize to empty string to avoid warnings */

    EXPECT_EQ(MENDER_FAIL, mender_artifact_get_device_type(ctx, &device_type));

    /* Process artifact data */
    EXPECT_EQ(MENDER_OK, mender_artifact_process_data(ctx, data, artifact_data.size(), mock_download_data));

    /* Get device type */
    EXPECT_EQ(MENDER_OK, mender_artifact_get_device_type(ctx, &device_type));

    EXPECT_STREQ(device_type, "unit-test");

    mender_artifact_release_ctx(ctx);
}
