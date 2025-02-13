/**
 * @file      sha.c
 * @brief     Mender SHA interface for MbedTLS platform
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

#include "alloc.h"
#include "sha.h"
#include "log.h"

#include <mbedtls/sha256.h>

mender_err_t
mender_sha256_begin(mender_sha256_context_t *context) {
    assert(NULL != context);

    mbedtls_sha256_context *ctx = mender_malloc(sizeof(mbedtls_sha256_context));
    if (NULL == ctx) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    mbedtls_sha256_init(ctx);
    if (0 != mbedtls_sha256_starts(ctx, 0 /* Use SHA-256, not SHA-224 */)) {
        mender_log_error("Failed to start SHA-256 checksum calculation");
        mender_free(ctx);
        return MENDER_FAIL;
    }

    *context = ctx;
    return MENDER_OK;
}

mender_err_t
mender_sha256_update(mender_sha256_context_t context, const unsigned char *input, size_t length) {
    assert(NULL != context);

    mbedtls_sha256_context *ctx = context;
    if (0 != mbedtls_sha256_update(ctx, input, length)) {
        mender_log_error("Failed to update SHA-256 checksum calculation");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_sha256_finish(mender_sha256_context_t context, unsigned char *output) {
    mender_err_t            ret = MENDER_OK;
    mbedtls_sha256_context *ctx = context;
    if (NULL != ctx) {
        if (NULL != output) {
            if (0 != mbedtls_sha256_finish(ctx, output)) {
                mender_log_error("Failed to finish SHA-256 checksum calculation");
                ret = MENDER_FAIL;
            }
        }
        mbedtls_sha256_free(ctx);
        mender_free(ctx);
    }
    return ret;
}
