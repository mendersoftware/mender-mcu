/**
 * @file      mender-sha.h
 * @brief     Mender SHA interface
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

#ifndef __MENDER_SHA_H__
#define __MENDER_SHA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-utils.h" /* mender_err_t */

/**
 * @brief This type is just a pointer to whatever data structure is required by
 *        a specific platform implementation. This data structure will be
 *        allocated on the heap by mender_sha256_begin function and must be
 *        free'd in the mender_sha256_finish function.
 */
typedef void *mender_sha256_context_t;

/**
 * @brief Size of SHA-256 digest buffer in Bytes.
 */
#define MENDER_DIGEST_BUFFER_SIZE 32

/**
 * @brief Initializes a SHA-256 context and starts a checksum calculation.
 * @param context The SHA-256 context to be initialized. This must not be NULL.
 * @note A call to mender_sha256_begin must be followed by a call to
 *       mender_sha256_finish in order to release resources.
 * @return MENDER_OK on success, otherwise error code.
 */
mender_err_t mender_sha256_begin(mender_sha256_context_t *context);

/**
 * @brief Feeds an input buffer into an ongoing SHA-256 checksum calculation.
 * @param context The SHA-256 context. This must have been initialized.
 * @param input The buffer holding the data to be fed.
 * @param length The length of the input data in Bytes.
 * @return MENDER_OK on success, otherwise error code.
 */
mender_err_t mender_sha256_update(mender_sha256_context_t context, const unsigned char *input, size_t length);

/**
 * @brief Finishes the SHA-256 checksum calculation, writes the result to the
 *        output buffer and clears the SHA-256 context.
 * @param context The SHA-256 context to be cleared. If NULL is passed, no
 *                operation is performed.
 * @param output A writeable buffer of MENDER_DIGEST_BUFFER_SIZE Bytes for
 *               SHA-256 checksum. If NULL is passed, the function will only
 *               clear the SHA-256 context.
 * @return MENDER_OK on success, otherwise error code.
 */
mender_err_t mender_sha256_finish(mender_sha256_context_t context, unsigned char *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_SHA_H__ */
