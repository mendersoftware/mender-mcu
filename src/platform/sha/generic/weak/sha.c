/**
 * @file      sha.c
 * @brief     Mender SHA interface for weak platform
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

#include <mender/sha.h>

MENDER_FUNC_WEAK mender_err_t
mender_sha256_begin(MENDER_ARG_UNUSED mender_sha256_context_t *ctx) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_sha256_update(MENDER_ARG_UNUSED mender_sha256_context_t ctx, MENDER_ARG_UNUSED const unsigned char *input, MENDER_ARG_UNUSED size_t length) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_sha256_finish(MENDER_ARG_UNUSED mender_sha256_context_t ctx, MENDER_ARG_UNUSED unsigned char *output) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}
