/**
 * @file      tls.c
 * @brief     Mender TLS interface for weak platform
 *
 * Copyright joelguittet and mender-mcu-client contributors
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

#include "mender-tls.h"

MENDER_FUNC_WEAK mender_err_t
mender_tls_init(void) {

    /* Nothing to do */
    return MENDER_OK;
}

MENDER_FUNC_WEAK mender_err_t
mender_tls_init_authentication_keys(mender_err_t (*get_user_provided_keys)(char **user_provided_key, size_t *user_provided_key_length), bool recommissioning) {

    (void)get_user_provided_keys;
    (void)recommissioning;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_tls_get_public_key_pem(char **public_key) {

    (void)public_key;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_tls_sign_payload(char *payload, char **signature, size_t *signature_length) {

    (void)payload;
    (void)signature;
    (void)signature_length;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_tls_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}
