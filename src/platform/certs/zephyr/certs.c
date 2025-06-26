/**
 * @file      certs.c
 * @brief     Mender MCU Certificate for zephyr
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

#include <stddef.h> /* size_t */
#include <zephyr/net/tls_credentials.h>

#include "certs.h"
#include "log.h"
#include <errno.h>

static const unsigned char dormant_certificate_a[] = {
#include "dormant_a.cer.inc"
};

static const unsigned char dormant_certificate_b[] = {
#include "dormant_b.cer.inc"
};

/* @note See https://docs.zephyrproject.org/4.0.0/doxygen/html/group__tls__credentials.html#ga640ff6dd3eb4d5017feaab6fab2bb2f7 */
mender_err_t
mender_add_dormant_certs(void) {
    int ret;

    // Add main certificate
    ret = tls_credential_add(
        CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_DORMANT_A, TLS_CREDENTIAL_CA_CERTIFICATE, dormant_certificate_a, sizeof(dormant_certificate_a));

    if (0 != ret) {
        mender_log_error("Failed to add dormant certificate A. (result = %d, error: %s)", ret, strerror(errno));
        return MENDER_FAIL;
    }

    // Add backup certificate
    ret = tls_credential_add(
        CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_DORMANT_B, TLS_CREDENTIAL_CA_CERTIFICATE, dormant_certificate_b, sizeof(dormant_certificate_b));

    if (0 != ret) {
        mender_log_error("Failed to add dormant certificate B. (result = %d, error: %s)", ret, strerror(errno));
        return MENDER_FAIL;
    }

    return MENDER_OK;
}
