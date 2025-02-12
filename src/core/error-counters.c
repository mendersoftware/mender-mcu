/**
 * @file      mender-error-counters.c
 * @brief     Mender Error counters implementation
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

#include <stdint.h>

#include "mender-error-counters.h"
#include "mender-log.h"
#include "mender-utils.h"

#if CONFIG_MENDER_ERRORS_THRESHOLD_NET > 0

static uint8_t net_errors = 0;
#if CONFIG_MENDER_ERRORS_THRESHOLD_NET > UINT8_MAX
#error "CONFIG_MENDER_ERRORS_THRESHOLD_NET must be <= UINT8_MAX"
#endif

mender_err_t
mender_err_count_net_inc(void) {
    if (net_errors < UINT8_MAX) {
        net_errors++;
    }
    if (net_errors > CONFIG_MENDER_ERRORS_THRESHOLD_NET) {
        mender_log_warning("Network errors limit exceeded");
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

mender_err_t
mender_err_count_net_check(void) {
    if (net_errors > CONFIG_MENDER_ERRORS_THRESHOLD_NET) {
        mender_log_warning("Network errors limit exceeded");
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

mender_err_t
mender_err_count_net_reset(void) {
    net_errors = 0;
    return MENDER_OK;
}
#endif /* CONFIG_MENDER_ERRORS_THRESHOLD_NET > 0 */

#if CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT > 0

static uint8_t reboot_errors = 0;
#if CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT > UINT8_MAX
#error "CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT must be <= UINT8_MAX"
#endif

mender_err_t
mender_err_count_reboot_inc(void) {
    if (reboot_errors < UINT8_MAX) {
        reboot_errors++;
    }
    if (reboot_errors > CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT) {
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

mender_err_t
mender_err_count_reboot_reset(void) {
    reboot_errors = 0;
    return MENDER_OK;
}
#endif /* CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT > 0 */
