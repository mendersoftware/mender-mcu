/**
 * @file      mender-error-counters.h
 * @brief     Mender Error Counters interface
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

#ifndef __MENDER_ERROR_COUNTERS_H__
#define __MENDER_ERROR_COUNTERS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mender-utils.h>

#ifndef CONFIG_MENDER_ERRORS_THRESHOLD_NET
#define CONFIG_MENDER_ERRORS_THRESHOLD_NET 0
#endif

#if CONFIG_MENDER_ERRORS_THRESHOLD_NET > 0

/**
 * @brief Increment the network errors counter
 * @return MENDER_OK if not too many errors, MENDER_FAIL if too many errors
 */
mender_err_t mender_err_count_net_inc(void);

/**
 * @brief Check the network errors counter
 * @return MENDER_OK if not too many errors, MENDER_FAIL if too many errors
 */
mender_err_t mender_err_count_net_check(void);

/**
 * @brief Reset the network errors counter
 * @return MENDER_OK if successful, error otherwise
 */
mender_err_t mender_err_count_net_reset(void);

#else

/* Define the functions as inline noops so that the compiler can simply rule them out. */
inline mender_err_t
mender_err_count_net_inc(void) {
    return MENDER_OK;
}
inline mender_err_t
mender_err_count_net_check(void) {
    return MENDER_OK;
}
inline mender_err_t
mender_err_count_net_reset(void) {
    return MENDER_OK;
}

#endif /* CONFIG_MENDER_ERRORS_THRESHOLD_NET > 0 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_ERROR_COUNTERS_H__ */
