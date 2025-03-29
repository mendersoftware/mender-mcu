/**
 * @file      log.h
 * @brief     Mender logging interface (private API)
 *
 * Copyright joelguittet and mender-mcu-client contributors
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

#ifndef __MENDER_LOG_PRIV_H__
#define __MENDER_LOG_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mender/log.h>

/**
 * @brief Initialize mender log
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_log_init(void);

/**
 * @brief Release mender log
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_log_exit(void);

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
/**
 * @brief Activate deployment logs gathering
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_deployment_logs_activate(void);

/**
 * @brief Deactivate deployment logs gathering
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_deployment_logs_deactivate(void);
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_LOG_PRIV_H__ */
