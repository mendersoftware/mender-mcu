/**
 * @file      mender-scheduler.h
 * @brief     Mender scheduler interface
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

#ifndef __MENDER_SCHEDULER_H__
#define __MENDER_SCHEDULER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-utils.h"

typedef mender_err_t (*mender_scheduler_work_function_t)(void);

/**
 * @brief Initializate the scheduler
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_scheduler_init(mender_scheduler_work_function_t func, int32_t interval);

/**
 * @brief Activate the Mender work
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_scheduler_activate(void);

/**
 * @brief Release the scheduler
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_scheduler_exit(void);

/**
 * @brief Function used to create a mutex
 * @param handle Mutex handle if the function succeeds, NULL otherwise
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_scheduler_mutex_create(void **handle);

/**
 * @brief Function used to take a mutex
 * @param handle Mutex handle
 * @param delay_ms Delay to obtain the mutex, -1 to block indefinitely (without a timeout)
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_scheduler_mutex_take(void *handle, int32_t delay_ms);

/**
 * @brief Function used to give a mutex
 * @param handle Mutex handle
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_scheduler_mutex_give(void *handle);

/**
 * @brief Function used to delete a mutex
 * @param handle Mutex handle
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_scheduler_mutex_delete(void *handle);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_SCHEDULER_H__ */
