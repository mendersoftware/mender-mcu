/**
 * @file      inventory.h
 * @brief     Mender MCU Inventory implementation (private API)
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

#ifndef __MENDER_INVENTORY_PRIV_H__
#define __MENDER_INVENTORY_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mender/inventory.h>

/**
 * @brief Initialize mender inventory
 * @param interval The interval to perform inventory updates at
 * @param device_type Device type
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_init(uint32_t interval, const char *device_type);

/**
 * @brief Reset persistent inventory
 * @return MENDER_OK in case of success, error code otherwise
 * @note The persistent inventory callbacks are called to get fresh data the next time inventory data
 *       is needed.
 */
mender_err_t mender_inventory_reset_persistent(void);

/**
 * @brief Add default inventory callbacks
 * @return MENDER_OK in case of success, error code otherwise
 */
mender_err_t mender_inventory_add_default_callbacks(void);

/**
 * @brief Activate mender inventory
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_activate(void);

/**
 * @brief Deactivate mender inventory
 * @note This function stops synchronization with the server
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_deactivate(void);

/**
 * @brief Trigger execution of the inventory work
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_execute(void);

/**
 * @brief Release mender inventory
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_exit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_INVENTORY_PRIV_H__ */
