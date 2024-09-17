/**
 * @file      mender-inventory.h
 * @brief     Mender MCU Inventory implementation
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

#ifndef __MENDER_INVENTORY_H__
#define __MENDER_INVENTORY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-utils.h"

#ifdef CONFIG_MENDER_CLIENT_INVENTORY

/**
 * @brief Initialize mender inventory
 * @param interval The interval to perform inventory updates at
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_init(uint32_t interval);

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
 * @brief Set mender inventory
 * @param inventory Mender inventory key/value pairs table, must end with a NULL/NULL element, NULL if not defined
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_set(mender_keystore_t *inventory);

/**
 * @brief Function used to trigger execution of the inventory work
 * @note Calling this function is optional when the periodic execution of the work is configured
 * @note It only permits to execute the work as soon as possible to synchronize inventory
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_execute(void);

/**
 * @brief Release mender inventory
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_exit(void);

#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_INVENTORY_H__ */
