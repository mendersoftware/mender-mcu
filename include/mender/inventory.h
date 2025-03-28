/**
 * @file      inventory.h
 * @brief     Mender MCU Inventory implementation (public API)
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

#include <mender/utils.h>

#ifndef CONFIG_MENDER_CLIENT_INVENTORY_DISABLE

/**
 * @brief Inventory callback type
 * @param inventory     Output argument for the inventory items array pointer
 * @param inventory_len Length of the array pointed to by #inventory (limited by the type to 255
 *                      items which should be more than enough)
 * @return %MENDER_OK in case of success, error otherwise
 */
typedef mender_err_t(MenderInventoryCallback)(mender_keystore_t **inventory, uint8_t *inventory_len);

/**
 * @brief Add mender inventory callback
 * @param callback   A function to call to obtain inventory information
 * @param persistent Whether the inventory information is persistent or dynamic (see notes below)
 * @return MENDER_OK if the function succeeds, error code otherwise
 * @note Persistent inventory data is only obtained and sent to the server once in the run of the
 *       client, i.e. during the first successful inventory submission. Dynamic inventory data is
 *       obtained and sent to the server at every inventory submission (interval).
 * @note Persistent inventory data is *considered static*, dynamic data is considered
 *       heap-allocated, with ownership being transferred (IOW, the Mender client deallocates the
 *       data when no longer needed). This applies to both the container (array) and the actual
 *       data (key-value pairs).
 */
mender_err_t mender_inventory_add_callback(MenderInventoryCallback callback, bool persistent);

/**
 * @brief Function used to trigger execution of the inventory work
 * @note Calling this function is optional when the periodic execution of the work is configured
 * @note It only permits to execute the work as soon as possible to synchronize inventory
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_inventory_execute(void);

#endif /* CONFIG_MENDER_CLIENT_INVENTORY_DISABLE */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_INVENTORY_H__ */
