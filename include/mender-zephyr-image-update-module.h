/**
 * @file      mender-zephyr-image-update-module.h
 * @brief     The basic Zephyr update module based on MCUboot
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

#ifndef __MENDER_ZEPHYR_IMAGE_UPDATE_MODULE_H__
#define __MENDER_ZEPHYR_IMAGE_UPDATE_MODULE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-update-module.h"

#ifdef CONFIG_MENDER_ZEPHYR_IMAGE_UPDATE_MODULE

/**
 * @brief  Register the 'zephyr-image' update module
 * @return MENDER_OK if successfully registered, error code otherwise
 */
mender_err_t mender_zephyr_image_register_update_module(void);

/**
 * @brief Callback function to be invoked to perform the treatment of the data from the artifact type "zephyr-image"
 * @return MENDER_OK if the function succeeds, error code if an error occurred
 */
mender_err_t mender_zephyr_image_download_artifact_flash_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Artifact installation callback to make sure MCUboot is set to switch to the new image
 */
mender_err_t mender_zephyr_image_set_pending_image(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Update failure callback
 */
mender_err_t mender_zephyr_image_abort_deployment(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Reboot callback
 */
mender_err_t mender_zephyr_image_reboot_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

#endif /* CONFIG_MENDER_ZEPHYR_IMAGE_UPDATE_MODULE */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_ZEPHYR_IMAGE_UPDATE_MODULE_H__ */
