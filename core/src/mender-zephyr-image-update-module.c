/**
 * @file      mender-zephyr-image-update-module.c
 * @brief     The basic Zephyr update module based on MCUboot
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

#include "mender-client.h"
#include "mender-flash.h"
#include "mender-log.h"
#include "mender-update-module.h"
#include "mender-zephyr-image-update-module.h"

/**
 * @brief Flash handle used to store temporary reference to write rootfs-image data
 */
static void *mcu_boot_flash_handle = NULL;

mender_err_t
mender_zephyr_image_register_update_module(void) {
    mender_err_t            ret;
    mender_update_module_t *zephyr_image_umod;

    /* Register the zephyr-image update module */
    if (NULL == (zephyr_image_umod = malloc(sizeof(mender_update_module_t)))) {
        mender_log_error("Unable to allocate memory for the 'zephyr-image' update module");
        return MENDER_FAIL;
    }
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_DOWNLOAD] = &mender_zephyr_image_download_artifact_flash_callback;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_INSTALL]  = &mender_zephyr_image_ensure_pending_image;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_REBOOT]   = &mender_zephyr_image_reboot_callback;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_FAILURE]  = &mender_zephyr_image_ensure_abort_deployment;
    zephyr_image_umod->artifact_type                           = "zephyr-image";
    zephyr_image_umod->requires_reboot                         = true;
    zephyr_image_umod->supports_rollback                       = false; /* TODO: support rollback */

    if (MENDER_OK != (ret = mender_client_register_update_module(zephyr_image_umod))) {
        mender_log_error("Unable to register the 'zephyr-image' update module");
        /* mender_client_register_update_module() takes ownership if it succeeds */
        free(zephyr_image_umod);
        return ret;
    }

    return MENDER_OK;
}

mender_err_t
mender_zephyr_image_download_artifact_flash_callback(NDEBUG_UNUSED mender_update_state_t state, mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_DOWNLOAD == state);

    struct mender_update_download_state_data_s *dl_data = callback_data.download_state_data;
    mender_err_t                                ret     = MENDER_OK;

    /* Check if the filename is provided */
    if (NULL != dl_data->filename) {
        /* Check if the flash handle must be opened */
        if (0 == dl_data->offset) {
            /* Open the flash handle */
            if (MENDER_OK != (ret = mender_flash_open(dl_data->filename, dl_data->size, &mcu_boot_flash_handle))) {
                mender_log_error("Unable to open flash handle");
                goto END;
            }
        }

        /* Write data */
        if (MENDER_OK != (ret = mender_flash_write(mcu_boot_flash_handle, dl_data->data, dl_data->offset, dl_data->length))) {
            mender_log_error("Unable to write data to flash");
            goto END;
        }

        /* Check if the flash handle must be closed */
        if (dl_data->offset + dl_data->length >= dl_data->size) {
            /* Close the flash handle */
            if (MENDER_OK != (ret = mender_flash_close(mcu_boot_flash_handle))) {
                mender_log_error("Unable to close flash handle");
                goto END;
            }
            mcu_boot_flash_handle = NULL;
        }
    }

    /* Set flags */
    mender_client_deployment_needs_set_pending_image = true;

END:

    return ret;
}

mender_err_t
mender_zephyr_image_ensure_pending_image(NDEBUG_UNUSED mender_update_state_t state, ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_INSTALL == state);
    mender_err_t ret;

    if (mender_client_deployment_needs_set_pending_image) {
        if (MENDER_OK != (ret = mender_flash_set_pending_image(mcu_boot_flash_handle))) {
            mender_log_error("Unable to set boot partition");
            return ret;
        }
    }
    return MENDER_OK;
}

mender_err_t
mender_zephyr_image_ensure_abort_deployment(NDEBUG_UNUSED mender_update_state_t state, ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_FAILURE == state);
    mender_err_t ret;

    if (mender_client_deployment_needs_set_pending_image) {
        if (MENDER_OK != (ret = mender_flash_abort_deployment(mcu_boot_flash_handle))) {
            mender_log_error("Unable to abort deployment");
            return ret;
        }
    }
    return MENDER_OK;
}

mender_err_t
mender_zephyr_image_reboot_callback(NDEBUG_UNUSED mender_update_state_t state, ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_REBOOT == state);
    /* Invoke restart callback, application is responsible to shutdown properly and restart the system */
    if (NULL != mender_client_callbacks.restart) {
        mender_client_callbacks.restart();
        return MENDER_OK;
    } else {
        mender_log_error("Reboot requested, but no reboot support");
        return MENDER_FAIL;
    }
}
