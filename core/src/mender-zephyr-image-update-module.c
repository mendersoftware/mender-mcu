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

/**
 * @brief Callback function to be invoked to perform the treatment of the data from the artifact type "zephyr-image"
 * @return MENDER_OK if the function succeeds, error code if an error occurred
 */
static mender_err_t mender_zephyr_image_download_artifact_flash_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Artifact installation callback to make sure MCUboot is set to switch to the new image
 */
static mender_err_t mender_zephyr_image_set_pending_image(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Update failure callback
 */
static mender_err_t mender_zephyr_image_abort_deployment(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Reboot callback
 */
static mender_err_t mender_zephyr_image_reboot_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief New image verification callback
 */
static mender_err_t mender_zephyr_image_verify_reboot_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Commit callback that confirms the booted image
 */
static mender_err_t mender_zephyr_image_confirm_image(mender_update_state_t state, mender_update_state_data_t callback_data);

mender_err_t
mender_zephyr_image_register_update_module(void) {
    mender_err_t            ret;
    mender_update_module_t *zephyr_image_umod;

    /* Register the zephyr-image update module */
    if (NULL == (zephyr_image_umod = calloc(1, sizeof(mender_update_module_t)))) {
        mender_log_error("Unable to allocate memory for the 'zephyr-image' update module");
        return MENDER_FAIL;
    }
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_DOWNLOAD]      = &mender_zephyr_image_download_artifact_flash_callback;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_INSTALL]       = &mender_zephyr_image_set_pending_image;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_REBOOT]        = &mender_zephyr_image_reboot_callback;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_VERIFY_REBOOT] = &mender_zephyr_image_verify_reboot_callback;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_COMMIT]        = &mender_zephyr_image_confirm_image;
    /* no need for a rollback callback because a reboot without image confirmation is a rollback */
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_FAILURE]         = &mender_zephyr_image_abort_deployment;
    zephyr_image_umod->callbacks[MENDER_UPDATE_STATE_ROLLBACK_REBOOT] = &mender_zephyr_image_reboot_callback;
    zephyr_image_umod->artifact_type                                  = "zephyr-image";
    zephyr_image_umod->requires_reboot                                = true;
    zephyr_image_umod->supports_rollback                              = true;

    if (MENDER_OK != (ret = mender_client_register_update_module(zephyr_image_umod))) {
        mender_log_error("Unable to register the 'zephyr-image' update module");
        /* mender_client_register_update_module() takes ownership if it succeeds */
        free(zephyr_image_umod);
        return ret;
    }

    return MENDER_OK;
}

static mender_err_t
mender_zephyr_image_download_artifact_flash_callback(MENDER_NDEBUG_UNUSED mender_update_state_t state, mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_DOWNLOAD == state);

    struct mender_update_download_state_data_s *dl_data = callback_data.download_state_data;
    mender_err_t                                ret     = MENDER_OK;

    /* Check if the filename is provided */
    if (NULL != dl_data->filename) {
        // TODO remove (here and below) in favor of debug logging once the logging is under control
        printf(".");

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

            printf("DONE\n");

            /* Close the flash handle */
            if (MENDER_OK != (ret = mender_flash_close(mcu_boot_flash_handle))) {
                mender_log_error("Unable to close flash handle");
                goto END;
            }
        }
    }

END:

    return ret;
}

static mender_err_t
mender_zephyr_image_set_pending_image(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_INSTALL == state);
    mender_err_t ret;

    if (NULL == mcu_boot_flash_handle) {
        mender_log_error("Set pending image requested but handle is cleared");
        return MENDER_FAIL;
    }

    if (MENDER_OK != (ret = mender_flash_set_pending_image(mcu_boot_flash_handle))) {
        mender_log_error("Unable to set boot partition");
        return ret;
    }
    return MENDER_OK;
}

static mender_err_t
mender_zephyr_image_abort_deployment(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_FAILURE == state);
    mender_err_t ret;

    if (MENDER_OK != (ret = mender_flash_abort_deployment(mcu_boot_flash_handle))) {
        mender_log_error("Unable to abort deployment");
        return ret;
    }
    return MENDER_OK;
}

static mender_err_t
mender_zephyr_image_reboot_callback(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_REBOOT == state || MENDER_UPDATE_STATE_ROLLBACK_REBOOT == state);
    /* Invoke restart callback, application is responsible to shutdown properly and restart the system */
    if (NULL != mender_client_callbacks.restart) {
        mender_client_callbacks.restart();
        return MENDER_OK;
    } else {
        mender_log_error("Reboot requested, but no reboot support");
        return MENDER_FAIL;
    }
}

static mender_err_t
mender_zephyr_image_verify_reboot_callback(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_VERIFY_REBOOT == state);

    if (mender_flash_is_image_confirmed()) {
        /* There is no pending image to confirm - we likely booted into the "old" confirmed image */
        return MENDER_FAIL;
    }

    return (MENDER_FAIL == mender_client_ensure_authenticated()) ? MENDER_FAIL : MENDER_OK;
}

static mender_err_t
mender_zephyr_image_confirm_image(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_COMMIT == state);

    mender_err_t ret = mender_flash_confirm_image();
    if (MENDER_OK != ret) {
        mender_log_error("Failed to confirm the new image");
    }

    return ret;
}
