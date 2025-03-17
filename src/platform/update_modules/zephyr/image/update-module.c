/**
 * @file      update-module.c
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

#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>

#include "client.h"
#include "log.h"
#include "update-module.h"
#include "utils.h"
#include "zephyr-image-update-module.h"

/**
 * @brief Flash handle used to store temporary reference to write rootfs-image data
 */
static struct flash_img_context *mcu_boot_flash_handle = NULL;

static bool artifact_had_payload;

static mender_err_t
mender_flash_open(const char *name, size_t size, struct flash_img_context **handle) {
    assert(NULL != name);
    assert(NULL != handle);

    int result;

    /* Print current file name and size */
    mender_log_info("Start flashing artifact '%s' with size %d", name, size);

    /* Allocate memory to store the flash handle */
    if (NULL == (*handle = mender_malloc(sizeof(struct flash_img_context)))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Begin deployment with sequential writes */
    if (0 != (result = flash_img_init(*handle))) {
        mender_log_error("flash_img_init failed (%d)", -result);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
mender_flash_write(struct flash_img_context *handle, const void *data, size_t index, size_t length) {
    (void)index;

    int result;

    /* Check flash handle */
    if (NULL == handle) {
        mender_log_error("Invalid flash handle");
        return MENDER_FAIL;
    }

    /* Write data received to the update partition */
    if (0 != (result = flash_img_buffered_write(handle, (const uint8_t *)data, length, false))) {
        mender_log_error("flash_img_buffered_write failed (%d)", -result);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
mender_flash_close(struct flash_img_context *handle) {
    int result;

    /* Check flash handle */
    if (NULL == handle) {
        mender_log_error("Invalid flash handle");
        return MENDER_FAIL;
    }

    /* Flush data received to the update partition */
    if (0 != (result = flash_img_buffered_write(handle, NULL, 0, true))) {
        mender_log_error("flash_img_buffered_write failed (%d)", -result);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
mender_flash_set_pending_image(struct flash_img_context **handle) {
    int result;

    /* Check flash handle */
    if (NULL != *handle) {

        /* Set new boot partition */
        if (0 != (result = boot_request_upgrade(BOOT_UPGRADE_TEST))) {
            mender_log_error("boot_request_upgrade failed (%d)", -result);
            return MENDER_FAIL;
        }

        /* Release memory */
        FREE_AND_NULL(*handle);
    } else {

        /* This should not happen! */
        mender_log_error("boot_request_upgrade not called, handle is NULL");
        return MENDER_NOT_FOUND;
    }

    return MENDER_OK;
}

static mender_err_t
mender_flash_abort_deployment(struct flash_img_context **handle) {
    /* Release memory */
    FREE_AND_NULL(*handle);

    return MENDER_OK;
}

static bool
mender_flash_is_image_confirmed(void) {
    /* Check if the image is still pending */
    return boot_is_img_confirmed();
}

static mender_err_t
mender_flash_confirm_image(void) {
    /* Validate the image if it is still pending */
    if (!mender_flash_is_image_confirmed()) {
        /* It's safe to call boot_write_img_confirmed() even though the current
         * image has already been confirmed. The check above is primarily to
         * control when the info message below is logged. */
        int result;
        if (0 != (result = boot_write_img_confirmed())) {
            mender_log_error("Unable to mark application valid, application will rollback (%d)", -result);
            return MENDER_FAIL;
        }
        mender_log_info("Application has been mark valid and rollback canceled");
    } else {

        /* This should not happen: if there is no pending image the deployment should
           have been already aborted in Artifact Verify Reboot state. */
        mender_log_error("Commit requested but there is no pending image con confirm");
        return MENDER_NOT_FOUND;
    }

    return MENDER_OK;
}

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
    if (NULL == (zephyr_image_umod = mender_calloc(1, sizeof(mender_update_module_t)))) {
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

    if (MENDER_OK != (ret = mender_update_module_register(zephyr_image_umod))) {
        mender_log_error("Unable to register the 'zephyr-image' update module");
        /* mender_update_module_register() takes ownership if it succeeds */
        mender_free(zephyr_image_umod);
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
        }
    }

    artifact_had_payload = true;
END:

    return ret;
}

static mender_err_t
mender_zephyr_image_set_pending_image(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_INSTALL == state);
    mender_err_t ret;

    if (!artifact_had_payload) {
        mender_log_error("No payload in artifact");
        return MENDER_FAIL;
    }
    artifact_had_payload = false;

    if (NULL == mcu_boot_flash_handle) {
        mender_log_error("Set pending image requested but handle is cleared");
        return MENDER_FAIL;
    }

    if (MENDER_OK != (ret = mender_flash_set_pending_image(&mcu_boot_flash_handle))) {
        mender_log_error("Unable to set boot partition");
        return ret;
    }
    return MENDER_OK;
}

static mender_err_t
mender_zephyr_image_abort_deployment(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_FAILURE == state);
    mender_err_t ret;

    if (MENDER_OK != (ret = mender_flash_abort_deployment(&mcu_boot_flash_handle))) {
        mender_log_error("Unable to abort deployment");
        return ret;
    }
    artifact_had_payload = false;
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

    return MENDER_OK;
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
