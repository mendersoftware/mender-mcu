/**
 * @file      update-module.c
 * @brief     The basic ESP-IDF update module based on ESP OTA
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

#include <errno.h>
#include <esp_ota_ops.h>

#include "client.h"
#include "log.h"
#include "update-module.h"
#include "utils.h"
#include "esp-ota-update-module.h"

#define OTA_HANDLE_INVALID 0
static esp_ota_handle_t       ota_handle    = OTA_HANDLE_INVALID;
static const esp_partition_t *ota_partition = NULL;

static bool artifact_had_payload;

static mender_err_t
handle_open(const char *name, size_t size, const esp_partition_t **partition, esp_ota_handle_t *handle) {
    assert(NULL != name);
    assert(0 != handle);

    esp_err_t err;

    /* Print current file name and size */
    mender_log_info("Start flashing artifact '%s' with size %d", name, size);

    *partition = esp_ota_get_next_update_partition(NULL);
    if (NULL == partition) {
        mender_log_error("Failed to find next update partition");
        return MENDER_FAIL;
    }
    mender_log_debug("Next update partition is '%s' (size: %d)", (*partition)->label, (*partition)->size);

    err = esp_ota_begin(*partition, size, handle);
    if (ESP_OK != err) {
        mender_log_error("Failed to start an OTA update: %s", esp_err_to_name(err));
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
handle_write(esp_ota_handle_t handle, const void *data, size_t length) {
    assert(0 != handle);
    assert((NULL != data) || (0 == length));

    esp_err_t err = esp_ota_write(handle, data, length);
    if (ESP_OK != err) {
        mender_log_error("Failed to write update data: %s", esp_err_to_name(err));
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

/**
 * @note Invalidates #handle
 */
static mender_err_t
handle_close(esp_ota_handle_t handle) {
    assert(0 != handle);

    esp_err_t err = esp_ota_end(handle);
    if (ESP_OK != err) {
        if (ESP_ERR_OTA_VALIDATE_FAILED == err) {
            mender_log_error("Update validation failed, image is corrupt");
        } else {
            mender_log_error("Failed to finish OTA update: %s", esp_err_to_name(err));
        }
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
set_pending_image(const esp_partition_t *partition) {
    assert(NULL != partition);

    esp_err_t err = esp_ota_set_boot_partition(partition);
    if (ESP_OK != err) {
        mender_log_error("Failed to set pending update partition: %s", esp_err_to_name(err));
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static bool
is_image_confirmed(void) {
    esp_err_t              err;
    esp_ota_img_states_t   img_state;
    const esp_partition_t *partition;

    if (NULL == (partition = esp_ota_get_running_partition())) {
        mender_log_error("Failed to get running partition");
        return false;
    }

    err = esp_ota_get_state_partition(partition, &img_state);
    if (ESP_OK != err) {
        mender_log_error("Failed to get state of the running partition: %s", esp_err_to_name(err));
        return false;
    }

    return (ESP_OTA_IMG_VALID == img_state);
}

static mender_err_t
confirm_image(void) {
    esp_err_t err;
    if (!is_image_confirmed()) {
        err = esp_ota_mark_app_valid_cancel_rollback();
        if (ESP_OK != err) {
            mender_log_error("Failed to mark application valid (%s), application will rollback", esp_err_to_name(err));
            return MENDER_FAIL;
        }
        mender_log_info("Application has been mark valid and rollback canceled");
    } else {
        /* This should not happen: if there is no pending image the deployment should
           have been already aborted in Artifact Verify Reboot state. */
        mender_log_error("Commit requested but there is no pending image to confirm");
        return MENDER_NOT_FOUND;
    }

    return MENDER_OK;
}

/**
 * @brief Callback function to be invoked to perform the treatment of the data from the artifact type "esp-ota"
 * @return MENDER_OK if the function succeeds, error code if an error occurred
 */
static mender_err_t mender_esp_ota_download_artifact_flash_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Artifact installation callback to make sure MCUboot is set to switch to the new image
 */
static mender_err_t mender_esp_ota_set_pending_image(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Update failure callback
 */
static mender_err_t mender_esp_ota_abort_deployment(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Cleanup callback
 */
static mender_err_t mender_esp_ota_cleanup(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Reboot callback
 */
static mender_err_t mender_esp_ota_reboot_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Rollback callback
 */
static mender_err_t mender_esp_ota_rollback_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief New image verification callback
 */
static mender_err_t mender_esp_ota_verify_reboot_callback(mender_update_state_t state, mender_update_state_data_t callback_data);

/**
 * @brief Commit callback that confirms the booted image
 */
static mender_err_t mender_esp_ota_confirm_image(mender_update_state_t state, mender_update_state_data_t callback_data);

mender_err_t
mender_esp_ota_register_update_module(void) {
    mender_err_t            ret;
    mender_update_module_t *esp_ota_umod;

    /* Register the esp-ota update module */
    if (NULL == (esp_ota_umod = mender_calloc(1, sizeof(mender_update_module_t)))) {
        mender_log_error("Unable to allocate memory for the 'esp-ota' update module");
        return MENDER_FAIL;
    }
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_DOWNLOAD]        = &mender_esp_ota_download_artifact_flash_callback;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_INSTALL]         = &mender_esp_ota_set_pending_image;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_REBOOT]          = &mender_esp_ota_reboot_callback;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_VERIFY_REBOOT]   = &mender_esp_ota_verify_reboot_callback;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_COMMIT]          = &mender_esp_ota_confirm_image;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_FAILURE]         = &mender_esp_ota_abort_deployment;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_CLEANUP]         = &mender_esp_ota_cleanup;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_ROLLBACK]        = &mender_esp_ota_rollback_callback;
    esp_ota_umod->callbacks[MENDER_UPDATE_STATE_ROLLBACK_REBOOT] = &mender_esp_ota_reboot_callback;
    esp_ota_umod->artifact_type                                  = "esp-ota";
    esp_ota_umod->requires_reboot                                = true;
    esp_ota_umod->supports_rollback                              = true;

    if (MENDER_OK != (ret = mender_update_module_register(esp_ota_umod))) {
        mender_log_error("Failed to register the 'esp-ota' update module");
        /* mender_update_module_register() takes ownership if it succeeds */
        mender_free(esp_ota_umod);
        return ret;
    }

    return MENDER_OK;
}

static mender_err_t
mender_esp_ota_download_artifact_flash_callback(MENDER_NDEBUG_UNUSED mender_update_state_t state, mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_DOWNLOAD == state);

    struct mender_update_download_state_data_s *dl_data = callback_data.download_state_data;
    mender_err_t                                ret     = MENDER_OK;

    /* Check if the filename is provided */
    if (NULL != dl_data->filename) {
        /* Check if the OTA handle must be opened */
        if (0 == dl_data->offset) {
            /* Open the OTA handle */
            if (MENDER_OK != (ret = handle_open(dl_data->filename, dl_data->size, &ota_partition, &ota_handle))) {
                /* error already logged */
                goto END;
            }
        }

        /* Write data */
        if (MENDER_OK != (ret = handle_write(ota_handle, dl_data->data, dl_data->length))) {
            /* error already logged */
            goto END;
        }

        /* Check if the OTA handle should be closed */
        if (dl_data->offset + dl_data->length >= dl_data->size) {
            /* Close the OTA handle */
            if (MENDER_OK != (ret = handle_close(ota_handle))) {
                /* error already logged */
                goto END;
            }
        }
    }

    artifact_had_payload = true;
END:

    return ret;
}

static mender_err_t
mender_esp_ota_set_pending_image(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_INSTALL == state);

    mender_err_t ret;

    if (!artifact_had_payload) {
        mender_log_error("No payload in artifact");
        return MENDER_FAIL;
    }
    artifact_had_payload = false;

    if (NULL == ota_partition) {
        mender_log_error("Set pending image requested with no OTA partition identified");
        return MENDER_FAIL;
    }

    if (MENDER_OK != (ret = set_pending_image(ota_partition))) {
        mender_log_error("Unable to set pending boot image");
        return ret;
    }
    return MENDER_OK;
}

static mender_err_t
mender_esp_ota_abort_deployment(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_FAILURE == state);

    const esp_partition_t *partition;
    esp_ota_img_states_t   img_state;
    esp_err_t              err;

    if (OTA_HANDLE_INVALID != ota_handle) {
        err = esp_ota_abort(ota_handle);
        if (ESP_OK != err) {
            mender_log_error("Failed to abort deployment: %s", esp_err_to_name(err));
            return MENDER_FAIL;
        }
        ota_handle = OTA_HANDLE_INVALID;
    }
    artifact_had_payload = false;

    if (NULL == (partition = esp_ota_get_running_partition())) {
        mender_log_error("Failed to get running partition");
        return MENDER_FAIL;
    }
    err = esp_ota_get_state_partition(partition, &img_state);
    if (ESP_OK != err) {
        mender_log_error("Failed to get state of the running partition: %s", esp_err_to_name(err));
        return MENDER_FAIL;
    }
    if (ESP_OTA_IMG_VALID == img_state) {
        /* We are running a confirmed/valid image, i.e. this abort is happening
           while still being on the old image. We need to make sure the next
           reboot (triggered by anything) doesn't boot into the flashed update
           image/partition. */
        err = esp_ota_set_boot_partition(partition);
        if (ESP_OK != err) {
            mender_log_error("Failed to reset boot partition on a deployment aborted before reboot: %s", esp_err_to_name(err));
            return MENDER_FAIL;
        }
    }
    return MENDER_OK;
}

static mender_err_t
mender_esp_ota_cleanup(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_CLEANUP == state);

    esp_err_t err;
    if (OTA_HANDLE_INVALID != ota_handle) {
        err = esp_ota_abort(ota_handle);
        if (ESP_OK != err) {
            mender_log_error("Failed to abort deployment: %s", esp_err_to_name(err));
            return MENDER_FAIL;
        }
        ota_handle = OTA_HANDLE_INVALID;
    }
    return MENDER_OK;
}

static mender_err_t
mender_esp_ota_reboot_callback(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
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
mender_esp_ota_rollback_callback(mender_update_state_t state, mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_ROLLBACK == state);

    // Don't attempt to rollback if we're in a confirmed image - e.g. if an aborted deployment is detected in `MENDER_UPDATE_STATE_REBOOT`
    if (is_image_confirmed()) {
        mender_log_debug("Current image is confirmed, nothing to rollback");
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

static mender_err_t
mender_esp_ota_verify_reboot_callback(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_VERIFY_REBOOT == state);

    if (is_image_confirmed()) {
        /* There is no pending image to confirm - we likely booted into the "old" confirmed image */
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
mender_esp_ota_confirm_image(MENDER_NDEBUG_UNUSED mender_update_state_t state, MENDER_ARG_UNUSED mender_update_state_data_t callback_data) {
    assert(MENDER_UPDATE_STATE_COMMIT == state);

    return confirm_image();
}
