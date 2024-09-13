/**
 * @file      mender-flash.c
 * @brief     Mender flash interface for Zephyr platform
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

#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/sys/reboot.h>
#include "mender-flash.h"
#include "mender-log.h"

mender_err_t
mender_flash_open(char *name, size_t size, void **handle) {

    assert(NULL != name);
    assert(NULL != handle);
    int result;

    /* Print current file name and size */
    mender_log_info("Start flashing artifact '%s' with size %d", name, size);

    /* Allocate memory to store the flash handle */
    if (NULL == (*handle = malloc(sizeof(struct flash_img_context)))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Begin deployment with sequential writes */
    if (0 != (result = flash_img_init((struct flash_img_context *)*handle))) {
        mender_log_error("flash_img_init failed (%d)", -result);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_flash_write(void *handle, void *data, size_t index, size_t length) {

    (void)index;
    int result;

    /* Check flash handle */
    if (NULL == handle) {
        mender_log_error("Invalid flash handle");
        return MENDER_FAIL;
    }

    /* Write data received to the update partition */
    if (0 != (result = flash_img_buffered_write((struct flash_img_context *)handle, (const uint8_t *)data, length, false))) {
        mender_log_error("flash_img_buffered_write failed (%d)", -result);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_flash_close(void *handle) {

    int result;

    /* Check flash handle */
    if (NULL == handle) {
        mender_log_error("Invalid flash handle");
        return MENDER_FAIL;
    }

    /* Flush data received to the update partition */
    if (0 != (result = flash_img_buffered_write((struct flash_img_context *)handle, NULL, 0, true))) {
        mender_log_error("flash_img_buffered_write failed (%d)", -result);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_flash_set_pending_image(void *handle) {

    int result;

    /* Check flash handle */
    if (NULL != handle) {

        /* Set new boot partition */
        if (0 != (result = boot_request_upgrade(BOOT_UPGRADE_TEST))) {
            mender_log_error("boot_request_upgrade failed (%d)", -result);
            return MENDER_FAIL;
        }

        /* Release memory */
        free(handle);
    } else {

        /* This should not happen! */
        mender_log_error("boot_request_upgrade not called, handle is NULL");
        return MENDER_NOT_FOUND;
    }

    return MENDER_OK;
}

mender_err_t
mender_flash_abort_deployment(void *handle) {

    /* Release memory */
    free(handle);

    return MENDER_OK;
}

mender_err_t
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

bool
mender_flash_is_image_confirmed(void) {

    /* Check if the image is still pending */
    return boot_is_img_confirmed();
}
