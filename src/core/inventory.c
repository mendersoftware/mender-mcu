/**
 * @file      inventory.c
 * @brief     Mender MCU Inventory implementation
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

#include "mender-api.h"
#include "mender-client.h"
#include "mender-inventory.h"
#include "mender-log.h"
#include "mender-os.h"

#ifdef CONFIG_MENDER_CLIENT_INVENTORY

/**
 * @brief Default inventory refresh interval (seconds)
 */
#ifndef CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL
#define CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL (28800)
#endif /* CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL */

/**
 * @brief Mender inventory keystore
 */
static mender_keystore_t *mender_inventory_keystore = NULL;
static void              *mender_inventory_mutex    = NULL;

/**
 * @brief Mender inventory work handle
 */
static mender_work_t *mender_inventory_work = NULL;

/**
 * @brief Mender inventory work function
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_inventory_work_function(void);

mender_err_t
mender_inventory_init(uint32_t interval) {
    mender_err_t ret;

    /* Create inventory mutex */
    if (MENDER_OK != (ret = mender_os_mutex_create(&mender_inventory_mutex))) {
        mender_log_error("Unable to create inventory mutex");
        return ret;
    }

    /* Create mender inventory work */
    mender_os_scheduler_work_params_t inventory_work_params;
    inventory_work_params.function = mender_inventory_work_function;
    inventory_work_params.period   = (0 != interval ? interval : CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL);
    inventory_work_params.name     = "mender_inventory";
    if (MENDER_OK != (ret = mender_os_scheduler_work_create(&inventory_work_params, &mender_inventory_work))) {
        mender_log_error("Unable to create inventory work");
        return ret;
    }

    return ret;
}

mender_err_t
mender_inventory_activate(void) {

    mender_err_t ret;

    /* Activate inventory work */
    if (MENDER_OK != (ret = mender_os_scheduler_work_activate(mender_inventory_work))) {
        mender_log_error("Unable to activate inventory work");
        return ret;
    }

    return ret;
}

mender_err_t
mender_inventory_deactivate(void) {

    /* Deactivate mender inventory work */
    mender_os_scheduler_work_deactivate(mender_inventory_work);

    return MENDER_OK;
}

mender_err_t
mender_inventory_set(mender_keystore_t *inventory) {

    mender_err_t ret;

    /* Take mutex used to protect access to the inventory key-store */
    if (MENDER_OK != (ret = mender_os_mutex_take(mender_inventory_mutex, -1))) {
        mender_log_error("Unable to take mutex");
        return ret;
    }

    /* Release previous inventory */
    if (MENDER_OK != (ret = mender_utils_keystore_delete(mender_inventory_keystore))) {
        mender_log_error("Unable to delete inventory");
        goto END;
    }

    /* Copy the new inventory */
    if (MENDER_OK != (ret = mender_utils_keystore_copy(&mender_inventory_keystore, inventory))) {
        mender_log_error("Unable to copy inventory");
        goto END;
    }

END:

    /* Release mutex used to protect access to the inventory key-store */
    mender_os_mutex_give(mender_inventory_mutex);

    return ret;
}

mender_err_t
mender_inventory_execute(void) {

    mender_err_t ret;

    /* Trigger execution of the work */
    if (MENDER_OK != (ret = mender_os_scheduler_work_execute(mender_inventory_work))) {
        mender_log_error("Unable to trigger inventory work");
        return ret;
    }

    return MENDER_OK;
}

mender_err_t
mender_inventory_exit(void) {

    mender_err_t ret;

    /* Delete mender inventory work */
    mender_os_scheduler_work_delete(mender_inventory_work);
    mender_inventory_work = NULL;

    /* Take mutex used to protect access to the inventory key-store */
    if (MENDER_OK != (ret = mender_os_mutex_take(mender_inventory_mutex, -1))) {
        mender_log_error("Unable to take mutex");
        return ret;
    }

    /* Release memory */
    DESTROY_AND_NULL(mender_utils_keystore_delete, mender_inventory_keystore);
    mender_os_mutex_give(mender_inventory_mutex);
    DESTROY_AND_NULL(mender_os_mutex_delete, mender_inventory_mutex);

    return ret;
}

static mender_err_t
mender_inventory_work_function(void) {

    mender_err_t ret;

    /* Take mutex used to protect access to the inventory key-store */
    if (MENDER_OK != (ret = mender_os_mutex_take(mender_inventory_mutex, -1))) {
        mender_log_error("Unable to take mutex");
        return ret;
    }

    /* Request access to the network */
    if (MENDER_FAIL == (ret = mender_client_ensure_connected())) {
        mender_log_error("Requesting access to the network failed");
        goto END;
    }

    /* Publish inventory */
    if (MENDER_OK != (ret = mender_api_publish_inventory_data(mender_inventory_keystore))) {
        mender_log_error("Unable to publish inventory data");
    }

END:

    /* Release mutex used to protect access to the inventory key-store */
    mender_os_mutex_give(mender_inventory_mutex);

    return ret;
}

#endif /* CONFIG_MENDER_CLIENT_INVENTORY */
