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

#include "api.h"
#include "client.h"
#include "inventory.h"
#include "log.h"
#include "os.h"
#include "storage.h"

#ifndef CONFIG_MENDER_CLIENT_INVENTORY_DISABLE

typedef struct {
    MenderInventoryCallback *callback;
    bool                     persistent;
} callback_item_t;

typedef struct keystores_item_t {
    mender_keystore_t       *keystore;
    uint8_t                  keystore_len;
    struct keystores_item_t *next;
} keystores_item_t;

/**
 * @brief Default inventory refresh interval (seconds)
 */
#ifndef CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL
#define CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL (1209600)
#endif /* CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL */

/**
 * @brief Mender inventory keystore
 */
static callback_item_t  *callbacks              = NULL;
static uint8_t           n_callbacks            = 0;
static uint8_t           n_persistent_callbacks = 0;
static uint8_t           callbacks_len          = 0;
static keystores_item_t *persistent_inventory   = NULL;
static bool              full_push_done         = false;
static void             *mender_inventory_mutex = NULL;

#define N_CALLBACKS_INIT 4
#define N_CALLBACKS_MAX  16

/**
 * @brief Mender inventory work handle
 */
static mender_work_t *mender_inventory_work = NULL;

static const char *device_type = NULL;

static mender_keystore_t *provides_inventory     = NULL;
static uint8_t            provides_inventory_len = 0;

/**
 * @brief Mender inventory work function
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_inventory_work_function(void);

static mender_err_t artifact_name_device_type_cb(mender_keystore_t **inventory, uint8_t *inventory_len);
static mender_err_t provides_cb(mender_keystore_t **inventory, uint8_t *inventory_len);

mender_err_t
mender_inventory_init(uint32_t interval, const char *dev_type, uint16_t backoff_interval, uint16_t max_backoff_interval) {
    mender_err_t ret;

    /* Create inventory mutex */
    if (MENDER_OK != (ret = mender_os_mutex_create(&mender_inventory_mutex))) {
        mender_log_error("Unable to create inventory mutex");
        return ret;
    }

    device_type = dev_type;

    callbacks = mender_calloc(N_CALLBACKS_INIT, sizeof(callback_item_t));
    if (NULL == callbacks) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    callbacks_len  = N_CALLBACKS_INIT;
    full_push_done = false;

    /* Create mender inventory work */
    mender_os_scheduler_work_params_t inventory_work_params;
    inventory_work_params.function             = mender_inventory_work_function;
    inventory_work_params.period               = (0 != interval ? interval : CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL);
    inventory_work_params.backoff.interval     = backoff_interval;
    inventory_work_params.backoff.max_interval = max_backoff_interval;
    inventory_work_params.name                 = "mender_inventory";

    if (MENDER_OK != (ret = mender_os_scheduler_work_create(&inventory_work_params, &mender_inventory_work))) {
        mender_log_error("Unable to create inventory work");
        return ret;
    }

    if (MENDER_OK != (ret = mender_inventory_add_callback(artifact_name_device_type_cb, true))) {
        mender_log_error("Failed to add the required inventory callback for artifact name and device type");
        return ret;
    }
    if (MENDER_OK != (ret = mender_inventory_add_callback(provides_cb, true))) {
        mender_log_error("Failed to add the required inventory callback for provides");
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
    mender_err_t ret;

    /* Deactivate mender inventory work */
    if (MENDER_OK != (ret = mender_os_scheduler_work_deactivate(mender_inventory_work))) {
        mender_log_error("Failed to deactivate inventory work");
        return ret;
    }

    return MENDER_OK;
}

mender_err_t
mender_inventory_add_callback(MenderInventoryCallback callback, bool persistent) {
    mender_err_t ret;

    /* Take mutex used to protect access to the inventory key-store */
    if (MENDER_OK != (ret = mender_os_mutex_take(mender_inventory_mutex, -1))) {
        mender_log_error("Unable to take mutex");
        return ret;
    }

    if (N_CALLBACKS_MAX == n_callbacks) {
        mender_log_error("Too many inventory callbacks");
        ret = MENDER_FAIL;
        goto END;
    }

    if (n_callbacks == callbacks_len) {
        callbacks = mender_realloc(callbacks, 2 * callbacks_len * sizeof(callback_item_t));
        if (NULL == callbacks) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }
        callbacks_len = 2 * callbacks_len;
    }
    callbacks[n_callbacks].callback   = callback;
    callbacks[n_callbacks].persistent = persistent;
    n_callbacks++;
    if (persistent) {
        n_persistent_callbacks++;
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

    mender_utils_keystore_delete(provides_inventory, provides_inventory_len);
    provides_inventory     = NULL;
    provides_inventory_len = 0;

    mender_free(callbacks);
    callbacks_len          = 0;
    n_callbacks            = 0;
    n_persistent_callbacks = 0;
    full_push_done         = false;

    keystores_item_t *inv = persistent_inventory;
    while (NULL != inv) {
        keystores_item_t *aux = inv;
        inv                   = inv->next;
        mender_free(aux);
    }
    persistent_inventory = NULL;

    mender_os_mutex_give(mender_inventory_mutex);
    DESTROY_AND_NULL(mender_os_mutex_delete, mender_inventory_mutex);

    return ret;
}

mender_err_t
mender_inventory_reset_persistent(void) {
    mender_err_t ret;

    /* Take mutex used to protect access to the inventory key-store */
    if (MENDER_OK != (ret = mender_os_mutex_take(mender_inventory_mutex, -1))) {
        mender_log_error("Unable to take mutex");
        return ret;
    }

    mender_utils_keystore_delete(provides_inventory, provides_inventory_len);
    provides_inventory     = NULL;
    provides_inventory_len = 0;

    keystores_item_t *inv = persistent_inventory;
    while (NULL != inv) {
        keystores_item_t *aux = inv;
        inv                   = inv->next;
        mender_free(aux);
    }
    persistent_inventory = NULL;

    mender_os_mutex_give(mender_inventory_mutex);
    return MENDER_OK;
}

static mender_err_t
collect_persistent_inventory(void) {
    mender_err_t ret;
    for (uint8_t idx = 0; idx < n_callbacks; idx++) {
        if (callbacks[idx].persistent) {
            keystores_item_t *item = mender_calloc(1, sizeof(keystores_item_t));
            if (NULL == item) {
                mender_log_error("Unable to allocate memory");
                return MENDER_FAIL;
            }
            if (MENDER_OK != (ret = callbacks[idx].callback(&(item->keystore), &(item->keystore_len)))) {
                if (MENDER_NOT_FOUND == ret) {
                    mender_log_debug("No persistent inventory data to collect");
                } else {
                    mender_log_error("Failed to get persistent inventory data");
                }
                /* keep going and collect as much as we can */
                mender_free(item);
                continue;
            }
            item->next           = persistent_inventory;
            persistent_inventory = item;
        }
    }
    return MENDER_OK;
}

static mender_err_t
append_keystore_to_inventory_data(cJSON *inventory_data, const mender_keystore_t *keystore, uint8_t keystore_len) {
    cJSON *item = NULL;
    for (uint8_t idx = 0; idx < keystore_len; idx++) {
        if (NULL == (item = cJSON_CreateObject())) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
        cJSON_AddStringToObject(item, "name", keystore[idx].name);
        cJSON_AddStringToObject(item, "value", keystore[idx].value);
        cJSON_AddItemToArray(inventory_data, item);
    }
    return MENDER_OK;
}

static mender_err_t
mender_inventory_work_function(void) {
    mender_err_t       ret;
    cJSON             *inventory_data = NULL;
    mender_keystore_t *keystore;
    uint8_t            keystore_len;

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

    /* Gather persistent inventory once */
    if (!full_push_done && (NULL == persistent_inventory)) {
        if (MENDER_OK != (ret = collect_persistent_inventory())) {
            goto END;
        }
    }

    /* Check if there's anything to do */
    if ((full_push_done || (NULL == persistent_inventory)) && (0 == n_callbacks - n_persistent_callbacks)) {
        /* nothing to do */
        ret = MENDER_OK;
        goto END;
    }

    /* Construct the inventory data */
    inventory_data = cJSON_CreateArray();
    if (NULL == inventory_data) {
        mender_log_error("Failed to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }

    if (!full_push_done && (NULL != persistent_inventory)) {
        for (keystores_item_t *pers_ks = persistent_inventory; NULL != pers_ks; pers_ks = pers_ks->next) {
            if (MENDER_OK != (ret = append_keystore_to_inventory_data(inventory_data, pers_ks->keystore, pers_ks->keystore_len))) {
                mender_log_error("Failed to add persistent inventory to inventory payload");
                goto END;
            }
        }
    }
    /* add dynamic inventory (if any) */
    if (n_callbacks - n_persistent_callbacks > 0) {
        for (uint8_t idx = 0; idx < n_callbacks; idx++) {
            if (callbacks[idx].persistent) {
                continue;
            }
            if (MENDER_OK != callbacks[idx].callback(&keystore, &keystore_len)) {
                mender_log_error("Failed to get dynamic inventory");
                /* keep going and collect as much as we can */
                continue;
            }
            if (MENDER_OK != (ret = append_keystore_to_inventory_data(inventory_data, keystore, keystore_len))) {
                mender_log_error("Failed to add dynamic inventory to inventory payload");
                mender_utils_keystore_delete(keystore, keystore_len);
                goto END;
            }
            mender_utils_keystore_delete(keystore, keystore_len);
        }
    }

    /* Publish inventory */
    if (MENDER_OK != (ret = mender_api_publish_inventory_data(inventory_data, full_push_done))) {
        mender_log_error("Unable to publish inventory data");
    } else {
        /* we either pushed the persistent inventory or it was pushed before */
        full_push_done = true;
    }
    /* mender_api_publish_inventory_data() takes ownership of inventory_data */
    inventory_data = NULL;

END:

    cJSON_Delete(inventory_data);
    /* Release mutex used to protect access to the inventory key-store */
    mender_os_mutex_give(mender_inventory_mutex);

    return ret;
}

static mender_err_t
artifact_name_device_type_cb(mender_keystore_t **inventory, uint8_t *inventory_len) {
    mender_err_t             ret;
    static mender_keystore_t basic_device_info[] = {
        { "artifact_name", NULL },
        { "device_type", NULL },
    };
    if (MENDER_OK != (ret = mender_storage_get_artifact_name((const char **)&(basic_device_info[0].value)))) {
        mender_log_error("Failed to get artifact name");
        return ret;
    }
    basic_device_info[1].value = (char *)device_type;
    *inventory                 = basic_device_info;
    *inventory_len             = 2;
    return MENDER_OK;
}

static mender_err_t
provides_cb(mender_keystore_t **inventory, uint8_t *inventory_len) {
    mender_err_t             ret;
    mender_key_value_list_t *provides = NULL;
    size_t                   n_provides;
    uint8_t                  idx;
    mender_key_value_list_t *item;

    /* mender_storage_get_provides() gives us a linked list (which is a good
       structure for manipulation with provides data in other places), but we
       need a key-value array so we need to do a transformation. */
    if (MENDER_OK != (ret = mender_storage_get_provides(&provides))) {
        /* error logged in function */
        return ret;
    }

    n_provides = mender_utils_key_value_list_length(provides);
    if (n_provides > UINT8_MAX) {
        mender_log_warning("Too many provides values, cannot inventory them all");
        n_provides = UINT8_MAX;
    }

    /* This should never be called when provides_inventory data is still
       there. */
    assert(NULL == provides_inventory);

    provides_inventory = mender_calloc(n_provides, sizeof(mender_keystore_t));
    if (NULL == provides_inventory) {
        mender_log_error("Cannot allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    for (item = provides, idx = 0; (NULL != item) && (idx < n_provides); item = item->next, idx++) {
        /* Move the data from the linked list into the inventory keystore, no
           need to duplicate it. */
        provides_inventory[idx].name  = item->key;
        item->key                     = NULL;
        provides_inventory[idx].value = item->value;
        item->value                   = NULL;
    }
    provides_inventory_len = n_provides;

    *inventory     = provides_inventory;
    *inventory_len = provides_inventory_len;

    ret = MENDER_OK;

END:
    mender_utils_key_value_list_free(provides);

    return ret;
}

#endif /* CONFIG_MENDER_CLIENT_INVENTORY_DISABLE */
