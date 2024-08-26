/**
 * @file      mender-storage.c
 * @brief     Mender storage interface for Zephyr platform
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

#include <errno.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/fs/nvs.h>
#include <zephyr/storage/flash_map.h>
#include "mender-log.h"
#include "mender-storage.h"

/**
 * @brief NVS storage
 */
#define MENDER_STORAGE_LABEL  storage_partition
#define MENDER_STORAGE_DEVICE FIXED_PARTITION_DEVICE(MENDER_STORAGE_LABEL)
#define MENDER_STORAGE_OFFSET FIXED_PARTITION_OFFSET(MENDER_STORAGE_LABEL)

/**
 * @brief NVS keys
 */
#define MENDER_STORAGE_NVS_PRIVATE_KEY     1
#define MENDER_STORAGE_NVS_PUBLIC_KEY      2
#define MENDER_STORAGE_NVS_DEPLOYMENT_DATA 3
#define MENDER_STORAGE_NVS_DEVICE_CONFIG   4
#define MENDER_STORAGE_NVS_PROVIDES        5

/**
 * @brief NVS storage handle
 */
static struct nvs_fs mender_storage_nvs_handle;

static mender_err_t
nvs_read_alloc(struct nvs_fs *nvs, uint16_t id, void **data, size_t *length) {
    ssize_t ret;

    /* Retrieve length of the data */
    ret = nvs_read(nvs, id, NULL, 0);
    if (ret <= 0) {
        return (0 == ret || -ENOENT == ret) ? MENDER_NOT_FOUND : MENDER_FAIL;
    }
    *length = (size_t)ret;

    /* Allocate memory */
    *data = malloc(*length);
    if (NULL == *data) {
        mender_log_error("Unable to allocate memory for: %d", id);
        return MENDER_FAIL;
    }

    /* Read data */
    ret = nvs_read(nvs, id, *data, *length);
    if (ret < 0) {
        free(*data);
        *data = NULL;
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_init(void) {

    int result;

    /* Get flash info */
    mender_storage_nvs_handle.flash_device = MENDER_STORAGE_DEVICE;
    if (!device_is_ready(mender_storage_nvs_handle.flash_device)) {
        mender_log_error("Flash device not ready");
        return MENDER_FAIL;
    }
    struct flash_pages_info info;
    mender_storage_nvs_handle.offset = MENDER_STORAGE_OFFSET;
    if (0 != flash_get_page_info_by_offs(mender_storage_nvs_handle.flash_device, mender_storage_nvs_handle.offset, &info)) {
        mender_log_error("Unable to get storage page info");
        return MENDER_FAIL;
    }
    mender_storage_nvs_handle.sector_size  = (uint16_t)info.size;
    mender_storage_nvs_handle.sector_count = CONFIG_MENDER_STORAGE_NVS_SECTOR_COUNT;

    /* Mount NVS */
    if (0 != (result = nvs_mount(&mender_storage_nvs_handle))) {
        mender_log_error("Unable to mount NVS storage, result = %d", result);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_set_authentication_keys(unsigned char *private_key, size_t private_key_length, unsigned char *public_key, size_t public_key_length) {

    assert(NULL != private_key);
    assert(NULL != public_key);

    /* Write keys */
    if ((nvs_write(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, private_key, private_key_length) < 0)
        || (nvs_write(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, public_key, public_key_length) < 0)) {
        mender_log_error("Unable to write authentication keys");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_get_authentication_keys(unsigned char **private_key, size_t *private_key_length, unsigned char **public_key, size_t *public_key_length) {

    assert(NULL != private_key);
    assert(NULL != private_key_length);
    assert(NULL != public_key);
    assert(NULL != public_key_length);

    /* Read private key */
    mender_err_t ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, (void **)private_key, private_key_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            mender_log_info("Private key not available");
        } else {
            mender_log_error("Unable to read private key");
        }
        return ret;
    }

    /* Read public key */
    ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, (void **)public_key, public_key_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            mender_log_info("Public key not available");
        } else {
            mender_log_error("Unable to read public key");
        }
        free(*private_key);
        *private_key = NULL;
        return ret;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_authentication_keys(void) {

    /* Erase keys */
    if ((0 != nvs_delete(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY))
        || (0 != nvs_delete(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY))) {
        mender_log_error("Unable to erase authentication keys");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_set_deployment_data(char *deployment_data) {

    assert(NULL != deployment_data);

    /* Write deployment data */
    if (nvs_write(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, deployment_data, strlen(deployment_data) + 1) < 0) {
        mender_log_error("Unable to write deployment data");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_get_deployment_data(char **deployment_data) {

    assert(NULL != deployment_data);
    size_t deployment_data_length = 0;

    /* Read deployment data */
    mender_err_t ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, (void **)deployment_data, &deployment_data_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            mender_log_info("Deployment data not available");
        } else {
            mender_log_error("Unable to read deployment data");
        }
        return ret;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_deployment_data(void) {

    /* Delete deployment data */
    if (0 != nvs_delete(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA)) {
        mender_log_error("Unable to delete deployment data");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

#ifdef CONFIG_MENDER_CLIENT_ADD_ON_CONFIGURE
#ifdef CONFIG_MENDER_CLIENT_CONFIGURE_STORAGE

mender_err_t
mender_storage_set_device_config(char *device_config) {

    assert(NULL != device_config);

    /* Write device configuration */
    if (nvs_write(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEVICE_CONFIG, device_config, strlen(device_config) + 1) < 0) {
        mender_log_error("Unable to write device configuration");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_get_device_config(char **device_config) {

    assert(NULL != device_config);
    size_t device_config_length = 0;

    /* Retrieve length of the device configuration */
    /* Read  device configuration */
    mender_err_t ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEVICE_CONFIG, (void **)device_config, &device_config_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            mender_log_info("Device configuration not available");
        } else {
            mender_log_error("Unable to read device configuration");
        }
        return ret;
    }

    return MENDER_OK;
}

#endif /* CONFIG_MENDER_CLIENT_CONFIGURE_STORAGE */
#endif /* CONFIG_MENDER_CLIENT_ADD_ON_CONFIGURE */

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
mender_err_t
mender_storage_delete_device_config(void) {

    /* Delete device configuration */
    if (0 != nvs_delete(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEVICE_CONFIG)) {
        mender_log_error("Unable to delete device configuration");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_set_provides(mender_key_value_list_t *provides) {

    assert(NULL != provides);

    char *provides_str = NULL;
    if (MENDER_OK != mender_utils_key_value_list_to_string(provides, &provides_str)) {
        return MENDER_FAIL;
    }

    /* Write provides */
    if (nvs_write(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, provides_str, strlen(provides_str) + 1) < 0) {
        mender_log_error("Unable to write provides");
        free(provides_str);
        return MENDER_FAIL;
    }

    free(provides_str);
    return MENDER_OK;
}

mender_err_t
mender_storage_get_provides(mender_key_value_list_t **provides) {

    assert(NULL != provides);
    size_t provides_length = 0;

    char *provides_str = NULL;
    /* Read provides */
    mender_err_t ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, (void **)&provides_str, &provides_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            mender_log_info("Provides not available");
        } else {
            mender_log_error("Unable to read provides");
        }
        return ret;
    }

    /* Convert str to key-value list */
    if (MENDER_OK != mender_utils_string_to_key_value_list(provides_str, provides)) {
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

mender_err_t
mender_storage_delete_provides(void) {

    /* Delete provides */
    if (0 != nvs_delete(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES)) {
        mender_log_error("Unable to delete provides");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

mender_err_t
mender_storage_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}
