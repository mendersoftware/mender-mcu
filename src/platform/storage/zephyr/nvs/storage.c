/**
 * @file      storage.c
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
#include <zephyr/sys/crc.h>
#include <zephyr/storage/flash_map.h>
#include "log.h"
#include "storage.h"

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
#include <zephyr/fs/fcb.h>
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

/**
 * @brief NVS storage
 */
#define MENDER_STORAGE_LABEL      storage_partition
#define MENDER_STORAGE_DEVICE     FIXED_PARTITION_DEVICE(MENDER_STORAGE_LABEL)
#define MENDER_STORAGE_OFFSET     FIXED_PARTITION_OFFSET(MENDER_STORAGE_LABEL)
#define MENDER_STORAGE_FLASH_AREA FIXED_PARTITION_ID(MENDER_STORAGE_LABEL)

/**
 * @brief NVS keys
 */
#define MENDER_STORAGE_NVS_PRIVATE_KEY     1
#define MENDER_STORAGE_NVS_PUBLIC_KEY      2
#define MENDER_STORAGE_NVS_DEPLOYMENT_DATA 3
#define MENDER_STORAGE_NVS_PROVIDES        4
#define MENDER_STORAGE_NVS_ARTICACT_NAME   5

/**
 * @brief Cached Artifact name
 */
static char *cached_artifact_name = NULL;

/**
 * @brief NVS storage handle
 */
static struct nvs_fs mender_storage_nvs_handle;

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
/* just some fixed magic value the FCB implementation uses to mark
   in-use/erased/... sectors */
#define DEPLOYMENT_LOGS_MAGIC_VALUE 0x2AABEE35

/**
 * @brief A Flash Circular Buffer for storing deployment logs
 */
static struct fcb depl_logs_buffer;

#define DEPL_LOGS_MAX_MSG_LEN 255
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

/**
 * @brief Flash sectors used by Mender
 */
#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
static struct flash_sector flash_sectors[CONFIG_MENDER_STORAGE_NVS_SECTOR_COUNT + CONFIG_MENDER_STORAGE_DEPLOYMENT_LOGS_SECTORS];
#else
static struct flash_sector flash_sectors[CONFIG_MENDER_STORAGE_NVS_SECTOR_COUNT];
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

static mender_err_t
nvs_read_alloc(struct nvs_fs *nvs, uint16_t id, void **data, size_t *length) {
    ssize_t ret;

    /* Peek read to retrieve length of the data */
    uint8_t byte;
    ret = nvs_read(nvs, id, &byte, 0);
    if (ret <= 0) {
        return (0 == ret || -ENOENT == ret) ? MENDER_NOT_FOUND : MENDER_FAIL;
    }
    *length = (size_t)ret;

    /* Allocate memory */
    *data = mender_malloc(*length);
    if (NULL == *data) {
        mender_log_error("Unable to allocate memory for: %d", id);
        return MENDER_FAIL;
    }

    /* Read data */
    ret = nvs_read(nvs, id, *data, *length);
    if (ret < 0) {
        FREE_AND_NULL(*data);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static inline bool
checked_nvs_write(struct nvs_fs *fs, uint16_t id, const void *data, size_t len) {
    ssize_t ret = nvs_write(fs, id, data, len);
    /* nvs_write() docs say:
     *    When a rewrite of the same data already stored is attempted, nothing is written to flash, thus 0 is returned.
     */
    return (len == ret) || (0 == ret);
}

static mender_err_t
crc_add(char **data, size_t *data_len) {

    assert(NULL != data);
    assert(NULL != data_len);

    uint32_t crc = crc32_ieee(*data, *data_len);
    char    *tmp = mender_realloc(*data, *data_len + sizeof(crc));
    if (NULL == tmp) {
        mender_log_error("Unable to allocate memory for deployment data");
        return MENDER_FAIL;
    }
    memcpy(tmp + *data_len, &crc, sizeof(crc));
    *data_len += sizeof(crc);
    *data = tmp;

    return MENDER_OK;
}

static mender_err_t
crc_check(const unsigned char *data, const size_t data_len) {

    assert(NULL != data);

    if (data_len > sizeof(uint32_t)) {

        /* Extract the CRC  */
        uint32_t crc = *(uint32_t *)(data + data_len - sizeof(crc));

        /* Compute CRC of the loaded data */
        uint32_t computed_crc = crc32_ieee(data, data_len - sizeof(crc));

        if (computed_crc != crc) {
            mender_log_error("CRC mismatch in deployment data");
            return MENDER_FAIL;
        }
    } else {
        mender_log_error("Invalid deployment data size (too small for CRC)");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_init(void) {
    int      result;
    uint32_t n_sectors;

    /* Get flash info */
    mender_storage_nvs_handle.flash_device = MENDER_STORAGE_DEVICE;
    if (!device_is_ready(mender_storage_nvs_handle.flash_device)) {
        mender_log_error("Flash device not ready");
        return MENDER_FAIL;
    }

    n_sectors = sizeof(flash_sectors) / sizeof(flash_sectors[0]);
    result    = flash_area_get_sectors(MENDER_STORAGE_FLASH_AREA, &n_sectors, flash_sectors);
    if ((0 != result) && (-ENOMEM != result)) {
        /* -ENOMEM means there were more sectors than the supplied size of the
            sector array (flash_sectors), but we don't worry about that, we just
            need the info about the first N sectors we want to use. */
        mender_log_error("Failed to get info about flash sectors in the Mender flash area [%d]", -result);
        return MENDER_FAIL;
    }
    if (n_sectors != (sizeof(flash_sectors) / sizeof(flash_sectors[0]))) {
        mender_log_error(
            "Not enough sectors on the flash for Mender (required: %" PRIu32 "d, available: %zd)", sizeof(flash_sectors) / sizeof(flash_sectors[0]), n_sectors);
        return MENDER_FAIL;
    }

    mender_storage_nvs_handle.offset       = MENDER_STORAGE_OFFSET;
    mender_storage_nvs_handle.sector_size  = (uint16_t)flash_sectors[0].fs_size;
    mender_storage_nvs_handle.sector_count = CONFIG_MENDER_STORAGE_NVS_SECTOR_COUNT;

    /* Mount NVS */
    if (0 != (result = nvs_mount(&mender_storage_nvs_handle))) {
        mender_log_error("Unable to mount NVS storage, result = %d", result);
        return MENDER_FAIL;
    }
    mender_log_debug("Initialized Mender NVS with %u sectors (%zd bytes available)",
                     mender_storage_nvs_handle.sector_count,
                     (size_t)(mender_storage_nvs_handle.sector_count - 1) * mender_storage_nvs_handle.sector_size);

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
    /* Initialize the Flash Circular Buffer (FCB) for deployment logs. */

    depl_logs_buffer.f_magic       = DEPLOYMENT_LOGS_MAGIC_VALUE;
    depl_logs_buffer.f_version     = 0; /* we don't version the data so 0 always */
    depl_logs_buffer.f_sector_cnt  = CONFIG_MENDER_STORAGE_DEPLOYMENT_LOGS_SECTORS;
    depl_logs_buffer.f_scratch_cnt = 0; /* no scratch sector, we don't use it */
    depl_logs_buffer.f_sectors     = flash_sectors + CONFIG_MENDER_STORAGE_NVS_SECTOR_COUNT;

    if (0 != (result = fcb_init(FIXED_PARTITION_ID(MENDER_STORAGE_LABEL), &depl_logs_buffer))) {
        mender_log_debug("Failed to initialize deployment logs FCB, erasing the particular flash area");

        const struct flash_area *fap;
        if (0 != (result = flash_area_open(FIXED_PARTITION_ID(MENDER_STORAGE_LABEL), &fap))) {
            mender_log_error("Unable to open the Mender storage flash area");
            return MENDER_FAIL;
        }

        /* flatten means: Erase flash area or fill with erase-value. */
        result = flash_area_flatten(
            fap, depl_logs_buffer.f_sectors[0].fs_off, depl_logs_buffer.f_sectors[0].fs_off * CONFIG_MENDER_STORAGE_DEPLOYMENT_LOGS_SECTORS);
        flash_area_close(fap);
        if (0 != result) {
            mender_log_error("Failed to erase the flash area for deployment logs");
        }
        /* Now, try again. */
        if (0 != (result = fcb_init(FIXED_PARTITION_ID(MENDER_STORAGE_LABEL), &depl_logs_buffer))) {
            mender_log_error("Unable to initialize the Flash Circular Buffer for deployment logs [%d]", -result);
            return MENDER_FAIL;
        }
    }
    mender_log_debug("Initialized deployment logs FCB with %u sectors (%zd bytes available)",
                     depl_logs_buffer.f_sector_cnt,
                     (depl_logs_buffer.f_sector_cnt - 1) * mender_storage_nvs_handle.sector_size);
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

    return MENDER_OK;
}

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
mender_err_t
mender_storage_deployment_log_append(const char *msg, size_t msg_size) {
    int          result;
    mender_err_t ret = MENDER_OK;

    msg_size = MIN(DEPL_LOGS_MAX_MSG_LEN + 1, msg_size);

    const struct flash_area *fap;
    if (0 != (result = flash_area_open(FIXED_PARTITION_ID(MENDER_STORAGE_LABEL), &fap))) {
        mender_log_error("Unable to open the Mender storage flash area [%d]", -result);
        return MENDER_FAIL;
    }

    struct fcb_entry entry = { 0 };
    result                 = fcb_append(&depl_logs_buffer, msg_size, &entry);
    if (-ENOSPC == result) {
        if (0 != (result = fcb_rotate(&depl_logs_buffer))) {
            mender_log_error("Failed to rotate the deployment logs FCB");
            ret = MENDER_FAIL;
            goto END;
        }
        const char rotation_msg[] = "<wrn> ------- DEPLOYMENT LOGS ROTATED -------";
        result                    = fcb_append(&depl_logs_buffer, sizeof(rotation_msg), &entry);
        if (0 != (result = flash_area_write(fap, entry.fe_sector->fs_off + entry.fe_data_off, rotation_msg, sizeof(rotation_msg)))) {
            mender_log_error("Failed to write message to the FCB entry [%d]", -result);
            ret = MENDER_FAIL;
            goto END;
        }
        result = fcb_append_finish(&depl_logs_buffer, &entry);
        if (0 != result) {
            mender_log_error("Failed to finish append of a rotation entry to the deployment logs FCB");
            ret = MENDER_FAIL;
            goto END;
        }

        result = fcb_append(&depl_logs_buffer, msg_size, &entry);
    }
    if (0 != result) {
        mender_log_error("Failed to append a new entry to the deployment logs FCB");
        ret = MENDER_FAIL;
        goto END;
    }
    /* else success, proceed */
    if (0 != (result = flash_area_write(fap, entry.fe_sector->fs_off + entry.fe_data_off, msg, msg_size))) {
        mender_log_error("Failed to write message to the FCB entry [%d]", -result);
        ret = MENDER_FAIL;
        goto END;
    }
    result = fcb_append_finish(&depl_logs_buffer, &entry);
    if (0 != result) {
        mender_log_error("Failed to finish append of a new entry to the deployment logs FCB");
        ret = MENDER_FAIL;
        goto END;
    }

END:
    flash_area_close(fap);

    return ret;
}

mender_err_t
mender_storage_deployment_log_walk(MenderDeploymentLogVisitor visitor_fn, void *ctx) {
    mender_err_t ret = MENDER_OK;
    int          result;
    char         msg[DEPL_LOGS_MAX_MSG_LEN + 1];

    const struct flash_area *fap;
    if (0 != (result = flash_area_open(FIXED_PARTITION_ID(MENDER_STORAGE_LABEL), &fap))) {
        mender_log_error("Unable to open the Mender storage flash area");
        return MENDER_FAIL;
    }

    struct fcb_entry entry = { 0 };
    result                 = fcb_getnext(&depl_logs_buffer, &entry);
    while (0 == result) {
        if (0 != (result = flash_area_read(fap, entry.fe_sector->fs_off + entry.fe_data_off, (void *)msg, MIN(DEPL_LOGS_MAX_MSG_LEN, entry.fe_data_len)))) {
            mender_log_error("Failed to read FCB entry from flash [%d]", -result);
            ret = MENDER_FAIL;
            goto END;
        }
        msg[MIN(DEPL_LOGS_MAX_MSG_LEN, entry.fe_data_len)] = '\0';
        visitor_fn(msg, ctx);
        result = fcb_getnext(&depl_logs_buffer, &entry);
    }

END:
    flash_area_close(fap);

    return ret;
}

mender_err_t
mender_storage_deployment_log_clear(void) {
    int result = fcb_clear(&depl_logs_buffer);
    return (0 == result) ? MENDER_OK : MENDER_FAIL;
}
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

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
            mender_log_debug("Private key not available");
        } else {
            mender_log_error("Unable to read private key");
        }
        return ret;
    }

    /* Read public key */
    ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, (void **)public_key, public_key_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            mender_log_debug("Public key not available");
        } else {
            mender_log_error("Unable to read public key");
        }
        FREE_AND_NULL(*private_key);
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

    size_t data_len = strlen(deployment_data) + 1;

#ifdef CONFIG_MENDER_STORAGE_DEPLOYMENT_DATA_CRC
    if (MENDER_OK != crc_add(&deployment_data, &data_len)) {
        return MENDER_FAIL;
    }
#endif /* CONFIG_MENDER_STORAGE_DEPLOYMENT_DATA_CRC */

    /* Write deployment data  */
    if (nvs_write(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, deployment_data, data_len) < 0) {
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
            mender_log_debug("Deployment data not available");
        } else {
            mender_log_error("Unable to read deployment data");
        }
        return ret;
    }

#ifdef CONFIG_MENDER_STORAGE_DEPLOYMENT_DATA_CRC
    if (MENDER_OK != crc_check(*deployment_data, deployment_data_length)) {
        return MENDER_FAIL;
    }
#endif /* CONFIG_MENDER_STORAGE_DEPLOYMENT_DATA_CRC */

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

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
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
        mender_free(provides_str);
        return MENDER_FAIL;
    }

    mender_free(provides_str);
    return MENDER_OK;
}

mender_err_t
mender_storage_get_provides(mender_key_value_list_t **provides) {
    assert(NULL != provides);
    assert(NULL == *provides); /* otherwise we prepend to a bad list going nowhere */

    size_t provides_length = 0;

    char *provides_str = NULL;
    /* Read provides */
    mender_err_t ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, (void **)&provides_str, &provides_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            mender_log_debug("Provides not available");
        } else {
            mender_log_error("Unable to read provides");
        }
        return ret;
    }

    /* Convert str to key-value list */
    if (MENDER_OK != mender_utils_string_to_key_value_list(provides_str, provides)) {
        mender_free(provides_str);
        return MENDER_FAIL;
    }
    mender_free(provides_str);
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
mender_storage_set_artifact_name(const char *artifact_name) {

    assert(NULL != artifact_name);

    /* Write artifact_name */
    if (!checked_nvs_write(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTICACT_NAME, artifact_name, strlen(artifact_name) + 1)) {
        mender_log_error("Unable to write artifact_name");
        return MENDER_FAIL;
    }

    mender_free(cached_artifact_name);
    cached_artifact_name = NULL;

    return MENDER_OK;
}

mender_err_t
mender_storage_get_artifact_name(const char **artifact_name) {

    assert(NULL != artifact_name);

    if (NULL != cached_artifact_name) {
        *artifact_name = cached_artifact_name;
        return MENDER_OK;
    }

    size_t artifact_name_length;

    /* Read artifact_name */
    mender_err_t ret = nvs_read_alloc(&mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTICACT_NAME, (void **)artifact_name, &artifact_name_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            if (NULL == (*artifact_name = mender_utils_strdup("unknown"))) {
                mender_log_error("Unable to allocate memory");
                return MENDER_FAIL;
            }
            cached_artifact_name = (char *)*artifact_name;
            return MENDER_OK;

        } else {
            mender_log_error("Unable to read artifact_name");
        }
    } else {
        cached_artifact_name = (char *)*artifact_name;
    }

    return ret;
}

mender_err_t
mender_storage_exit(void) {

    FREE_AND_NULL(cached_artifact_name);

    return MENDER_OK;
}
