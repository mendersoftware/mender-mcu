/**
 * @file      storage.c
 * @brief     Mender storage interface for Posix platform
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

#include <unistd.h>
#include "alloc.h"
#include "log.h"
#include "storage.h"

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
#error Deployment logs not implemented on POSIX (MEN-8258)
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

/**
 * @brief Default storage path (working directory)
 */
#ifndef CONFIG_MENDER_STORAGE_PATH
#define CONFIG_MENDER_STORAGE_PATH ""
#endif /* CONFIG_MENDER_STORAGE_PATH */

/**
 * @brief NVS Files
 */
#define MENDER_STORAGE_NVS_PRIVATE_KEY     CONFIG_MENDER_STORAGE_PATH "key.der"
#define MENDER_STORAGE_NVS_PUBLIC_KEY      CONFIG_MENDER_STORAGE_PATH "pubkey.der"
#define MENDER_STORAGE_NVS_DEPLOYMENT_DATA CONFIG_MENDER_STORAGE_PATH "deployment-data.json"
#define MENDER_STORAGE_NVS_PROVIDES        CONFIG_MENDER_STORAGE_PATH "provides.txt"
#define MENDER_STORAGE_NVS_ARTICACT_NAME   CONFIG_MENDER_STORAGE_PATH "artifact_name.txt"

mender_err_t
mender_storage_init(void) {

    /* Nothing to do */
    return MENDER_OK;
}

static mender_err_t
mender_storage_write_file(const char *file_path, const void *data, size_t data_length) {

    assert(NULL != file_path);
    assert(NULL != data);

    FILE *f = fopen(file_path, "wb");
    if (NULL == f) {
        mender_log_error("Unable to open file %s for writing", file_path);
        return MENDER_FAIL;
    }
    if (fwrite(data, sizeof(unsigned char), data_length, f) != data_length) {
        mender_log_error("Unable to write data to file %s", file_path);
        fclose(f);
        return MENDER_FAIL;
    }
    fclose(f);
    return MENDER_OK;
}

static mender_err_t
mender_storage_read_file(const char *file_path, void **data, size_t *data_length) {

    assert(NULL != file_path);
    assert(NULL != data);
    assert(NULL != data_length);

    FILE *f = fopen(file_path, "rb");
    if (NULL == f) {
        return MENDER_NOT_FOUND;
    }
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    if (length <= 0) {
        mender_log_info("File %s is empty or unavailable", file_path);
        fclose(f);
        return MENDER_NOT_FOUND;
    }
    *data_length = (size_t)length;
    fseek(f, 0, SEEK_SET);
    *data = mender_malloc(*data_length + 1);
    if (NULL == *data) {
        mender_log_error("Unable to allocate memory");
        fclose(f);
        return MENDER_FAIL;
    }
    /* Set last byte to \0 */
    ((unsigned char *)*data)[*data_length] = '\0';
    if (fread(*data, sizeof(unsigned char), *data_length, f) != *data_length) {
        mender_log_error("Unable to read data from file %s", file_path);
        mender_free(*data);
        fclose(f);
        return MENDER_FAIL;
    }
    fclose(f);
    return MENDER_OK;
}

mender_err_t
mender_storage_set_authentication_keys(unsigned char *private_key, size_t private_key_length, unsigned char *public_key, size_t public_key_length) {

    assert(NULL != private_key);
    assert(NULL != public_key);

    if (MENDER_OK != mender_storage_write_file(MENDER_STORAGE_NVS_PRIVATE_KEY, private_key, private_key_length)) {
        return MENDER_FAIL;
    }
    if (MENDER_OK != mender_storage_write_file(MENDER_STORAGE_NVS_PUBLIC_KEY, public_key, public_key_length)) {
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

    if (MENDER_OK != mender_storage_read_file(MENDER_STORAGE_NVS_PRIVATE_KEY, (void **)private_key, private_key_length)) {
        return MENDER_NOT_FOUND;
    }
    if (MENDER_OK != mender_storage_read_file(MENDER_STORAGE_NVS_PUBLIC_KEY, (void **)public_key, public_key_length)) {
        mender_free(*private_key);
        *private_key        = NULL;
        *private_key_length = 0;
        return MENDER_NOT_FOUND;
    }
    return MENDER_OK;
}

mender_err_t
mender_storage_delete_authentication_keys(void) {

    /* Erase keys */
    if ((0 != unlink(MENDER_STORAGE_NVS_PRIVATE_KEY)) || (0 != unlink(MENDER_STORAGE_NVS_PUBLIC_KEY))) {
        mender_log_error("Unable to erase authentication keys");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_set_deployment_data(char *deployment_data) {
    assert(NULL != deployment_data);
    size_t deployment_data_length = strlen(deployment_data);

    if (MENDER_OK != mender_storage_write_file(MENDER_STORAGE_NVS_DEPLOYMENT_DATA, deployment_data, deployment_data_length)) {
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

mender_err_t
mender_storage_get_deployment_data(char **deployment_data) {
    assert(NULL != deployment_data);

    size_t deployment_data_length;
    if (MENDER_OK != mender_storage_read_file(MENDER_STORAGE_NVS_DEPLOYMENT_DATA, (void **)deployment_data, &deployment_data_length)) {
        return MENDER_NOT_FOUND;
    }
    return MENDER_OK;
}

mender_err_t
mender_storage_delete_deployment_data(void) {

    /* Delete deployment data */
    if (0 != unlink(MENDER_STORAGE_NVS_DEPLOYMENT_DATA)) {
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
    size_t provides_str_length = strlen(provides_str);

    if (MENDER_OK != mender_storage_write_file(MENDER_STORAGE_NVS_PROVIDES, provides_str, provides_str_length)) {
        mender_free(provides_str);
        return MENDER_FAIL;
    }
    mender_free(provides_str);
    return MENDER_OK;
}

mender_err_t
mender_storage_get_provides(mender_key_value_list_t **provides) {

    assert(NULL != provides);

    char  *provides_str = NULL;
    size_t provides_length;
    if (MENDER_OK != mender_storage_read_file(MENDER_STORAGE_NVS_PROVIDES, (void **)&provides_str, &provides_length)) {
        return MENDER_NOT_FOUND;
    }
    if (MENDER_OK != mender_utils_string_to_key_value_list(provides_str, provides)) {
        mender_log_error("Unable to parse provides");
        mender_free(provides_str);
        return MENDER_FAIL;
    }

    mender_free(provides_str);
    return MENDER_OK;
}

mender_err_t
mender_storage_delete_provides(void) {

    /* Delete provides */
    if (0 != unlink(MENDER_STORAGE_NVS_PROVIDES)) {
        mender_log_error("Unable to delete provides");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

#endif /*CONFIG_MENDER_FULL_PARSE_ARTIFACT*/
#endif /*CONFIG_MENDER_PROVIDES_DEPENDS*/

mender_err_t
mender_storage_set_artifact_name(const char *artifact_name) {

    assert(NULL != artifact_name);

    size_t artifact_name_str_length = strlen(artifact_name);

    if (MENDER_OK != mender_storage_write_file(MENDER_STORAGE_NVS_ARTICACT_NAME, artifact_name, artifact_name_str_length)) {
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

mender_err_t
mender_storage_get_artifact_name(const char **artifact_name) {

    assert(NULL != artifact_name);

    size_t       artifact_name_length;
    mender_err_t ret = mender_storage_read_file(MENDER_STORAGE_NVS_ARTICACT_NAME, (void **)artifact_name, &artifact_name_length);
    if (MENDER_OK != ret) {
        if (MENDER_NOT_FOUND == ret) {
            *artifact_name = "unknown";
            return MENDER_OK;
        } else {
            mender_log_error("Unable to read artifact_name");
        }
    }

    return ret;
}

mender_err_t
mender_storage_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}
