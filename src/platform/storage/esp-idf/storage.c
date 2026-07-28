/**
 * @file      storage.c
 * @brief     Mender storage interface for the ESP-IDF platform
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

#include <nvs_flash.h>

#include "log.h"
#include "storage.h"
#include "utils.h"

/* In case a custom partition label was specified, use it, otherwise default to
   "mender" */
#ifdef CONFIG_MENDER_STORAGE_PARTITION_LABEL
#define MENDER_STORAGE_PARTITION_LABEL CONFIG_MENDER_STORAGE_PARTITION_LABEL
#else
#define MENDER_STORAGE_PARTITION_LABEL "mender"
#endif /* CONFIG_MENDER_STORAGE_PARTITION_LABEL */

/**
 * @brief NVS keys
 * @note According to the ESP-IDF documentation the NVS keys are limited to 15 characters:
 *       https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_flash.html#keys-and-values
 */
/*                                         "###MAX-LENGTH##" */
#define MENDER_STORAGE_NVS_PRIVATE_KEY     "private_key"
#define MENDER_STORAGE_NVS_PUBLIC_KEY      "public_key"
#define MENDER_STORAGE_NVS_DEPLOYMENT_DATA "deployment-data"
#define MENDER_STORAGE_NVS_PROVIDES        "provides"
#define MENDER_STORAGE_NVS_ARTIFACT_NAME   "artifact-name"

/**
 * @brief Cached Artifact name
 */
static char *cached_artifact_name = NULL;

/**
 * @brief NVS storage handle
 */
static nvs_handle_t mender_storage_nvs_handle;

mender_err_t
mender_storage_init(void) {
    if (StringEqual(MENDER_STORAGE_PARTITION_LABEL, "nvs")) {
        /* The default partition (using label "nvs") specified, simply
           initialize and open this default and use the "mender" namespace */
        if (ESP_OK != nvs_flash_init()) {
            mender_log_error("Failed to initialize default NVS storage");
            return MENDER_FAIL;
        }
        if (ESP_OK != nvs_open("mender", NVS_READWRITE, &mender_storage_nvs_handle)) {
            mender_log_error("Failed to open default NVS storage");
            return MENDER_FAIL;
        }
    } else {
        const esp_partition_t *part;
        /* TODO: do nvs_flash_init() with partition label instead? */
        esp_err_t err = esp_partition_find_first_err(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, MENDER_STORAGE_PARTITION_LABEL, &part);
        if (ESP_ERR_NOT_FOUND == err) {
            mender_log_error("Failed to find an NVS data partition with label '" MENDER_STORAGE_PARTITION_LABEL "'");
            return MENDER_FAIL;
        } else if (ESP_OK != err) {
            mender_log_error("Failure when looking up NVS data partition for Mender data: %s", esp_err_to_name(err));
            return MENDER_FAIL;
        }
        if (ESP_OK != nvs_flash_init_partition_ptr(part)) {
            mender_log_error("Failed to initialize NVS data partition");
            return MENDER_FAIL;
        }
        if (ESP_OK != nvs_open_from_partition(MENDER_STORAGE_PARTITION_LABEL, "mender", NVS_READWRITE, &mender_storage_nvs_handle)) {
            mender_log_error("Failed to open NVS data partition");
            return MENDER_FAIL;
        }
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_set_authentication_keys(unsigned char *private_key, size_t private_key_length, unsigned char *public_key, size_t public_key_length) {
    assert(NULL != private_key);
    assert(NULL != public_key);

    if ((ESP_OK != nvs_set_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, private_key, private_key_length))
        || (ESP_OK != nvs_set_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, public_key, public_key_length))) {
        mender_log_error("Failed to write authentication keys");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write authentication keys");
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

    /* Retrieve length of the keys */
    nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, NULL, private_key_length);
    nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, NULL, public_key_length);
    if ((0 == *private_key_length) || (0 == *public_key_length)) {
        mender_log_info("Authentication keys not available in NVS");
        return MENDER_NOT_FOUND;
    }

    /* Allocate memory for the keys */
    if (NULL == (*private_key = mender_malloc(*private_key_length))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    if (NULL == (*public_key = mender_malloc(*public_key_length))) {
        mender_log_error("Unable to allocate memory");
        FREE_AND_NULL(*private_key);
        return MENDER_FAIL;
    }

    /* Read the keys */
    if ((ESP_OK != nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, *private_key, private_key_length))
        || (ESP_OK != nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, *public_key, public_key_length))) {
        mender_log_error("Failed to read authentication keys from NVS");
        FREE_AND_NULL(*private_key);
        FREE_AND_NULL(*public_key);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_authentication_keys(void) {
    if ((ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY))
        || (ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY))) {
        mender_log_error("Failed to erase authentication keys from NVS");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to erase authentication keys from NVS");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_set_deployment_data(char *deployment_data) {
    assert(NULL != deployment_data);

    if (ESP_OK != nvs_set_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, deployment_data)) {
        mender_log_error("Failed to write deployment data to NVS");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write (commit) deployment data to NVS");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_get_deployment_data(char **deployment_data) {
    assert(NULL != deployment_data);

    /* Retrieve length of the deployment data */
    size_t deployment_data_length = 0;
    nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, NULL, &deployment_data_length);
    if (0 == deployment_data_length) {
        mender_log_info("No deployment data found");
        return MENDER_NOT_FOUND;
    }

    /* Allocate memory for the deployment data */
    if (NULL == (*deployment_data = mender_malloc(deployment_data_length + 1))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Read the deployment data */
    if (ESP_OK != nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, *deployment_data, &deployment_data_length)) {
        mender_log_error("Failed to read deployment data");
        FREE_AND_NULL(*deployment_data);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_deployment_data(void) {
    if (ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA)) {
        mender_log_error("Failed to delete deployment data");
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

    if (ESP_OK != nvs_set_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, provides_str)) {
        mender_log_error("Failed to write provides to NVS");
        mender_free(provides_str);
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write (commit) provides to NVS");
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

    size_t provides_str_length = 0;
    char  *provides_str        = NULL;
    nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, NULL, &provides_str_length);
    if (0 == provides_str_length) {
        mender_log_info("No provides found");
        return MENDER_NOT_FOUND;
    }

    /* Allocate memory for the provides */
    if (NULL == (provides_str = mender_malloc(provides_str_length + 1))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Read the provides */
    if (ESP_OK != nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, provides_str, &provides_str_length)) {
        mender_log_error("Failed to read provides");
        mender_free(provides_str);
        return MENDER_FAIL;
    }

    /* Convert str to key-value list */
    if (MENDER_OK != mender_utils_string_to_key_value_list(provides_str, provides)) {
        /* Error already logged */
        mender_free(provides_str);
        return MENDER_FAIL;
    }
    mender_free(provides_str);

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_provides(void) {
    if (ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES)) {
        mender_log_error("Failed to delete provides");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

mender_err_t
mender_storage_set_artifact_name(const char *artifact_name) {
    assert(NULL != artifact_name);

    if (ESP_OK != nvs_set_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTIFACT_NAME, artifact_name)) {
        mender_log_error("Failed to write artifact name to NVS");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write (commit) artifact name to NVS");
        return MENDER_FAIL;
    }

    FREE_AND_NULL(cached_artifact_name);
    return MENDER_OK;
}

mender_err_t
mender_storage_get_artifact_name(const char **artifact_name) {
    assert(NULL != artifact_name);

    if (NULL != cached_artifact_name) {
        *artifact_name = cached_artifact_name;
        return MENDER_OK;
    }

    /* Retrieve length of the artifact name */
    size_t artifact_name_length = 0;
    nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTIFACT_NAME, NULL, &artifact_name_length);
    if (0 == artifact_name_length) {
        mender_log_info("No artifact name found");
        const char *artifact_name_literal;
        /* Get the Artifact Name from the build, if set */
#ifdef CONFIG_MENDER_ARTIFACT_NAME
        if (strlen(CONFIG_MENDER_ARTIFACT_NAME) > 0) {
            artifact_name_literal = CONFIG_MENDER_ARTIFACT_NAME;
        } else {
            artifact_name_literal = "unknown";
        }
#else
        artifact_name_literal = "unknown";
#endif
        if (NULL == (*artifact_name = mender_utils_strdup(artifact_name_literal))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }

        cached_artifact_name = (char *)*artifact_name;
        return MENDER_OK;
    }

    /* Allocate memory for the artifact name */
    char *nvs_artifact_name;
    if (NULL == (nvs_artifact_name = mender_malloc(artifact_name_length + 1))) {
        mender_log_error("Unable to allocate memory");
        *artifact_name = NULL;
        return MENDER_FAIL;
    }

    /* Read the artifact name */
    if (ESP_OK != nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTIFACT_NAME, nvs_artifact_name, &artifact_name_length)) {
        mender_log_error("Failed to read artifact name");
        mender_free(nvs_artifact_name);
        *artifact_name = NULL;
        return MENDER_FAIL;
    }

    *artifact_name       = (char *)nvs_artifact_name;
    cached_artifact_name = nvs_artifact_name;

    return MENDER_OK;
}

mender_err_t
mender_storage_exit(void) {
    FREE_AND_NULL(cached_artifact_name);

    /* Close the NVS storage */
    nvs_close(mender_storage_nvs_handle);

    return MENDER_OK;
}
