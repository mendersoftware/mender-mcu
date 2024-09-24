/**
 * @file      mender-deployment-data.c
 * @brief     Mender Deployment Data interface
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

#include "mender-deployment-data.h"

#include "mender-log.h"
#include "mender-storage.h"

/**
 * @brief Deployment data version number.
 * @note cJSON stores numbers as double, so we might as well define this
 *       constant as a double to avoid type casting.
 */
#define DEPLOYMENT_DATA_VERSION 1.0

/**
 * @brief Deployment data version number.
 * @note cJSON stores numbers as double, so we might as well define this
 *       constant as a double to avoid type casting.
 */
#define MAX_STATE_DATA_STORE_COUNT 50.0 /* TODO: What should this constant be? */

/**
 * @brief Validate deployment data
 * @param deployment_data Deployment data
 * @return True if valid, otherwise false
 */
static bool
validate_deployment_data(const cJSON *deployment_data) {

    assert(NULL != deployment_data);

    struct key_and_type {
        const char *const key;
        cJSON_bool (*type)(const cJSON *const);
    };

    static const struct key_and_type fields[] = {
        { .key = MENDER_DEPLOYMENT_DATA_KEY_VERSION, .type = cJSON_IsNumber },                /* So we can modify fields later */
        { .key = MENDER_DEPLOYMENT_DATA_KEY_ID, .type = cJSON_IsString },                     /* Deployment identifier */
        { .key = MENDER_DEPLOYMENT_DATA_KEY_ARTIFACT_NAME, .type = cJSON_IsString },          /* Name of artifact */
        { .key = MENDER_DEPLOYMENT_DATA_KEY_PAYLOAD_TYPES, .type = cJSON_IsArray },           /* Types of payloads embedded in artifact */
        { .key = MENDER_DEPLOYMENT_DATA_KEY_PROVIDES, .type = cJSON_IsString },               /* Artifact provides (filtered on clears provides) */
        /* { .key = MENDER_DEPLOYMENT_DATA_KEY_STATE, .type = cJSON_IsString }, */            /* TODO: MEN-7515: State name */
        { .key = MENDER_DEPLOYMENT_DATA_KEY_STATE_DATA_STORE_COUNT, .type = cJSON_IsNumber }, /* State data store count */
    };

    const size_t num_fields = sizeof(fields) / sizeof(struct key_and_type);
    for (size_t i = 0; i < num_fields; i++) {
        const cJSON *item;

        /* Make sure the field exists */
        if (NULL == (item = cJSON_GetObjectItemCaseSensitive(deployment_data, fields[i].key))) {
            mender_log_debug("Missing key '%s' in deployment data", fields[i].key);
            return false;
        }

        /* Make sure the field has correct type */
        if (!fields[i].type(item)) {
            mender_log_debug("Bad type for key '%s' in deployment data", fields[i].key);
            return false;
        }

        /* Check version compatibility */
        if (StringEqual(fields[i].key, MENDER_DEPLOYMENT_DATA_KEY_VERSION)) {
            /* Trying to avoid floating-point precision errors */
            const double delta = (DEPLOYMENT_DATA_VERSION > cJSON_GetNumberValue(item)) ? DEPLOYMENT_DATA_VERSION - cJSON_GetNumberValue(item)
                                                                                        : cJSON_GetNumberValue(item) - DEPLOYMENT_DATA_VERSION;
            if (delta > 0.01) {
                mender_log_debug("Unsupported deployment data version");
                return false;
            }
        }
    }

    return true;
}

mender_err_t
mender_set_deployment_data(mender_deployment_data_t *deployment_data) {

    assert(NULL != deployment_data);

    /* Validate deployment data */
    if (!validate_deployment_data(deployment_data)) {
        mender_log_error("Invalid deployment data");
        return MENDER_FAIL;
    }

    /* Check if max state data store count is reached */
    cJSON *item = cJSON_GetObjectItemCaseSensitive(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_STATE_DATA_STORE_COUNT);
    assert(NULL != item); /* Validation above should have catched this already */
    if (MAX_STATE_DATA_STORE_COUNT <= cJSON_GetNumberValue(item)) {
        mender_log_error("Reached max state data store count");
        return MENDER_FAIL;
    }

    /* Increment state data store count */
    cJSON_SetNumberValue(item, cJSON_GetNumberValue(item) + 1.0);

    /* Compose JSON string */
    char *json_str;
    if (NULL == (json_str = cJSON_PrintUnformatted(deployment_data))) {
        mender_log_error("Unable to compose deployment data");
        return MENDER_FAIL;
    }

    /* Write to store */
    if (MENDER_OK != mender_storage_set_deployment_data(json_str)) {
        /* Error already logged */
        free(json_str);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_get_deployment_data(mender_deployment_data_t **deployment_data) {

    assert(NULL != deployment_data);

    mender_err_t ret;
    char        *json_str;

    if (MENDER_OK != (ret = mender_storage_get_deployment_data(&json_str))) {
        /* Error already logged */
        return ret;
    }

    /* Parse deployment data from JSON string. */
    *deployment_data = cJSON_Parse(json_str);
    free(json_str);
    if (NULL == deployment_data) {
        mender_log_error("Unable to parse deployment data");
        return MENDER_FAIL;
    }

    /* Validate deployment data */
    if (!validate_deployment_data(*deployment_data)) {
        mender_log_error("Invalid deployment data");
        DESTROY_AND_NULL(cJSON_Delete, *deployment_data);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_create_deployment_data(const char *id, const char *artifact_name, mender_deployment_data_t **deployment_data) {

    assert(NULL != deployment_data);

    cJSON *item = NULL;

    if (NULL == (*deployment_data = cJSON_CreateObject())) {
        goto FAIL;
    }

    /* Add version field */
    if (NULL == cJSON_AddNumberToObject(*deployment_data, MENDER_DEPLOYMENT_DATA_KEY_VERSION, DEPLOYMENT_DATA_VERSION)) {
        goto FAIL;
    }

    /* Add deployment ID field */
    if (NULL == (item = (NULL == id) ? cJSON_CreateNull() : cJSON_CreateString(id))) {
        goto FAIL;
    }
    if (!cJSON_AddItemToObject(*deployment_data, MENDER_DEPLOYMENT_DATA_KEY_ID, item)) {
        goto FAIL;
    }
    item = NULL;

    /* Add artifact name field */
    if (NULL == (item = (NULL == artifact_name) ? cJSON_CreateNull() : cJSON_CreateString(artifact_name))) {
        goto FAIL;
    }
    if (!cJSON_AddItemToObject(*deployment_data, MENDER_DEPLOYMENT_DATA_KEY_ARTIFACT_NAME, item)) {
        goto FAIL;
    }
    item = NULL;

    /* Initialize payload types field as empty array. This one needs to be populated later */
    if (NULL == cJSON_AddArrayToObject(*deployment_data, MENDER_DEPLOYMENT_DATA_KEY_PAYLOAD_TYPES)) {
        goto FAIL;
    }

    /* Add provides field */
    item = cJSON_CreateNull();
    if (!cJSON_AddItemToObject(*deployment_data, MENDER_DEPLOYMENT_DATA_KEY_PROVIDES, item)) {
        goto FAIL;
    }
    item = NULL;

    /* Add state field */
    item = cJSON_CreateNull();
    if (!cJSON_AddItemToObject(*deployment_data, MENDER_DEPLOYMENT_DATA_KEY_STATE, item)) {
        goto FAIL;
    }
    item = NULL;

    /* Initialize state data store count to zero */
    if (NULL == (cJSON_AddNumberToObject(*deployment_data, MENDER_DEPLOYMENT_DATA_KEY_STATE_DATA_STORE_COUNT, 0.0))) {
        goto FAIL;
    }

    return MENDER_OK;

FAIL:
    /* Only memory allocation errors are possible */
    mender_log_error("Unable to allocate memory");

    cJSON_Delete(item);
    cJSON_Delete(*deployment_data);
    *deployment_data = NULL;

    return MENDER_FAIL;
}

mender_err_t
__mender_deployment_data_get_string(const mender_deployment_data_t *deployment_data, const char *key, const char **str) {

    assert(NULL != deployment_data);
    assert(NULL != key);
    assert(NULL != str);

    cJSON *item;
    if (NULL == (item = cJSON_GetObjectItemCaseSensitive(deployment_data, key))) {
        return MENDER_FAIL;
    }

    *str = cJSON_GetStringValue(item);

    /* Can hold JSON null, see mender_create_deployment_data() */
    assert(NULL != *str || cJSON_IsNull(item));

    return MENDER_OK;
}

mender_err_t
__mender_deployment_data_set_string(mender_deployment_data_t *deployment_data, const char *key, const char *str) {

    assert(NULL != deployment_data);
    assert(NULL != key);
    assert(NULL != str);

    cJSON *item;
    if (NULL == (item = cJSON_CreateString(str))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    if (!cJSON_ReplaceItemInObjectCaseSensitive(deployment_data, key, item)) {
        mender_log_error("Unable to allocate memory");
        cJSON_Delete(item);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_deployment_data_add_payload_type(mender_deployment_data_t *deployment_data, const char *payload_type) {

    assert(NULL != deployment_data);
    assert(NULL != payload_type);

    cJSON *types;
    if (NULL == (types = cJSON_GetObjectItemCaseSensitive(deployment_data, "payload_types"))) {
        return MENDER_FAIL;
    }

    bool   found = false;
    cJSON *type  = NULL;
    cJSON_ArrayForEach(type, types) {
        if (StringEqual(payload_type, cJSON_GetStringValue(type))) {
            found = true;
            break;
        }
    }

    if (!found) {
        if (!cJSON_AddItemToArray(types, cJSON_CreateString(payload_type))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
    }

    return MENDER_OK;
}
