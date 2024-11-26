/**
 * @file      mender-api.c
 * @brief     Implementation of the Mender API
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

#define _GNU_SOURCE // asprintf
#include <stdio.h>  // asprintf

#include "mender-api.h"
#include "mender-artifact.h"
#include "mender-error-counters.h"
#include "mender-scheduler.h"
#include "mender-storage.h"
#include "mender-http.h"
#include "mender-log.h"
#include "mender-tls.h"

/**
 * @brief Paths of the mender-server APIs
 */
#define MENDER_API_PATH_POST_AUTHENTICATION_REQUESTS "/api/devices/v1/authentication/auth_requests"
#define MENDER_API_PATH_GET_NEXT_DEPLOYMENT          "/api/devices/v1/deployments/device/deployments/next"
#define MENDER_API_PATH_POST_NEXT_DEPLOYMENT_V2      "/api/devices/v2/deployments/device/deployments/next"
#define MENDER_API_PATH_PUT_DEPLOYMENT_STATUS        "/api/devices/v1/deployments/device/deployments/%s/status"
#define MENDER_API_PATH_GET_DEVICE_CONFIGURATION     "/api/devices/v1/deviceconfig/configuration"
#define MENDER_API_PATH_PUT_DEVICE_CONFIGURATION     "/api/devices/v1/deviceconfig/configuration"
#define MENDER_API_PATH_GET_DEVICE_CONNECT           "/api/devices/v1/deviceconnect/connect"
#define MENDER_API_PATH_PUT_DEVICE_ATTRIBUTES        "/api/devices/v1/inventory/device/attributes"

/**
 * @brief Mender API configuration
 */
static mender_api_config_t api_config;

/**
 * @brief Authentication token
 */
static char *api_jwt = NULL;

/**
 * @brief A mutex ensuring there are no concurrent operations using or updating the authentication token
 */
static void *auth_lock = NULL;

/**
 * @brief HTTP callback used to handle text content
 * @param event HTTP client event
 * @param data Data received
 * @param data_length Data length
 * @param params Callback parameters
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_api_http_text_callback(mender_http_client_event_t event, void *data, size_t data_length, void *params);

/**
 * @brief Perform authentication of the device, retrieve token from mender-server used for the next requests
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t perform_authentication(void);

/**
 * @brief Ensure authenticated and holding the #auth_lock
 * @return MENDER_OK if success, MENDER_LOCK_FAILED in case of lock failure, other errors otherwise
 */
static mender_err_t ensure_authenticated_and_locked(void);

mender_err_t
mender_api_init(mender_api_config_t *config) {
    assert(NULL != config);
    assert(NULL != config->device_type);
    assert(NULL != config->host);
    assert(NULL != config->identity_cb);

    mender_err_t ret;

    /* Save configuration */
    memcpy(&api_config, config, sizeof(mender_api_config_t));

    /* Initializations */
    mender_http_config_t mender_http_config = { .host = api_config.host };
    if (MENDER_OK != (ret = mender_http_init(&mender_http_config))) {
        mender_log_error("Unable to initialize HTTP");
        return ret;
    }

    if (MENDER_OK != (ret = mender_scheduler_mutex_create(&auth_lock))) {
        mender_log_error("Unable to initialize authentication lock");
        return ret;
    }

    return ret;
}

mender_err_t
mender_api_drop_authentication_data(void) {
    mender_err_t ret;
    if (MENDER_OK != (ret = mender_scheduler_mutex_take(auth_lock, -1))) {
        mender_log_error("Unable to obtain the authentication lock");
        return MENDER_LOCK_FAILED;
    }
    FREE_AND_NULL(api_jwt);
    if (MENDER_OK != (ret = mender_scheduler_mutex_give(auth_lock))) {
        mender_log_error("Unable to release the authentication lock");
    }

    return ret;
}

mender_err_t
mender_api_ensure_authenticated(void) {
    mender_err_t ret = ensure_authenticated_and_locked();
    if (MENDER_LOCK_FAILED == ret) {
        /* Error already logged. */
        return MENDER_FAIL;
    }

    if (MENDER_OK != (ret = mender_scheduler_mutex_give(auth_lock))) {
        mender_log_error("Unable to release the authentication lock");
    }

    return ret;
}

static mender_err_t
ensure_authenticated_and_locked(void) {
    mender_err_t ret;

    if (MENDER_OK != (ret = mender_scheduler_mutex_take(auth_lock, -1))) {
        mender_log_error("Unable to obtain the authentication lock");
        return MENDER_LOCK_FAILED;
    }

    if (NULL != api_jwt) {
        return MENDER_DONE;
    }

    /* Perform authentication with the mender server */
    if (MENDER_OK != (ret = perform_authentication())) {
        mender_log_error("Authentication failed");
        return MENDER_FAIL;
    } else {
        mender_log_debug("Authenticated successfully");
    }

    return ret;
}

static mender_err_t
perform_authentication(void) {
    mender_err_t             ret;
    char                    *public_key_pem   = NULL;
    const mender_identity_t *identity         = NULL;
    cJSON                   *json_identity    = NULL;
    char                    *identity_info    = NULL;
    cJSON                   *json_payload     = NULL;
    char                    *payload          = NULL;
    char                    *response         = NULL;
    char                    *signature        = NULL;
    size_t                   signature_length = 0;
    int                      status           = 0;

    /* Get public key in PEM format */
    if (MENDER_OK != (ret = mender_tls_get_public_key_pem(&public_key_pem))) {
        mender_log_error("Unable to get public key");
        goto END;
    }

    /* Get identity (we don't own the returned data) */
    if (MENDER_OK != (ret = api_config.identity_cb(&identity))) {
        mender_log_error("Unable to get identity");
        goto END;
    }

    /* Format identity */
    if (MENDER_OK != (ret = mender_utils_identity_to_json(identity, &json_identity))) {
        mender_log_error("Unable to format identity");
        goto END;
    }
    if (NULL == (identity_info = cJSON_PrintUnformatted(json_identity))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Format payload */
    if (NULL == (json_payload = cJSON_CreateObject())) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    cJSON_AddStringToObject(json_payload, "id_data", identity_info);
    cJSON_AddStringToObject(json_payload, "pubkey", public_key_pem);
    if (NULL != api_config.tenant_token) {
        cJSON_AddStringToObject(json_payload, "tenant_token", api_config.tenant_token);
    }
    if (NULL == (payload = cJSON_PrintUnformatted(json_payload))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Sign payload */
    if (MENDER_OK != (ret = mender_tls_sign_payload(payload, &signature, &signature_length))) {
        mender_log_error("Unable to sign payload");
        goto END;
    }

    /* Perform HTTP request */
    if (MENDER_OK
        != (ret = mender_http_perform(NULL,
                                      MENDER_API_PATH_POST_AUTHENTICATION_REQUESTS,
                                      MENDER_HTTP_POST,
                                      payload,
                                      signature,
                                      &mender_api_http_text_callback,
                                      (void *)&response,
                                      &status))) {
        mender_log_error("Unable to perform HTTP request");
        mender_err_count_net_inc();
        goto END;
    }

    /* Treatment depending of the status */
    if (200 == status) {
        if (NULL == response) {
            mender_log_error("Response is empty");
            ret = MENDER_FAIL;
            goto END;
        }
        if (NULL != api_jwt) {
            free(api_jwt);
        }
        if (NULL == (api_jwt = strdup(response))) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }
        ret = MENDER_OK;
    } else {
        mender_api_print_response_error(response, status);
        /* Maybe the identity is wrong? Let's make sure we get fresh data for the next attempt. */
        FREE_AND_NULL(identity_info);
        ret = MENDER_FAIL;
    }

END:

    /* Release memory */
    free(response);
    free(signature);
    free(payload);
    cJSON_Delete(json_payload);
    cJSON_Delete(json_identity);
    free(identity_info);
    free(public_key_pem);

    return ret;
}

/**
 * @see mender_http_perform()
 */
static mender_err_t
authenticated_http_perform(char *path, mender_http_method_t method, char *payload, char *signature, char **response, int *status) {
    mender_err_t ret;

    if (MENDER_IS_ERROR(ret = ensure_authenticated_and_locked())) {
        /* Errors already logged. */
        if (MENDER_LOCK_FAILED != ret) {
            if (MENDER_OK != mender_scheduler_mutex_give(auth_lock)) {
                mender_log_error("Unable to release the authentication lock");
                return MENDER_FAIL;
            }
        }
        return ret;
    }

    ret = mender_http_perform(api_jwt, path, method, payload, signature, &mender_api_http_text_callback, response, status);
    if (MENDER_OK != mender_scheduler_mutex_give(auth_lock)) {
        mender_log_error("Unable to release the authentication lock");
        return MENDER_FAIL;
    }
    if (MENDER_OK != ret) {
        /* HTTP errors already logged. */
        mender_err_count_net_inc();
        return ret;
    }

    if (401 == *status) {
        /* Unauthorized => try to re-authenticate and perform the request again */
        mender_log_info("Trying to re-authenticate");
        FREE_AND_NULL(api_jwt);
        if (MENDER_IS_ERROR(ret = ensure_authenticated_and_locked())) {
            free(*response);
            ret = mender_http_perform(api_jwt, path, method, payload, signature, &mender_api_http_text_callback, response, status);
            if (MENDER_OK != mender_scheduler_mutex_give(auth_lock)) {
                mender_log_error("Unable to release the authentication lock");
                return MENDER_FAIL;
            }
            if (MENDER_OK != ret) {
                /* HTTP errors already logged. */
                mender_err_count_net_inc();
            }
        } else if (MENDER_LOCK_FAILED != ret) {
            if (MENDER_OK != mender_scheduler_mutex_give(auth_lock)) {
                mender_log_error("Unable to release the authentication lock");
                return MENDER_FAIL;
            }
        }
    }

    return ret;
}

static mender_err_t
api_check_for_deployment_v2(int *status, char **response) {
    assert(NULL != status);
    assert(NULL != response);

    mender_err_t ret           = MENDER_FAIL;
    cJSON       *json_payload  = NULL;
    char        *payload       = NULL;
    const char  *artifact_name = NULL;
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
    mender_key_value_list_t *provides = NULL;
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */

    /* Create payload */
    if (NULL == (json_payload = cJSON_CreateObject())) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }

    /* Add "device_provides" entity to payload */
    cJSON *json_provides = NULL;
    if (NULL == (json_provides = cJSON_AddObjectToObject(json_payload, "device_provides"))) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }

    if (NULL == cJSON_AddStringToObject(json_provides, "device_type", api_config.device_type)) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }

#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
    /* Add provides from storage */
    if (MENDER_FAIL == mender_storage_get_provides(&provides)) {
        mender_log_error("Unable to get provides");
        goto END;
    }
    for (mender_key_value_list_t *item = provides; NULL != item; item = item->next) {
        if (NULL == cJSON_AddStringToObject(json_provides, item->key, item->value)) {
            mender_log_error("Unable to allocate memory");
            goto END;
        }
    }
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */

    if ((MENDER_OK != mender_storage_get_artifact_name(&artifact_name)) && (NULL != artifact_name)) {
        mender_log_error("Unable to get artifact name");
        return MENDER_FAIL;
    }

    if (NULL == cJSON_AddStringToObject(json_provides, "artifact_name", artifact_name)) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }

    if (NULL == (payload = cJSON_PrintUnformatted(json_payload))) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }

    /* Perform HTTP request */
    if (MENDER_OK != (ret = authenticated_http_perform(MENDER_API_PATH_POST_NEXT_DEPLOYMENT_V2, MENDER_HTTP_POST, payload, NULL, response, status))) {
        mender_log_error("Unable to perform HTTP request");
        goto END;
    }

    ret = MENDER_OK;

END:

#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
    mender_utils_key_value_list_free(provides);
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
    cJSON_Delete(json_payload);
    free(payload);
    return ret;
}

static mender_err_t
api_check_for_deployment_v1(int *status, char **response) {

    assert(NULL != status);
    assert(NULL != response);

    mender_err_t ret           = MENDER_FAIL;
    char        *path          = NULL;
    const char  *artifact_name = NULL;

    if ((MENDER_OK != mender_storage_get_artifact_name(&artifact_name)) && (NULL != artifact_name)) {
        mender_log_error("Unable to get artifact name");
        return MENDER_FAIL;
    }

    /* Compute path */
    if (-1 == asprintf(&path, MENDER_API_PATH_GET_NEXT_DEPLOYMENT "?artifact_name=%s&device_type=%s", artifact_name, api_config.device_type)) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }

    /* Perform HTTP request */
    if (MENDER_OK != (ret = authenticated_http_perform(path, MENDER_HTTP_GET, NULL, NULL, response, status))) {
        mender_log_error("Unable to perform HTTP request");
        goto END;
    }

    ret = MENDER_OK;

END:

    /* Release memory */
    free(path);

    return ret;
}

mender_err_t
mender_api_check_for_deployment(mender_api_deployment_data_t *deployment) {

    assert(NULL != deployment);
    mender_err_t ret      = MENDER_FAIL;
    char        *response = NULL;
    int          status   = 0;

    if (MENDER_FAIL == (ret = api_check_for_deployment_v2(&status, &response))) {
        goto END;
    }

    /* Yes, 404 still means MENDER_OK above */
    if (404 == status) {
        mender_log_debug("POST request to v2 version of the deployments API failed, falling back to v1 version and GET");
        FREE_AND_NULL(response);
        if (MENDER_FAIL == (ret = api_check_for_deployment_v1(&status, &response))) {
            goto END;
        }
    }

    /* Treatment depending of the status */
    if (200 == status) {
        cJSON *json_response = cJSON_Parse(response);
        if (NULL != json_response) {
            cJSON *json_id = cJSON_GetObjectItem(json_response, "id");
            if (NULL != json_id) {
                if (NULL == (deployment->id = strdup(cJSON_GetStringValue(json_id)))) {
                    ret = MENDER_FAIL;
                    goto END;
                }
            }
            cJSON *json_artifact = cJSON_GetObjectItem(json_response, "artifact");
            if (NULL != json_artifact) {
                cJSON *json_artifact_name = cJSON_GetObjectItem(json_artifact, "artifact_name");
                if (NULL != json_artifact_name) {
                    if (NULL == (deployment->artifact_name = strdup(cJSON_GetStringValue(json_artifact_name)))) {
                        ret = MENDER_FAIL;
                        goto END;
                    }
                }
                cJSON *json_source = cJSON_GetObjectItem(json_artifact, "source");
                if (NULL != json_source) {
                    cJSON *json_uri = cJSON_GetObjectItem(json_source, "uri");
                    if (NULL != json_uri) {
                        if (NULL == (deployment->uri = strdup(cJSON_GetStringValue(json_uri)))) {
                            ret = MENDER_FAIL;
                            goto END;
                        }
                        ret = MENDER_OK;
                    } else {
                        mender_log_error("Invalid response");
                        ret = MENDER_FAIL;
                    }
                } else {
                    mender_log_error("Invalid response");
                    ret = MENDER_FAIL;
                }
                cJSON *json_device_types_compatible = cJSON_GetObjectItem(json_artifact, "device_types_compatible");
                if (NULL != json_device_types_compatible && cJSON_IsArray(json_device_types_compatible)) {
                    deployment->device_types_compatible_size = cJSON_GetArraySize(json_device_types_compatible);
                    deployment->device_types_compatible      = (char **)malloc(deployment->device_types_compatible_size * sizeof(char *));
                    if (NULL == deployment->device_types_compatible) {
                        mender_log_error("Unable to allocate memory");
                        ret = MENDER_FAIL;
                        goto END;
                    }
                    for (size_t i = 0; i < deployment->device_types_compatible_size; i++) {
                        cJSON *json_device_type = cJSON_GetArrayItem(json_device_types_compatible, i);
                        if (NULL != json_device_type && cJSON_IsString(json_device_type)) {
                            if (NULL == (deployment->device_types_compatible[i] = strdup(cJSON_GetStringValue(json_device_type)))) {
                                ret = MENDER_FAIL;
                                goto END;
                            }
                        } else {
                            mender_log_error("Could not get device type form device_types_compatible array");
                            ret = MENDER_FAIL;
                        }
                    }
                } else {
                    mender_log_error("Could not load device_types_compatible");
                    ret = MENDER_FAIL;
                }
            } else {
                mender_log_error("Invalid response");
                ret = MENDER_FAIL;
            }
            cJSON_Delete(json_response);
        } else {
            mender_log_error("Invalid response");
            ret = MENDER_FAIL;
        }
    } else if (204 == status) {
        /* No response expected */
        ret = MENDER_NOT_FOUND;
    } else {
        mender_api_print_response_error(response, status);
        ret = MENDER_FAIL;
    }

END:

    /* Release memory */
    free(response);

    return ret;
}

mender_err_t
mender_api_publish_deployment_status(const char *id, mender_deployment_status_t deployment_status) {
    assert(NULL != id);

    mender_err_t ret;
    char        *value        = NULL;
    cJSON       *json_payload = NULL;
    char        *payload      = NULL;
    char        *path         = NULL;
    char        *response     = NULL;
    int          status       = 0;

    /* Deployment status to string */
    if (NULL == (value = mender_utils_deployment_status_to_string(deployment_status))) {
        mender_log_error("Invalid status");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Format payload */
    if (NULL == (json_payload = cJSON_CreateObject())) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    cJSON_AddStringToObject(json_payload, "status", value);
    if (NULL == (payload = cJSON_PrintUnformatted(json_payload))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Compute path */
    size_t str_length = strlen(MENDER_API_PATH_PUT_DEPLOYMENT_STATUS) - strlen("%s") + strlen(id) + 1;
    if (NULL == (path = (char *)malloc(str_length))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    snprintf(path, str_length, MENDER_API_PATH_PUT_DEPLOYMENT_STATUS, id);

    /* Perform HTTP request */
    if (MENDER_OK != (ret = authenticated_http_perform(path, MENDER_HTTP_PUT, payload, NULL, &response, &status))) {
        mender_log_error("Unable to perform HTTP request");
        goto END;
    }

    /* Treatment depending of the status */
    if (204 == status) {
        /* No response expected */
        ret = MENDER_OK;
    } else {
        mender_api_print_response_error(response, status);
        ret = MENDER_FAIL;
    }

END:

    /* Release memory */
    free(response);
    free(path);
    free(payload);
    cJSON_Delete(json_payload);

    return ret;
}

#ifdef CONFIG_MENDER_CLIENT_INVENTORY

mender_err_t
mender_api_publish_inventory_data(mender_keystore_t *inventory) {

    mender_err_t ret;
    char        *payload       = NULL;
    char        *response      = NULL;
    int          status        = 0;
    const char  *artifact_name = NULL;

    if ((MENDER_OK != mender_storage_get_artifact_name(&artifact_name)) && (NULL != artifact_name)) {
        mender_log_error("Unable to get artifact name");
        return MENDER_FAIL;
    }

    /* Format payload */
    cJSON *object = cJSON_CreateArray();
    if (NULL == object) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    cJSON *item = cJSON_CreateObject();
    if (NULL == item) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    cJSON_AddStringToObject(item, "name", "artifact_name");
    cJSON_AddStringToObject(item, "value", artifact_name);
    cJSON_AddItemToArray(object, item);
    item = cJSON_CreateObject();
    if (NULL == item) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    cJSON_AddStringToObject(item, "name", "device_type");
    cJSON_AddStringToObject(item, "value", api_config.device_type);
    cJSON_AddItemToArray(object, item);
    if (NULL != inventory) {
        size_t index = 0;
        while ((NULL != inventory[index].name) && (NULL != inventory[index].value)) {
            if (NULL == (item = cJSON_CreateObject())) {
                mender_log_error("Unable to allocate memory");
                ret = MENDER_FAIL;
                goto END;
            }
            cJSON_AddStringToObject(item, "name", inventory[index].name);
            cJSON_AddStringToObject(item, "value", inventory[index].value);
            cJSON_AddItemToArray(object, item);
            index++;
        }
    }
    if (NULL == (payload = cJSON_PrintUnformatted(object))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Perform HTTP request */
    if (MENDER_OK != (ret = authenticated_http_perform(MENDER_API_PATH_PUT_DEVICE_ATTRIBUTES, MENDER_HTTP_PUT, payload, NULL, &response, &status))) {
        mender_log_error("Unable to perform HTTP request");
        goto END;
    }

    /* Treatment depending of the status */
    if (200 == status) {
        /* No response expected */
        ret = MENDER_OK;
    } else {
        mender_api_print_response_error(response, status);
        ret = MENDER_FAIL;
    }

END:

    /* Release memory */
    free(response);
    free(payload);
    cJSON_Delete(object);

    return ret;
}

#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

mender_err_t
mender_api_exit(void) {

    /* Release all modules */
    mender_http_exit();

    /* Destroy the authentication lock */
    mender_scheduler_mutex_delete(auth_lock);

    /* Release memory */
    FREE_AND_NULL(api_jwt);

    return MENDER_OK;
}

static mender_err_t
mender_api_http_text_callback(mender_http_client_event_t event, void *data, size_t data_length, void *params) {

    assert(NULL != params);
    char       **response = (char **)params;
    mender_err_t ret      = MENDER_OK;
    char        *tmp;

    /* Treatment depending of the event */
    switch (event) {
        case MENDER_HTTP_EVENT_CONNECTED:
            /* Nothing to do */
            break;
        case MENDER_HTTP_EVENT_DATA_RECEIVED:
            /* Check input data */
            if ((NULL == data) || (0 == data_length)) {
                mender_log_error("Invalid data received");
                ret = MENDER_FAIL;
                break;
            }
            /* Concatenate data to the response */
            size_t response_length = (NULL != *response) ? strlen(*response) : 0;
            if (NULL == (tmp = realloc(*response, response_length + data_length + 1))) {
                mender_log_error("Unable to allocate memory");
                ret = MENDER_FAIL;
                break;
            }
            *response = tmp;
            memcpy((*response) + response_length, data, data_length);
            *((*response) + response_length + data_length) = '\0';
            break;
        case MENDER_HTTP_EVENT_DISCONNECTED:
            /* Nothing to do */
            break;
        case MENDER_HTTP_EVENT_ERROR:
            /* Downloading the response fails */
            mender_log_error("An error occurred");
            ret = MENDER_FAIL;
            break;
        default:
            /* Should no occur */
            ret = MENDER_FAIL;
            break;
    }

    return ret;
}

void
mender_api_print_response_error(char *response, int status) {
    const char *desc;

    /* Treatment depending of the status */
    if (NULL != (desc = mender_utils_http_status_to_string(status))) {
        if (NULL != response) {
            cJSON *json_response = cJSON_Parse(response);
            if (NULL != json_response) {
                cJSON *json_error = cJSON_GetObjectItemCaseSensitive(json_response, "error");
                if (NULL != json_error) {
                    mender_log_error("[%d] %s: %s", status, desc, cJSON_GetStringValue(json_error));
                } else {
                    mender_log_error("[%d] %s: unknown error", status, desc);
                }
                cJSON_Delete(json_response);
            } else {
                mender_log_error("[%d] %s: unknown error", status, desc);
            }
        } else {
            mender_log_error("[%d] %s: unknown error", status, desc);
        }
    } else {
        mender_log_error("Unknown error occurred, status=%d", status);
    }
}
