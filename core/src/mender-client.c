/**
 * @file      mender-client.c
 * @brief     Mender MCU client implementation
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
#include "mender-artifact.h"
#include "mender-flash.h"
#include "mender-log.h"
#include "mender-scheduler.h"
#include "mender-storage.h"
#include "mender-tls.h"

/**
 * @brief Default host
 */
#ifndef CONFIG_MENDER_SERVER_HOST
#define CONFIG_MENDER_SERVER_HOST "https://hosted.mender.io"
#endif /* CONFIG_MENDER_SERVER_HOST */

/**
 * @brief Default tenant token
 */
#ifndef CONFIG_MENDER_SERVER_TENANT_TOKEN
#define CONFIG_MENDER_SERVER_TENANT_TOKEN NULL
#endif /* CONFIG_MENDER_SERVER_TENANT_TOKEN */

/**
 * @brief Default authentication poll interval (seconds)
 */
#ifndef CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL
#define CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL (600)
#endif /* CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL */

/**
 * @brief Default update poll interval (seconds)
 */
#ifndef CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL
#define CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL (1800)
#endif /* CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL */

/**
 * @brief Mender client configuration
 */
static mender_client_config_t mender_client_config;

/**
 * @brief Mender client callbacks
 */
static mender_client_callbacks_t mender_client_callbacks;

/**
 * @brief Mender client states
 */
typedef enum {
    MENDER_CLIENT_STATE_INITIALIZATION, /**< Perform initialization */
    MENDER_CLIENT_STATE_AUTHENTICATION, /**< Perform authentication with the server */
    MENDER_CLIENT_STATE_AUTHENTICATED,  /**< Perform updates */
} mender_client_state_t;

/**
 * @brief Mender client state
 */
static mender_client_state_t mender_client_state = MENDER_CLIENT_STATE_INITIALIZATION;

/**
 * @brief Deployment data (ID, artifact name and payload types), used to report deployment status after rebooting
 */
static cJSON *mender_client_deployment_data = NULL;

/**
 * @brief Mender client artifact type
 */
typedef struct {
    char *type; /**< Artifact type */
    mender_err_t (*callback)(
        char *, char *, char *, cJSON *, char *, size_t, void *, size_t, size_t); /**< Callback to be invoked to handle the artifact type */
    bool  needs_restart;                                                          /**< Indicate the artifact type needs a restart to be applied on the system */
    char *artifact_name; /**< Artifact name (optional, NULL otherwise), set to validate module update after restarting */
} mender_client_artifact_type_t;

/**
 * @brief Mender client artifact types list and mutex
 */
static mender_client_artifact_type_t **mender_client_artifact_types_list  = NULL;
static size_t                          mender_client_artifact_types_count = 0;
static void                           *mender_client_artifact_types_mutex = NULL;

/**
 * @brief Mender client add-ons list and mutex
 */
static mender_addon_instance_t **mender_client_addons_list  = NULL;
static size_t                    mender_client_addons_count = 0;
static void                     *mender_client_addons_mutex = NULL;

/**
 * @brief Flash handle used to store temporary reference to write rootfs-image data
 */
static void *mender_client_flash_handle = NULL;

/**
 * @brief Flag to indicate if the deployment needs to set pending image status
 */
static bool mender_client_deployment_needs_set_pending_image = false;

/**
 * @brief Flag to indicate if the deployment needs restart
 */
static bool mender_client_deployment_needs_restart = false;

/**
 * @brief Mender client work function
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_client_work_function(void);

/**
 * @brief Mender client initialization work function
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_client_initialization_work_function(void);

/**
 * @brief Mender client authentication work function
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_client_authentication_work_function(void);

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
/**
 * @brief Compare artifact, device and deployment device types
 * @param device_type_artifact Device type of artifact
 * @param device_type_device Device type of configuration
 * @param device_type_deployment Device types of deployment
 * @param device_type_deployment_size Deployment device types size
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_compare_device_types(const char  *device_type_artifact,
                                                const char  *device_type_device,
                                                const char **device_type_deployment,
                                                const size_t device_type_deployment_size);
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
/**
 * @brief Filter provides and merge the two lists
 * @param mender_artifact_ctx Mender artifact context
 * @param new_provides New provides list
 * @param stored_provides Stored provides list
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_filter_provides(mender_artifact_ctx_t    *mender_artifact_ctx,
                                           mender_key_value_list_t **new_provides,
                                           mender_key_value_list_t **stored_provides);
/**
 * @brief Prepare the new provides data to be commited on a successful deployment
 * @param mender_artifact_ctx Mender artifact context
 * @param provides Provies data to be written
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_prepare_new_provides(mender_artifact_ctx_t *mender_artifact_ctx, char **provides);

/**
 * @brief Determine the compatiblity of the deployment by: comparing artifact's depend with the stored provides
 * @param mender_artifact_ctx Mender artifact context
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_check_device_compatibility(mender_artifact_ctx_t *mender_artifact_ctx);
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

/**
 * @brief Mender client update work function
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_client_update_work_function(void);

/**
 * @brief Callback function to be invoked to perform the treatment of the data from the artifact
 * @param id ID of the deployment
 * @param artifact name Artifact name
 * @param type Type from header-info payloads
 * @param meta_data Meta-data from header tarball
 * @param filename Artifact filename
 * @param size Artifact file size
 * @param data Artifact data
 * @param index Artifact data index
 * @param length Artifact data length
 * @return MENDER_OK if the function succeeds, error code if an error occurred
 */
static mender_err_t mender_client_download_artifact_callback(
    char *type, cJSON *meta_data, char *filename, size_t size, void *data, size_t index, size_t length);

/**
 * @brief Callback function to be invoked to perform the treatment of the data from the artifact type "rootfs-image"
 * @param id ID of the deployment
 * @param artifact name Artifact name
 * @param type Type from header-info payloads
 * @param meta_data Meta-data from header tarball
 * @param filename Artifact filename
 * @param size Artifact file size
 * @param data Artifact data
 * @param index Artifact data index
 * @param length Artifact data length
 * @return MENDER_OK if the function succeeds, error code if an error occurred
 */
static mender_err_t mender_client_download_artifact_flash_callback(
    char *id, char *artifact_name, char *type, cJSON *meta_data, char *filename, size_t size, void *data, size_t index, size_t length);

/**
 * @brief Publish deployment status of the device to the mender-server and invoke deployment status callback
 * @param id ID of the deployment
 * @param deployment_status Deployment status
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_client_publish_deployment_status(char *id, mender_deployment_status_t deployment_status);

char *
mender_client_version(void) {

    /* Return version as string */
    return MENDER_CLIENT_VERSION;
}

mender_err_t
mender_client_init(mender_client_config_t *config, mender_client_callbacks_t *callbacks) {

    assert(NULL != config);
    assert(NULL != config->artifact_name);
    assert(NULL != config->device_type);
    assert(NULL != callbacks);
    assert(NULL != callbacks->restart);
    mender_err_t ret;

    mender_client_config.artifact_name = config->artifact_name;
    mender_client_config.device_type   = config->device_type;

    mender_log_info("Artifact name: [%s]; device type: [%s]", mender_client_config.artifact_name, mender_client_config.device_type);

    if ((NULL != config->host) && (strlen(config->host) > 0)) {
        mender_client_config.host = config->host;
    } else {
        mender_client_config.host = CONFIG_MENDER_SERVER_HOST;
    }
    if ((NULL == mender_client_config.host) || (0 == strlen(mender_client_config.host))) {
        mender_log_error("Invalid server host configuration, can't be null or empty");
        ret = MENDER_FAIL;
        goto END;
    }
    if ('/' == mender_client_config.host[strlen(mender_client_config.host) - 1]) {
        mender_log_error("Invalid server host configuration, trailing '/' is not allowed");
        ret = MENDER_FAIL;
        goto END;
    }
    if ((NULL != config->tenant_token) && (strlen(config->tenant_token) > 0)) {
        mender_client_config.tenant_token = config->tenant_token;
    } else {
        mender_client_config.tenant_token = CONFIG_MENDER_SERVER_TENANT_TOKEN;
    }
    if ((NULL != mender_client_config.tenant_token) && (0 == strlen(mender_client_config.tenant_token))) {
        mender_client_config.tenant_token = NULL;
    }
    if (0 != config->authentication_poll_interval) {
        mender_client_config.authentication_poll_interval = config->authentication_poll_interval;
    } else {
        mender_client_config.authentication_poll_interval = CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL;
    }
    if (0 != config->update_poll_interval) {
        mender_client_config.update_poll_interval = config->update_poll_interval;
    } else {
        mender_client_config.update_poll_interval = CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL;
    }
    mender_client_config.recommissioning = config->recommissioning;

    /* Save callbacks */
    memcpy(&mender_client_callbacks, callbacks, sizeof(mender_client_callbacks_t));

    /* Initializations */
    if (MENDER_OK != (ret = mender_scheduler_alt_work_create(mender_client_work_function, mender_client_config.update_poll_interval))) {
        mender_log_error("Unable to initialize scheduler");
        goto END;
    }
    if (MENDER_OK != (ret = mender_log_init())) {
        mender_log_error("Unable to initialize log");
        goto END;
    }
    if (MENDER_OK != (ret = mender_storage_init())) {
        mender_log_error("Unable to initialize storage");
        goto END;
    }
    if (MENDER_OK != (ret = mender_tls_init())) {
        mender_log_error("Unable to initialize TLS");
        goto END;
    }
    mender_api_config_t mender_api_config = {
        .artifact_name = mender_client_config.artifact_name,
        .device_type   = mender_client_config.device_type,
        .host          = mender_client_config.host,
        .tenant_token  = mender_client_config.tenant_token,
    };
    if (MENDER_OK != (ret = mender_api_init(&mender_api_config))) {
        mender_log_error("Unable to initialize API");
        goto END;
    }

    /* Register rootfs-image artifact type */
    if (MENDER_OK
        != (ret = mender_client_register_artifact_type("rootfs-image", &mender_client_download_artifact_flash_callback, true, config->artifact_name))) {
        mender_log_error("Unable to register 'rootfs-image' artifact type");
        goto END;
    }

END:

    return ret;
}

mender_err_t
mender_client_register_artifact_type(char *type,
                                     mender_err_t (*callback)(char *, char *, char *, cJSON *, char *, size_t, void *, size_t, size_t),
                                     bool  needs_restart,
                                     char *artifact_name) {

    assert(NULL != type);
    mender_client_artifact_type_t  *artifact_type;
    mender_client_artifact_type_t **tmp;
    mender_err_t                    ret = MENDER_OK;

    /* Create mender artifact type */
    if (NULL == (artifact_type = (mender_client_artifact_type_t *)malloc(sizeof(mender_client_artifact_type_t)))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    artifact_type->type          = type;
    artifact_type->callback      = callback;
    artifact_type->needs_restart = needs_restart;
    artifact_type->artifact_name = artifact_name;

    /* Add mender artifact type to the list */
    if (NULL
        == (tmp = (mender_client_artifact_type_t **)realloc(mender_client_artifact_types_list,
                                                            (mender_client_artifact_types_count + 1) * sizeof(mender_client_artifact_type_t *)))) {
        mender_log_error("Unable to allocate memory");
        free(artifact_type);
        ret = MENDER_FAIL;
        goto END;
    }
    mender_client_artifact_types_list                                     = tmp;
    mender_client_artifact_types_list[mender_client_artifact_types_count] = artifact_type;
    mender_client_artifact_types_count++;

END:

    return ret;
}

mender_err_t
mender_client_register_addon(mender_addon_instance_t *addon, void *config, void *callbacks) {

    assert(NULL != addon);
    mender_addon_instance_t **tmp;
    mender_err_t              ret = MENDER_OK;

    /* Initialization of the add-on */
    if (NULL != addon->init) {
        if (MENDER_OK != (ret = addon->init(config, callbacks))) {
            mender_log_error("Unable to initialize add-on");
            goto END;
        }
    }

    /* Activate add-on if authentication is already done */
    if (MENDER_CLIENT_STATE_AUTHENTICATED == mender_client_state) {
        if (NULL != addon->activate) {
            if (MENDER_OK != (ret = addon->activate())) {
                mender_log_error("Unable to activate add-on");
                if (NULL != addon->exit) {
                    addon->exit();
                }
                goto END;
            }
        }
    }

    /* Add add-on to the list */
    if (NULL == (tmp = (mender_addon_instance_t **)realloc(mender_client_addons_list, (mender_client_addons_count + 1) * sizeof(mender_addon_instance_t *)))) {
        mender_log_error("Unable to allocate memory");
        if (NULL != addon->exit) {
            addon->exit();
        }
        ret = MENDER_FAIL;
        goto END;
    }
    mender_client_addons_list                             = tmp;
    mender_client_addons_list[mender_client_addons_count] = addon;
    mender_client_addons_count++;

END:

    return ret;
}

mender_err_t
mender_client_activate(void) {

    mender_scheduler_alt_work_start();

    return MENDER_OK;
}

//TODO: Remove when removing the add-ons
mender_err_t
mender_client_deactivate(void) {

    /* Deactivate add-ons */
    if (NULL != mender_client_addons_list) {
        for (size_t index = 0; index < mender_client_addons_count; index++) {
            if (NULL != mender_client_addons_list[index]->deactivate) {
                mender_client_addons_list[index]->deactivate();
            }
        }
    }

    return MENDER_OK;
}

//TODO: Remove when removing the add-ons
mender_err_t
mender_client_execute(void) {

    return MENDER_OK;
}

mender_err_t
mender_client_network_connect(void) {

    mender_err_t ret = MENDER_OK;

    /* Request network access */
    if (NULL != mender_client_callbacks.network_connect) {
        if (MENDER_OK != (ret = mender_client_callbacks.network_connect())) {
            mender_log_error("Unable to connect network");
            goto END;
        }
    }

END:

    return ret;
}

mender_err_t
mender_client_network_release(void) {

    mender_err_t ret = MENDER_OK;

    /* Release network access */
    if (NULL != mender_client_callbacks.network_release) {
        if (MENDER_OK != (ret = mender_client_callbacks.network_release())) {
            mender_log_error("Unable to release network");
            goto END;
        }
    }

END:

    return ret;
}

mender_err_t
mender_client_exit(void) {

    /* Release add-ons */
    if (NULL != mender_client_addons_list) {
        for (size_t index = 0; index < mender_client_addons_count; index++) {
            if (NULL != mender_client_addons_list[index]->exit) {
                mender_client_addons_list[index]->exit();
            }
        }
    }

    /* Release all modules */
    mender_api_exit();
    mender_tls_exit();
    mender_storage_exit();
    mender_log_exit();

    /* Release memory */
    mender_client_config.artifact_name                = NULL;
    mender_client_config.device_type                  = NULL;
    mender_client_config.host                         = NULL;
    mender_client_config.tenant_token                 = NULL;
    mender_client_config.authentication_poll_interval = 0;
    mender_client_config.update_poll_interval         = 0;
    if (NULL != mender_client_deployment_data) {
        cJSON_Delete(mender_client_deployment_data);
        mender_client_deployment_data = NULL;
    }
    if (NULL != mender_client_artifact_types_list) {
        for (size_t artifact_type_index = 0; artifact_type_index < mender_client_artifact_types_count; artifact_type_index++) {
            free(mender_client_artifact_types_list[artifact_type_index]);
        }
        free(mender_client_artifact_types_list);
        mender_client_artifact_types_list = NULL;
    }
    mender_client_artifact_types_count = 0;
    mender_client_artifact_types_mutex = NULL;
    if (NULL != mender_client_addons_list) {
        free(mender_client_addons_list);
        mender_client_addons_list = NULL;
    }
    mender_client_addons_count = 0;
    mender_client_addons_mutex = NULL;

    return MENDER_OK;
}

static mender_err_t
mender_client_work_function(void) {

    mender_err_t ret = MENDER_OK;

    mender_log_info("work function: %d", mender_client_state);

    switch (mender_client_state) {
        case MENDER_CLIENT_STATE_INITIALIZATION:
            mender_log_info("work function; initialization");
            if (MENDER_DONE != (ret = mender_client_initialization_work_function())) {
                return ret;
            }
            mender_client_state = MENDER_CLIENT_STATE_AUTHENTICATION;
            /* fallthrough */
        case MENDER_CLIENT_STATE_AUTHENTICATION:
            mender_log_info("work function; authentication");
            if (MENDER_DONE != (ret = mender_client_authentication_work_function())) {
                mender_client_network_release();
                return ret;
            }
            mender_client_state = MENDER_CLIENT_STATE_AUTHENTICATED;
            /* fallthrough */
        case MENDER_CLIENT_STATE_AUTHENTICATED:
            mender_log_info("work function; authenticated");
            ret = mender_client_update_work_function();
            break;
    }

    return ret;
}

static mender_err_t
mender_client_initialization_work_function(void) {

    char        *storage_deployment_data = NULL;
    mender_err_t ret                     = MENDER_DONE;

    /* Retrieve or generate authentication keys */
    if (MENDER_OK != (ret = mender_tls_init_authentication_keys(mender_client_callbacks.get_user_provided_keys, mender_client_config.recommissioning))) {
        mender_log_error("Unable to retrieve or generate authentication keys");
        goto END;
    }

    mender_log_info("Keys initialized");

    /* Retrieve deployment data if it is found (following an update) */
    if (MENDER_OK != (ret = mender_storage_get_deployment_data(&storage_deployment_data))) {
        if (MENDER_NOT_FOUND != ret) {
            mender_log_error("Unable to get deployment data");
            goto REBOOT;
        }
    }

    mender_log_info("Deployment data retrieved");

    if (NULL != storage_deployment_data) {
        if (NULL == (mender_client_deployment_data = cJSON_Parse(storage_deployment_data))) {
            mender_log_error("Unable to parse deployment data");
            free(storage_deployment_data);
            ret = MENDER_FAIL;
            goto REBOOT;
        }
        free(storage_deployment_data);
    }

    mender_log_info("Initialization done");

    return MENDER_DONE;

END:

    return ret;

REBOOT:

    mender_log_info("Rebooting...");

    /* Delete pending deployment */
    mender_storage_delete_deployment_data();

    /* Invoke restart callback, application is responsible to shutdown properly and restart the system */
    if (NULL != mender_client_callbacks.restart) {
        mender_client_callbacks.restart();
    }

    return ret;
}

static mender_err_t
mender_client_authentication_work_function(void) {

    mender_err_t ret;

    /* Perform authentication with the mender server */
    if (MENDER_OK != (ret = mender_api_perform_authentication(mender_client_callbacks.get_identity))) {

        /* Invoke authentication error callback */
        if (NULL != mender_client_callbacks.authentication_failure) {
            if (MENDER_OK != mender_client_callbacks.authentication_failure()) {

                /* Check if deployment is pending */
                if (NULL != mender_client_deployment_data) {
                    /* Authentication error callback inform the reboot should be done, probably something is broken and it prefers to rollback */
                    mender_log_error("Authentication error callback failed, rebooting");
                    goto REBOOT;
                }
            }
        }

        return ret;
    }

    /* Invoke authentication success callback */
    if (NULL != mender_client_callbacks.authentication_success) {
        if (MENDER_OK != mender_client_callbacks.authentication_success()) {

            /* Check if deployment is pending */
            if (NULL != mender_client_deployment_data) {
                /* Authentication success callback inform the reboot should be done, probably something is broken and it prefers to rollback */
                mender_log_error("Authentication success callback failed, rebooting");
                goto REBOOT;
            }
        }
    }

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
    /* New provides to be written on success */
    mender_key_value_list_t *new_provides = NULL;
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */

    /* Check if deployment is pending */
    if (NULL != mender_client_deployment_data) {

        /* Retrieve deployment data */
        cJSON *json_id = NULL;
        if (NULL == (json_id = cJSON_GetObjectItemCaseSensitive(mender_client_deployment_data, "id"))) {
            mender_log_error("Unable to get ID from the deployment data");
            goto RELEASE;
        }
        char *id;
        if (NULL == (id = cJSON_GetStringValue(json_id))) {
            mender_log_error("Unable to get ID from the deployment data");
            goto RELEASE;
        }
        cJSON *json_artifact_name = NULL;
        if (NULL == (json_artifact_name = cJSON_GetObjectItemCaseSensitive(mender_client_deployment_data, "artifact_name"))) {
            mender_log_error("Unable to get artifact name from the deployment data");
            goto RELEASE;
        }
        char *artifact_name;
        if (NULL == (artifact_name = cJSON_GetStringValue(json_artifact_name))) {
            mender_log_error("Unable to get artifact name from the deployment data");
            goto RELEASE;
        }
        cJSON *json_types = NULL;
        if (NULL == (json_types = cJSON_GetObjectItemCaseSensitive(mender_client_deployment_data, "types"))) {
            mender_log_error("Unable to get types from the deployment data");
            goto RELEASE;
        }
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
        cJSON *provides = NULL;
        if (NULL == (provides = cJSON_GetObjectItemCaseSensitive(mender_client_deployment_data, "provides"))) {
            mender_log_error("Unable to get new_provides from the deployment data");
            goto RELEASE;
        }
        if (MENDER_OK != mender_utils_string_to_key_value_list(provides->valuestring, &new_provides)) {
            mender_log_error("Unable to parse provides from the deployment data");
            goto RELEASE;
        }
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

        /* Check if artifact running is the pending one */
        bool   success   = true;
        cJSON *json_type = NULL;
        cJSON_ArrayForEach(json_type, json_types) {
            if (NULL != mender_client_artifact_types_list) {
                for (size_t artifact_type_index = 0; artifact_type_index < mender_client_artifact_types_count; artifact_type_index++) {
                    if (StringEqual(mender_client_artifact_types_list[artifact_type_index]->type, cJSON_GetStringValue(json_type))) {
                        if (NULL != mender_client_artifact_types_list[artifact_type_index]->artifact_name) {
                            if (!StringEqual(mender_client_artifact_types_list[artifact_type_index]->artifact_name, artifact_name)) {
                                /* Deployment status failure */
                                success = false;
                            }
                        }
                    }
                }
            }
        }

        /* Publish deployment status */
        if (true == success) {

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
            /* Replace the stored provides with the new provides */
            if (MENDER_OK != mender_storage_set_provides(new_provides)) {
                mender_log_error("Unable to set provides");
                mender_client_publish_deployment_status(id, MENDER_DEPLOYMENT_STATUS_FAILURE);
                goto RELEASE;
            }
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
            mender_client_publish_deployment_status(id, MENDER_DEPLOYMENT_STATUS_SUCCESS);

        } else {
            mender_client_publish_deployment_status(id, MENDER_DEPLOYMENT_STATUS_FAILURE);
        }

        /* Delete pending deployment */
        mender_storage_delete_deployment_data();
    }

RELEASE:

    /* Release memory */
    if (NULL != mender_client_deployment_data) {
        cJSON_Delete(mender_client_deployment_data);
        mender_client_deployment_data = NULL;
    }

    /* Activate add-ons */
    if (NULL != mender_client_addons_list) {
        for (size_t index = 0; index < mender_client_addons_count; index++) {
            if (NULL != mender_client_addons_list[index]->activate) {
                mender_client_addons_list[index]->activate();
            }
        }
    }

    return MENDER_DONE;

REBOOT:

    /* Invoke restart callback, application is responsible to shutdown properly and restart the system */
    if (NULL != mender_client_callbacks.restart) {
        mender_client_callbacks.restart();
    }

    return ret;
}

static mender_err_t
deployment_destroy(mender_api_deployment_data_t *deployment) {
    if (NULL != deployment) {
        free(deployment->id);
        free(deployment->artifact_name);
        free(deployment->uri);
        for (size_t i = 0; i < deployment->device_types_compatible_size; ++i) {
            free(deployment->device_types_compatible[i]);
        }
        free(deployment->device_types_compatible);
        free(deployment);
    }
    return MENDER_OK;
}

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
static mender_err_t
mender_compare_device_types(const char  *device_type_artifact,
                            const char  *device_type_device,
                            const char **device_type_deployment,
                            const size_t device_type_deployment_size) {

    assert(NULL != device_type_artifact);
    assert(NULL != device_type_deployment);
    assert(NULL != device_type_device);
    assert(0 < device_type_deployment_size);

    if (!StringEqual(device_type_artifact, device_type_device)) {
        mender_log_error("Device type from artifact '%s' is not compatible with device '%s'", device_type_artifact, device_type_device);
        return MENDER_FAIL;
    }

    /* Return MENDER_OK if one of the devices in the deployment are compatible with the device */
    for (size_t i = 0; i < device_type_deployment_size; i++) {
        if (StringEqual(device_type_deployment[i], device_type_device)) {
            return MENDER_OK;
        }
    }
    mender_log_error("None of the device types from the deployment are compatible with device '%s'", device_type_device);
    return MENDER_FAIL;
}

#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
static mender_err_t
mender_filter_provides(mender_artifact_ctx_t *mender_artifact_ctx, mender_key_value_list_t **new_provides, mender_key_value_list_t **stored_provides) {

    mender_err_t ret = MENDER_FAIL;
    /* Clears provides */
    bool matches;
    for (size_t i = 0; i < mender_artifact_ctx->payloads.size; i++) {
        for (size_t j = 0; j < mender_artifact_ctx->payloads.values[i].clears_provides_size; j++) {
            const char *to_clear = mender_artifact_ctx->payloads.values[i].clears_provides[j];
            for (mender_key_value_list_t *item = *stored_provides; NULL != item; item = item->next) {
                if (MENDER_OK != mender_utils_compare_wildcard(item->key, to_clear, &matches)) {
                    mender_log_error("Unable to compare wildcard %s with key %s", to_clear, item->key);
                    goto END;
                }
                if (matches && MENDER_OK != mender_utils_key_value_list_delete_node(stored_provides, item->key)) {
                    mender_log_error("Unable to delete node containing key %s", item->key);
                    goto END;
                }
            }
        }
    }

    /* Combine the stored provides with the new ones */
    if (MENDER_OK != mender_utils_key_value_list_append_unique(new_provides, stored_provides)) {
        mender_log_error("Unable to merge provides");
        goto END;
    }

    ret = MENDER_OK;

END:

    mender_utils_free_linked_list(*stored_provides);
    return ret;
}

static mender_err_t
mender_prepare_new_provides(mender_artifact_ctx_t *mender_artifact_ctx, char **new_provides) {

    assert(NULL != mender_artifact_ctx);

    /* Load the currently stored provides */
    mender_key_value_list_t *stored_provides = NULL;
    if (MENDER_FAIL == mender_storage_get_provides(&stored_provides)) {
        mender_log_error("Unable to get provides");
        return MENDER_FAIL;
    }

    /* Combine the provides from the header-info and from the payloads */
    mender_key_value_list_t *provides = mender_artifact_ctx->artifact_info.provides;
    for (size_t i = 0; i < mender_artifact_ctx->payloads.size; i++) {
        if (MENDER_OK != mender_utils_append_list(&provides, &mender_artifact_ctx->payloads.values[i].provides)) {
            mender_log_error("Unable to merge provides");
            mender_utils_free_linked_list(stored_provides);
            return MENDER_FAIL;
        }
    }

    /* Filter provides */
    if (MENDER_OK != mender_filter_provides(mender_artifact_ctx, &provides, &stored_provides)) {
        return MENDER_FAIL;
    }

    if (MENDER_OK != mender_utils_key_value_list_to_string(provides, new_provides)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
mender_check_device_compatibility(mender_artifact_ctx_t *mender_artifact_ctx) {

    /* We need to load the stored provides */
    mender_key_value_list_t *stored_provides = NULL;
    if (MENDER_FAIL == mender_storage_get_provides(&stored_provides)) {
        return MENDER_FAIL;
    }

    mender_err_t ret = MENDER_FAIL;

    /* Get depends */
    mender_key_value_list_t *depends = NULL;
    for (size_t i = 0; i < mender_artifact_ctx->payloads.size; i++) {
        if (MENDER_OK != mender_utils_append_list(&depends, &mender_artifact_ctx->payloads.values[i].depends)) {
            mender_log_error("Unable to append depends");
            goto END;
        }
    }

    /* Match depends from artifact with device's provides */
    for (mender_key_value_list_t *depends_item = depends; NULL != depends_item; depends_item = depends_item->next) {
        bool matches = false;
        for (mender_key_value_list_t *provides_item = stored_provides; NULL != provides_item; provides_item = provides_item->next) {
            /* Match key-value from depends with provides */
            if (StringEqual(depends_item->key, provides_item->key)) {
                if (!StringEqual(depends_item->value, provides_item->value)) {
                    mender_log_error("Value mismatch for key '%s': depends-value '%s' does not match provides-value '%s'",
                                     depends_item->key,
                                     depends_item->value,
                                     provides_item->value);
                    break;
                }
                matches = true;
                break;
            }
        }
        if (!matches) {
            mender_log_error("Missing '%s:%s' in provides, required by artifact depends", depends_item->key, depends_item->value);
            goto END;
        }
    }

    ret = MENDER_OK;

END:
    mender_utils_free_linked_list(stored_provides);
    return ret;
}
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

static mender_err_t
mender_client_update_work_function(void) {

    mender_err_t ret;

    /* Ensure that the context is initialized to NULL before goto END */
    mender_artifact_ctx_t *mender_artifact_ctx = NULL;

    /* Check for deployment */
    mender_api_deployment_data_t *deployment              = calloc(1, sizeof(mender_api_deployment_data_t));
    char                         *storage_deployment_data = NULL;

    mender_log_info("Checking for deployment...");
    if (MENDER_OK != (ret = mender_api_check_for_deployment(deployment))) {
        mender_log_error("Unable to check for deployment");
        goto END;
    }

    /* Check if deployment is available */
    if ((NULL == deployment->id) || (NULL == deployment->artifact_name) || (NULL == deployment->uri) || (NULL == deployment->device_types_compatible)) {
        mender_log_info("No deployment available");
        goto END;
    }

    /* Reset flags */
    mender_client_deployment_needs_set_pending_image = false;
    mender_client_deployment_needs_restart           = false;

    /* Create deployment data */
    if (NULL == (mender_client_deployment_data = cJSON_CreateObject())) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    cJSON_AddStringToObject(mender_client_deployment_data, "id", deployment->id);
    cJSON_AddStringToObject(mender_client_deployment_data, "artifact_name", deployment->artifact_name);
    cJSON_AddArrayToObject(mender_client_deployment_data, "types");

    /* Download deployment artifact */
    mender_log_info(
        "Downloading deployment artifact with id '%s', artifact name '%s' and uri '%s'", deployment->id, deployment->artifact_name, deployment->uri);
    mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);
    if (MENDER_OK != (ret = mender_api_download_artifact(deployment->uri, mender_client_download_artifact_callback))) {
        mender_log_error("Unable to download artifact");
        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
        if (true == mender_client_deployment_needs_set_pending_image) {
            mender_flash_abort_deployment(mender_client_flash_handle);
        }
        goto END;
    }

    mender_log_info("Will be getting context");

    /* Artifact context */
    if (MENDER_OK != (ret = mender_artifact_get_ctx(&mender_artifact_ctx))) {
        mender_log_error("Unable to get artifact context");
        if (mender_client_deployment_needs_set_pending_image) {
            mender_flash_abort_deployment(mender_client_flash_handle);
        }
        goto END;
    }

    mender_log_info("Getting device type");

    /* Retrieve device type from artifact */
    const char *device_type_artifact = NULL;
    if (MENDER_OK != (ret = mender_artifact_get_device_type(mender_artifact_ctx, &device_type_artifact))) {
        mender_log_error("Unable to get device type from artifact");
        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
        if (mender_client_deployment_needs_set_pending_image) {
            mender_flash_abort_deployment(mender_client_flash_handle);
        }
        goto END;
    }

    mender_log_info("Checking device type compatibility");

    /* Match device type  */
    if (MENDER_OK
        != mender_compare_device_types(device_type_artifact,
                                       mender_client_config.device_type,
                                       (const char **)deployment->device_types_compatible,
                                       deployment->device_types_compatible_size)) {
        /* Erorrs are logged by the function */
        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
        if (mender_client_deployment_needs_set_pending_image) {
            mender_flash_abort_deployment(mender_client_flash_handle);
        }
        goto END;
    }

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
    /* Compare Artifact's depends with the stored provides */
    if (MENDER_OK != mender_check_device_compatibility(mender_artifact_ctx)) {
        /* Errors logged by function */
        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
        if (mender_client_deployment_needs_set_pending_image) {
            mender_flash_abort_deployment(mender_client_flash_handle);
        }
        goto END;
    }

    /* Add the new provides to the deployment data (we need the artifact context)*/
    char *new_provides = NULL;
    if (MENDER_OK != mender_prepare_new_provides(mender_artifact_ctx, &new_provides)) {
        mender_log_error("Unable to prepare new provides");
        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
        if (mender_client_deployment_needs_set_pending_image) {
            mender_flash_abort_deployment(mender_client_flash_handle);
        }
        goto END;
    }
    cJSON_AddStringToObject(mender_client_deployment_data, "provides", new_provides);
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */

    /* Set boot partition */
    mender_log_info("Download done, installing artifact");
    mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_INSTALLING);
    if (true == mender_client_deployment_needs_set_pending_image) {
        if (MENDER_OK != (ret = mender_flash_set_pending_image(mender_client_flash_handle))) {
            mender_log_error("Unable to set boot partition");
            mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
            goto END;
        }
    }

    /* Check if the system must restart following downloading the deployment */
    if (true == mender_client_deployment_needs_restart) {
        mender_log_info("Needs restart");
        /* Save deployment data to publish deployment status after rebooting */
        if (NULL == (storage_deployment_data = cJSON_PrintUnformatted(mender_client_deployment_data))) {
            mender_log_error("Unable to save deployment data");
            mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
            ret = MENDER_FAIL;
            goto END;
        }
        if (MENDER_OK != (ret = mender_storage_set_deployment_data(storage_deployment_data))) {
            mender_log_error("Unable to save deployment data");
            mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
            goto END;
        }
        mender_log_info("Rebooting system");
        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_REBOOTING);
    } else {
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
        /* Write new_provides directly to provides store */
        mender_key_value_list_t *provides = NULL;
        /* Convert 'new_provides' to key value list */
        if (MENDER_OK != mender_utils_string_to_key_value_list(new_provides, &provides)) {
            mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
            goto END;
        }
        /* Store provides */
        if (MENDER_OK != mender_storage_set_provides(provides)) {
            mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
            goto END;
        }
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_SUCCESS);
        goto END;
    }

    /* Release memory */
    mender_log_info("Destroying deployment");
    deployment_destroy(deployment);
    if (NULL != storage_deployment_data) {
        free(storage_deployment_data);
    }
    if (NULL != mender_client_deployment_data) {
        cJSON_Delete(mender_client_deployment_data);
        mender_client_deployment_data = NULL;
    }
    mender_log_info("Releasing artifact context");
    // TODO We should check the context releasing (deinitialization; cleanup) before the restart.
    // mender_artifact_release_ctx(mender_artifact_ctx);

    /* Check if the system must restart following downloading the deployment */
    if (true == mender_client_deployment_needs_restart) {
        mender_log_info("All righty; get it done baby!");
        /* Invoke restart callback, application is responsible to shutdown properly and restart the system */
        if (NULL != mender_client_callbacks.restart) {
            mender_client_callbacks.restart();
        }
    }

    return MENDER_DONE;

END:

    /* Release memory */
    deployment_destroy(deployment);
    if (NULL != storage_deployment_data) {
        free(storage_deployment_data);
    }
    if (NULL != mender_client_deployment_data) {
        cJSON_Delete(mender_client_deployment_data);
        mender_client_deployment_data = NULL;
    }
    mender_artifact_release_ctx(mender_artifact_ctx);

    return ret;
}

static mender_err_t
mender_client_download_artifact_callback(char *type, cJSON *meta_data, char *filename, size_t size, void *data, size_t index, size_t length) {

    assert(NULL != type);
    cJSON       *json_types;
    mender_err_t ret = MENDER_FAIL;

    mender_log_debug("Downloading artifact of type '%s' [%d/%zu]", type, index, size);

    /* Treatment depending of the type */
    if (NULL != mender_client_artifact_types_list) {

        for (size_t artifact_type_index = 0; artifact_type_index < mender_client_artifact_types_count; artifact_type_index++) {

            /* Check artifact type */
            if (StringEqual(type, mender_client_artifact_types_list[artifact_type_index]->type)) {

                // mender_log_info("Found correct type callback");

                /* Retrieve ID and artifact name */
                cJSON *json_id = NULL;
                if (NULL == (json_id = cJSON_GetObjectItemCaseSensitive(mender_client_deployment_data, "id"))) {
                    mender_log_error("Unable to get ID from the deployment data");
                    goto END;
                }
                char *id;
                if (NULL == (id = cJSON_GetStringValue(json_id))) {
                    mender_log_error("Unable to get ID from the deployment data");
                    goto END;
                }
                cJSON *json_artifact_name = NULL;
                if (NULL == (json_artifact_name = cJSON_GetObjectItemCaseSensitive(mender_client_deployment_data, "artifact_name"))) {
                    mender_log_error("Unable to get artifact name from the deployment data");
                    goto END;
                }
                char *artifact_name;
                if (NULL == (artifact_name = cJSON_GetStringValue(json_artifact_name))) {
                    mender_log_error("Unable to get artifact name from the deployment data");
                    goto END;
                }

                /* Invoke artifact type callback */
                if (MENDER_OK
                    != (ret = mender_client_artifact_types_list[artifact_type_index]->callback(
                            id, artifact_name, type, meta_data, filename, size, data, index, length))) {
                    mender_log_error("An error occurred while processing data of the artifact '%s'", type);
                    goto END;
                }

                /* Treatments related to the artifact type (once) */
                if (0 == index) {

                    // mender_log_info("Are we index 0? This logic drives me mad!");

                    /* Add type to the deployment data */
                    if (NULL == (json_types = cJSON_GetObjectItemCaseSensitive(mender_client_deployment_data, "types"))) {
                        mender_log_error("Unable to add type to the deployment data");
                        ret = MENDER_FAIL;
                        goto END;
                    }
                    bool   found     = false;
                    cJSON *json_type = NULL;
                    cJSON_ArrayForEach(json_type, json_types) {
                        if (StringEqual(type, cJSON_GetStringValue(json_type))) {
                            found = true;
                        }
                    }
                    if (false == found) {
                        cJSON_AddItemToArray(json_types, cJSON_CreateString(type));
                    }

                    /* Set flags */
                    if (true == mender_client_artifact_types_list[artifact_type_index]->needs_restart) {
                        mender_log_info("We are going to restart after the update");
                        mender_client_deployment_needs_restart = true;
                    }
                }

                ret = MENDER_OK;
                goto END;
            }
        }
    }

    /* Content is not supported by the mender-mcu-client */
    mender_log_error("Unable to handle artifact type '%s'", type);
    ret = MENDER_FAIL;

END:

    return ret;
}

static mender_err_t
mender_client_download_artifact_flash_callback(
    char *id, char *artifact_name, char *type, cJSON *meta_data, char *filename, size_t size, void *data, size_t index, size_t length) {

    (void)id;
    (void)artifact_name;
    (void)type;
    (void)meta_data;
    mender_err_t ret = MENDER_OK;

    /* Check if the filename is provided */
    if (NULL != filename) {
        mender_log_info("Writing to flash: %s", filename);

        // TODO remove (here and below) in favor of debug logging once the logging is under control
        printf(".");

        /* Check if the flash handle must be opened */
        if (0 == index) {

            /* Open the flash handle */
            if (MENDER_OK != (ret = mender_flash_open(filename, size, &mender_client_flash_handle))) {
                mender_log_error("Unable to open flash handle");
                goto END;
            }
        }

        /* Write data */
        if (MENDER_OK != (ret = mender_flash_write(mender_client_flash_handle, data, index, length))) {
            mender_log_error("Unable to write data to flash");
            goto END;
        }

        /* Check if the flash handle must be closed */
        if (index + length >= size) {

            printf("DONE\n");
            /* Close the flash handle */
            if (MENDER_OK != (ret = mender_flash_close(mender_client_flash_handle))) {
                mender_log_error("Unable to close flash handle");
                goto END;
            }
        }
    }

    /* Set flags */
    mender_client_deployment_needs_set_pending_image = true;

END:

    return ret;
}

static mender_err_t
mender_client_publish_deployment_status(char *id, mender_deployment_status_t deployment_status) {

    assert(NULL != id);
    mender_err_t ret;

    /* Publish status to the mender server */
    ret = mender_api_publish_deployment_status(id, deployment_status);

    /* Invoke deployment status callback if defined */
    if (NULL != mender_client_callbacks.deployment_status) {
        mender_client_callbacks.deployment_status(deployment_status, mender_utils_deployment_status_to_string(deployment_status));
    }

    return ret;
}
