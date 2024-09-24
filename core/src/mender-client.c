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
#include "mender-log.h"
#include "mender-scheduler.h"
#include "mender-storage.h"
#include "mender-tls.h"
#include "mender-update-module.h"
#include "mender-utils.h"
#include "mender-deployment-data.h"

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
#include "mender-inventory.h"
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

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
mender_client_callbacks_t mender_client_callbacks = { 0 };

mender_client_state_t mender_client_state = MENDER_CLIENT_STATE_INITIALIZATION;

struct mender_update_state_transition_s {
    mender_update_state_t success;
    mender_update_state_t failure;
};

/**
 * @brief Mender Update (module) state transitions
 */
static const struct mender_update_state_transition_s update_state_transitions[N_MENDER_UPDATE_STATES] = {
    /* MENDER_UPDATE_STATE_DOWNLOAD               */ { MENDER_UPDATE_STATE_INSTALL, MENDER_UPDATE_STATE_CLEANUP },
    /* MENDER_UPDATE_STATE_INSTALL                */ { MENDER_UPDATE_STATE_REBOOT, MENDER_UPDATE_STATE_FAILURE },
    /* MENDER_UPDATE_STATE_REBOOT                 */ { MENDER_UPDATE_STATE_VERIFY_REBOOT, MENDER_UPDATE_STATE_ROLLBACK },
    /* MENDER_UPDATE_STATE_VERIFY_REBOOT          */ { MENDER_UPDATE_STATE_COMMIT, MENDER_UPDATE_STATE_ROLLBACK },
    /* MENDER_UPDATE_STATE_COMMIT                 */ { MENDER_UPDATE_STATE_CLEANUP, MENDER_UPDATE_STATE_ROLLBACK },
    /* MENDER_UPDATE_STATE_CLEANUP                */ { MENDER_UPDATE_STATE_END, MENDER_UPDATE_STATE_END },
    /* MENDER_UPDATE_STATE_ROLLBACK               */ { MENDER_UPDATE_STATE_ROLLBACK_REBOOT, MENDER_UPDATE_STATE_FAILURE },
    /* MENDER_UPDATE_STATE_ROLLBACK_REBOOT        */ { MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT, MENDER_UPDATE_STATE_FAILURE },
    /* MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT */ { MENDER_UPDATE_STATE_FAILURE, MENDER_UPDATE_STATE_FAILURE },
    /* MENDER_UPDATE_STATE_FAILURE                */ { MENDER_UPDATE_STATE_CLEANUP, MENDER_UPDATE_STATE_CLEANUP },
};

#if CONFIG_MENDER_LOG_LEVEL >= MENDER_LOG_LEVEL_DBG
/* This is only needed for debug messages. */
static const char *update_state_str[N_MENDER_UPDATE_STATES + 1] = {
    "MENDER_UPDATE_STATE_DOWNLOAD",
    "MENDER_UPDATE_STATE_INSTALL",
    "MENDER_UPDATE_STATE_REBOOT",
    "MENDER_UPDATE_STATE_VERIFY_REBOOT",
    "MENDER_UPDATE_STATE_COMMIT",
    "MENDER_UPDATE_STATE_CLEANUP",
    "MENDER_UPDATE_STATE_ROLLBACK",
    "MENDER_UPDATE_STATE_ROLLBACK_REBOOT",
    "MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT",
    "MENDER_UPDATE_STATE_FAILURE",
    "MENDER_UPDATE_STATE_END (this is a bug!)",
};
#endif

/**
 * @brief Flag to know if network connection was requested or not
 */
static bool mender_client_network_connected = false;

/**
 * @brief Deployment data. Used to track progress of an update, so that the
 *        operation can resume or roll back across reboots
 */
static mender_deployment_data_t *mender_client_deployment_data = NULL;

/**
 * @brief Mender client update modules list
 */
static mender_update_module_t **mender_update_modules_list  = NULL;
static size_t                   mender_update_modules_count = 0;

/**
 * @brief Update module being used by the current deployment
 */
static mender_update_module_t *mender_update_module = NULL;

/**
 * @brief Mender client work handle
 */
static void *mender_client_work_handle = NULL;

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
 * @brief Function to request network access
 * @return MENDER_OK if network is connected following the request, error code otherwise
 */
static mender_err_t mender_client_network_connect(void);

/**
 * @brief Function to release network access
 * @return MENDER_OK if network is released following the request, error code otherwise
 */
static mender_err_t mender_client_network_release(void);

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
static mender_err_t mender_prepare_new_provides(mender_artifact_ctx_t *mender_artifact_ctx, char **provides, const char **artifact_name);

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
 * @brief Publish deployment status of the device to the mender-server and invoke deployment status callback
 * @param id ID of the deployment
 * @param deployment_status Deployment status
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_client_publish_deployment_status(const char *id, mender_deployment_status_t deployment_status);

char *
mender_client_version(void) {

    /* Return version as string */
    return MENDER_CLIENT_VERSION;
}

mender_err_t
mender_client_init(mender_client_config_t *config, mender_client_callbacks_t *callbacks) {

    assert(NULL != config);
    assert(NULL != config->device_type);
    assert(NULL != callbacks);
    assert(NULL != callbacks->restart);
    mender_err_t ret;

    mender_client_config.device_type = config->device_type;

    mender_log_info("Device type: [%s]", mender_client_config.device_type);

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
    // TODO: what to do with the authentication interval?
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
        .device_type  = mender_client_config.device_type,
        .host         = mender_client_config.host,
        .tenant_token = mender_client_config.tenant_token,
    };
    if (MENDER_OK != (ret = mender_api_init(&mender_api_config))) {
        mender_log_error("Unable to initialize API");
        goto END;
    }

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
    if (MENDER_OK != (ret = mender_inventory_init(mender_client_config.inventory_update_interval))) {
        mender_log_error("Failed to initialize the inventory functionality");
        goto END;
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

END:

    return ret;
}

mender_err_t
mender_client_register_update_module(mender_update_module_t *update_module) {

    assert(NULL != update_module);

    mender_update_module_t **tmp;
    mender_err_t             ret = MENDER_OK;

    /* Add mender artifact type to the list */
    if (NULL == (tmp = (mender_update_module_t **)realloc(mender_update_modules_list, (mender_update_modules_count + 1) * sizeof(mender_update_module_t *)))) {
        mender_log_error("Unable to allocate memory for update modules list");
        ret = MENDER_FAIL;
        goto END;
    }
    mender_update_modules_list                                = tmp;
    mender_update_modules_list[mender_update_modules_count++] = update_module;
    ret                                                       = MENDER_OK;

END:

    return ret;
}

mender_err_t
mender_client_activate(void) {

    mender_err_t ret = MENDER_OK;

    mender_scheduler_alt_work_start();

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
    /* Activate inventory work */
    if (MENDER_OK != (ret = mender_inventory_activate())) {
        mender_log_error("Unable to activate the inventory functionality");
        return ret;
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

    return ret;
}

mender_err_t
mender_client_ensure_connected(void) {
    if (mender_client_network_connected) {
        return MENDER_DONE;
    }

    return mender_client_network_connect();
}

static mender_err_t
mender_client_network_connect(void) {
    if (mender_client_network_connected) {
        return MENDER_OK;
    }

    /* Request network access */
    if (NULL != mender_client_callbacks.network_connect) {
        if (MENDER_OK != mender_client_callbacks.network_connect()) {
            mender_log_error("Unable to connect network");
            return MENDER_FAIL;
        }
    }

    mender_client_network_connected = true;

    return MENDER_OK;
}

static mender_err_t
mender_client_network_release(void) {
    if (!mender_client_network_connected) {
        return MENDER_OK;
    }

    /* Release network access */
    if (NULL != mender_client_callbacks.network_release) {
        if (MENDER_OK != mender_client_callbacks.network_release()) {
            mender_log_error("Unable to release network");
            return MENDER_FAIL;
        }
    }
    mender_client_network_connected = false;

    return MENDER_OK;
}

mender_err_t
mender_client_exit(void) {

    mender_err_t ret = MENDER_OK;

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
    if (MENDER_OK != (ret = mender_inventory_exit())) {
        mender_log_error("Unable to cleanup after the inventory functionality");
        /* keep going on, we want to do as much cleanup as possible */
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

    /* Delete mender client work */
    mender_scheduler_work_delete(mender_client_work_handle);
    mender_client_work_handle = NULL;

    /* Release all modules */
    mender_api_exit();
    mender_tls_exit();
    mender_storage_exit();
    mender_log_exit();
    mender_client_network_release();

    /* Release memory */
    mender_client_config.device_type                  = NULL;
    mender_client_config.host                         = NULL;
    mender_client_config.tenant_token                 = NULL;
    mender_client_config.authentication_poll_interval = 0;
    mender_client_config.update_poll_interval         = 0;
    DESTROY_AND_NULL(mender_delete_deployment_data, mender_client_deployment_data);

    if (NULL != mender_update_modules_list) {
        for (size_t update_module_index = 0; update_module_index < mender_update_modules_count; update_module_index++) {
            free(mender_update_modules_list[update_module_index]);
        }
        FREE_AND_NULL(mender_update_modules_list);
    }
    mender_update_modules_count = 0;

    return ret;
}

static mender_err_t
mender_client_work_function(void) {
    mender_log_info("work function: %d", mender_client_state);

    switch (mender_client_state) {
        case MENDER_CLIENT_STATE_PENDING_REBOOT:
            mender_log_info("Waiting for a reboot");
            /* nothing to do */
            return MENDER_OK;
        case MENDER_CLIENT_STATE_INITIALIZATION:
            /* Perform initialization of the client */
            if (MENDER_DONE != mender_client_initialization_work_function()) {
                return MENDER_FAIL;
            }
            mender_client_state = MENDER_CLIENT_STATE_OPERATIONAL;
            /* fallthrough */
        case MENDER_CLIENT_STATE_OPERATIONAL:
            return mender_client_update_work_function();
    }

    /* This should never be reached, all the cases should be covered in the
       above switch and they all return. */
    return MENDER_FAIL;
}

static mender_err_t
mender_client_initialization_work_function(void) {

    mender_err_t ret = MENDER_DONE;

    /* Retrieve or generate authentication keys */
    if (MENDER_OK != (ret = mender_tls_init_authentication_keys(mender_client_callbacks.get_user_provided_keys, mender_client_config.recommissioning))) {
        mender_log_error("Unable to retrieve or generate authentication keys");
        goto END;
    }

    /* Retrieve deployment data if it is found (following an update) */
    if (MENDER_OK != (ret = mender_get_deployment_data(&mender_client_deployment_data))) {
        if (MENDER_NOT_FOUND != ret) {
            mender_log_error("Unable to get deployment data");
            goto REBOOT;
        }
    }

    mender_log_info("Initialization done");

    return MENDER_DONE;

END:

    return ret;

REBOOT:

    mender_log_info("Rebooting...");

    /* Delete pending deployment */
    mender_storage_delete_deployment_data();
    mender_storage_delete_update_state();

    /* Invoke restart callback, application is responsible to shutdown properly and restart the system */
    if (NULL != mender_client_callbacks.restart) {
        mender_client_callbacks.restart();
    }

    return ret;
}

static mender_err_t
mender_commit_artifact_data(void) {

    assert(NULL != mender_client_deployment_data);

    const char *artifact_name;
    if (MENDER_OK != mender_deployment_data_get_artifact_name(mender_client_deployment_data, &artifact_name)) {
        mender_log_error("Unable to get artifact name from the deployment data");
        return MENDER_FAIL;
    }

    if (MENDER_OK != mender_storage_set_artifact_name(artifact_name)) {
        mender_log_error("Unable to set artifact name");
        return MENDER_FAIL;
    }

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
    /* Get provides from the deployment data */
    const char *provides;
    if (MENDER_OK != mender_deployment_data_get_provides(mender_client_deployment_data, &provides)) {
        mender_log_error("Unable to get new_provides from the deployment data");
        return MENDER_FAIL;
    }

    /* Parse provides */
    mender_key_value_list_t *new_provides = NULL;
    if (MENDER_OK != mender_utils_string_to_key_value_list(provides, &new_provides)) {
        mender_log_error("Unable to parse provides from the deployment data");
        return MENDER_FAIL;
    }
    /* Replace the stored provides with the new provides */
    if (MENDER_OK != mender_storage_set_provides(new_provides)) {
        mender_log_error("Unable to set provides");
        mender_utils_free_linked_list(new_provides);
        return MENDER_FAIL;
    }
    mender_utils_free_linked_list(new_provides);
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

    return MENDER_OK;
}

mender_err_t
mender_client_ensure_authenticated(void) {
    if (mender_api_is_authenticated()) {
        return MENDER_DONE;
    }

    if (MENDER_FAIL == mender_client_ensure_connected()) {
        return MENDER_FAIL;
    }

    /* Perform authentication with the mender server */
    if (MENDER_OK != mender_api_perform_authentication(mender_client_callbacks.get_identity)) {
        mender_log_error("Authentication failed");
        return MENDER_FAIL;
    }

    mender_log_info("Authenticated successfully");
    return MENDER_OK;
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

    /* Make sure the artifact name is not in the new provides */
    if (MENDER_OK != mender_utils_key_value_list_delete_node(new_provides, "artifact_name")) {
        mender_log_error("Unable to delete node containing key 'artifact_name'");
        goto END;
    }

    ret = MENDER_OK;

END:

    mender_utils_free_linked_list(*stored_provides);
    return ret;
}

static mender_err_t
mender_prepare_new_provides(mender_artifact_ctx_t *mender_artifact_ctx, char **new_provides, const char **artifact_name) {

    assert(NULL != artifact_name);
    assert(NULL != mender_artifact_ctx);

    /* Load the currently stored provides */
    mender_key_value_list_t *stored_provides = NULL;
    if (MENDER_FAIL == mender_storage_get_provides(&stored_provides)) {
        mender_log_error("Unable to get provides");
        return MENDER_FAIL;
    }

    mender_key_value_list_t *provides = NULL;
    for (size_t i = 0; i < mender_artifact_ctx->payloads.size; i++) {
        if (MENDER_OK != mender_utils_append_list(&provides, &mender_artifact_ctx->payloads.values[i].provides)) {
            mender_log_error("Unable to merge provides");
            mender_utils_free_linked_list(stored_provides);
            return MENDER_FAIL;
        }
    }

    /* Get artifact name from provides */
    for (mender_key_value_list_t *item = mender_artifact_ctx->artifact_info.provides; NULL != item; item = item->next) {
        if (StringEqual("artifact_name", item->key)) {
            *artifact_name = item->value;
            break;
        }
    }

    if (NULL == *artifact_name) {
        mender_log_error("No artifact name found in provides");
        mender_utils_free_linked_list(stored_provides);
        return MENDER_FAIL;
    }

    /* Filter provides */
    /* `stored_provides` is freed in `mender_filter_provides` */
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

static inline mender_update_module_t *
mender_client_get_update_module(const char *artifact_type) {
    mender_update_module_t *ret = NULL;

    /* Treatment depending of the type */
    if (NULL != mender_update_modules_list) {
        for (size_t update_module_index = 0; (NULL == ret) && (update_module_index < mender_update_modules_count); update_module_index++) {
            /* Check artifact type */
            if (StringEqual(artifact_type, mender_update_modules_list[update_module_index]->artifact_type)) {
                ret = mender_update_modules_list[update_module_index];
            }
        }
    }

    return ret;
}

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
mender_err_t
mender_check_artifact_requirements(mender_artifact_ctx_t *mender_artifact_ctx, mender_api_deployment_data_t *deployment) {
    mender_err_t ret;

    /* Retrieve device type from artifact */
    const char *device_type_artifact = NULL;
    if (MENDER_OK != (ret = mender_artifact_get_device_type(mender_artifact_ctx, &device_type_artifact))) {
        mender_log_error("Unable to get device type from artifact");
        return ret;
    }

    mender_log_info("Checking device type compatibility");

    /* Match device type  */
    if (MENDER_OK
        != (ret = mender_compare_device_types(device_type_artifact,
                                              mender_client_config.device_type,
                                              (const char **)deployment->device_types_compatible,
                                              deployment->device_types_compatible_size))) {
        return ret;
    }

#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
    /* Compare Artifact's depends with the stored provides */
    if (MENDER_OK != (ret = mender_check_device_compatibility(mender_artifact_ctx))) {
        return ret;
    }
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */

    return MENDER_OK;
}
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

static mender_err_t
mender_client_check_deployment(mender_api_deployment_data_t **deployment_data) {
    assert(NULL != deployment_data);

    if (MENDER_FAIL == mender_client_ensure_authenticated()) {
        /* authentication errors logged already */
        mender_log_error("Cannot check for new deployment");
        return MENDER_FAIL;
    }

    if (NULL == (*deployment_data = calloc(1, sizeof(mender_api_deployment_data_t)))) {
        mender_log_error("Unable to allocate memory for deployment data");
        return MENDER_FAIL;
    }

    mender_api_deployment_data_t *deployment = *deployment_data;

    mender_err_t ret = MENDER_OK;

    mender_log_info("Checking for deployment...");
    if (MENDER_NOT_FOUND == (ret = mender_api_check_for_deployment(deployment))) {
        mender_log_info("No deployment available");
        return MENDER_DONE;
    } else if (MENDER_OK != ret) {
        mender_log_error("Unable to check for deployment");
        return MENDER_FAIL;
    }

    /* Check if deployment is valid */
    if ((NULL == deployment->id) || (NULL == deployment->artifact_name) || (NULL == deployment->uri) || (NULL == deployment->device_types_compatible)) {
        mender_log_error("Invalid deployment data");
        return MENDER_FAIL;
    }

    /* Create deployment data */
    if (NULL != mender_client_deployment_data) {
        mender_log_warning("Unexpected stale deployment data");
        mender_delete_deployment_data(mender_client_deployment_data);
    }
    if (MENDER_OK != (mender_create_deployment_data(deployment->id, deployment->artifact_name, &mender_client_deployment_data))) {
        /* Error already logged */
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

static mender_err_t
mender_client_update_work_function(void) {
    mender_err_t ret = MENDER_OK;

    /* Ensure that the context is initialized to NULL before goto END */
    mender_artifact_ctx_t *mender_artifact_ctx = NULL;

    /* Check for deployment */
    mender_api_deployment_data_t *deployment    = NULL;
    mender_update_state_t         update_state  = MENDER_UPDATE_STATE_DOWNLOAD;
    const char                   *deployment_id = NULL;

    /* reset the currently used update module */
    mender_update_module = NULL;

    if (NULL != mender_client_deployment_data) {
        mender_deployment_data_get_id(mender_client_deployment_data, &deployment_id);
    }

    {
        char                 *artifact_type;
        mender_update_state_t update_state_resume;
        if (MENDER_OK == (ret = mender_storage_get_update_state(&update_state_resume, &artifact_type))) {
            update_state = update_state_resume;
            mender_log_debug("Resuming from state %s", update_state_str[update_state]);
            mender_update_module = mender_client_get_update_module(artifact_type);
            if (NULL == mender_update_module) {
                /* The artifact_type from the saved state does not match any update module */
                mender_log_error("No update module found for artifact type '%s'", artifact_type);
                mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_FAILURE);
                mender_storage_delete_deployment_data();
                mender_storage_delete_update_state();
                free(artifact_type);
                goto END;
            }
            free(artifact_type);
        }
    }

    /* Skip the block below if we just resume from a saved state. */

/* A macro to advance to the next state -- on success we just keep going to the
 * code below the macro invocation (fallthrough to the next case), on error we
 * go to the beginning of the loop (the switch statement) again using 'continue'
 * (see below).
 *
 * mender_update_module is guaranteed be not NULL since the first
 * successful transition (from the DOWNLOAD state). */
#define NEXT_STATE                                                                               \
    if (MENDER_OK == ret) {                                                                      \
        update_state = update_state_transitions[update_state].success;                           \
        assert(NULL != mender_update_module);                                                    \
        mender_log_debug("Entering state %s", update_state_str[update_state]);                   \
        mender_storage_save_update_state(update_state, mender_update_module->artifact_type);     \
        ret = MENDER_OK;                                                                         \
    } else {                                                                                     \
        update_state = update_state_transitions[update_state].failure;                           \
        mender_log_debug("Entering state %s", update_state_str[update_state]);                   \
        if (NULL != mender_update_module) {                                                      \
            mender_storage_save_update_state(update_state, mender_update_module->artifact_type); \
        }                                                                                        \
        ret = MENDER_OK;                                                                         \
        continue;                                                                                \
    }

    while (MENDER_UPDATE_STATE_END != update_state) {
        switch (update_state) {
            case MENDER_UPDATE_STATE_DOWNLOAD:

                /* Check for deployment */
                if (MENDER_OK != (ret = mender_client_check_deployment(&deployment))) {
                    /* No deployment available */
                    goto END;
                }

                mender_log_info("Downloading deployment artifact with id '%s', artifact name '%s' and uri '%s'",
                                deployment->id,
                                deployment->artifact_name,
                                deployment->uri);
                mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

                /* Set deployment_id */
                deployment_id = deployment->id;

                /* mender_client_download_artifact_callback() sets
                 * mender_update_module if there is enough data to get
                 * artifact type and there is a matching update module. */
                /* TODO: the actual update module's download callback is called
                 *       via 9 levels of indirection from here, refactoring
                 *       needed */
                if (MENDER_OK == (ret = mender_api_download_artifact(deployment->uri, mender_client_download_artifact_callback))) {
                    assert(NULL != mender_update_module);

                    /* Get artifact context if artifact download succeeded */
                    if ((NULL != mender_update_module) && (MENDER_OK == (ret = mender_artifact_get_ctx(&mender_artifact_ctx)))) {
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
                        if (MENDER_OK == (ret = mender_check_artifact_requirements(mender_artifact_ctx, deployment))) {
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
                            /* Add the new provides to the deployment data (we need the artifact context) */
                            char       *new_provides  = NULL;
                            const char *artifact_name = NULL;
                            if (MENDER_OK == (ret = mender_prepare_new_provides(mender_artifact_ctx, &new_provides, &artifact_name))) {
                                if (MENDER_OK != (ret = mender_deployment_data_set_provides(mender_client_deployment_data, new_provides))) {
                                    mender_log_error("Failed to set deployment data provides");
                                }
                                /* Replace artifact_name with the one from provides */
                                else if (MENDER_OK != (ret = mender_deployment_data_set_artifact_name(mender_client_deployment_data, artifact_name))) {
                                    mender_log_error("Failed to set deployment data artifact name");
                                }
                                free(new_provides);
                            } else {
                                mender_log_error("Unable to prepare new provides");
                            }
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
                        }
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
                    } else {
                        mender_log_error("Unable to get artifact type and context");
                    }
                } else {
                    mender_log_error("Unable to download artifact");
                    if (NULL == mender_update_module) {
                        /* Error logged in mender_client_download_artifact_callback() */
                        mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_FAILURE);
                        goto END;
                    }
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_INSTALL:
                mender_log_info("Download done, installing artifact");
                mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_INSTALLING);
                if (NULL != mender_update_module->callbacks[update_state]) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                if ((MENDER_OK == ret) && !mender_update_module->requires_reboot) {
                    /* skip reboot */
                    update_state = MENDER_UPDATE_STATE_COMMIT;
                    mender_storage_save_update_state(update_state, mender_update_module->artifact_type);
                    continue;
                }
                /* else continue to the next successful/failure state */
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_REBOOT:
                assert(mender_update_module->requires_reboot);
                mender_log_info("Artifact installation done, rebooting");
                mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_REBOOTING);

                /* Save deployment data to publish deployment status after rebooting */
                if (MENDER_OK != (ret = mender_set_deployment_data(mender_client_deployment_data))) {
                    mender_log_error("Unable to save deployment data");
                }
                if ((MENDER_OK == ret) && (NULL != mender_update_module->callbacks[update_state])) {
                    /* Save the next state before running the reboot callback --
                     * if there is an interrupt (power, crash,...) right after,
                     * it will reboot anyway so after the new boot, reboot
                     * verification should happen anyway, the callback in that
                     * state should be able to see if things went well or
                     * wrong. */
                    mender_storage_save_update_state(MENDER_UPDATE_STATE_VERIFY_REBOOT, mender_update_module->artifact_type);
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);

                    if (MENDER_OK == ret) {
                        /* now we need to get outside of the loop so that a
                         * potential asynchronous reboot has a chance to kick in
                         * after a proper cleanup below */
                        mender_client_state = MENDER_CLIENT_STATE_PENDING_REBOOT;
                        ret                 = MENDER_DONE;
                        goto END;
                    }
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_VERIFY_REBOOT:
                assert(mender_update_module->requires_reboot);
                if (NULL != mender_update_module->callbacks[update_state]) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_COMMIT:
                /* Check for pending deployment */
                if (NULL == mender_client_deployment_data) {
                    mender_log_error("No deployment data found on commit");
                    mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_FAILURE);
                    goto END;
                }
                if (MENDER_OK != mender_commit_artifact_data()) {
                    mender_log_error("Unable to commit artifact data");
                    ret = MENDER_FAIL;
                }
                if ((MENDER_OK == ret) && (NULL != mender_update_module->callbacks[update_state])) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                if (MENDER_OK == ret) {
                    mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_SUCCESS);
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_CLEANUP:
                if (NULL != mender_update_module->callbacks[update_state]) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                NEXT_STATE;
                mender_storage_delete_deployment_data();
                mender_storage_delete_update_state();
                break; /* below is the failure path */

            case MENDER_UPDATE_STATE_ROLLBACK:
                if (!mender_update_module->supports_rollback) {
                    mender_log_warning("Rollback not supported for artifacts of type '%s'", mender_update_module->artifact_type);
                    ret = MENDER_FAIL;
                } else if (NULL != mender_update_module->callbacks[update_state]) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_ROLLBACK_REBOOT:
                /* Save the next state before running the reboot callback (see
                 * STATE_REBOOT for details). */
                mender_storage_save_update_state(MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT, mender_update_module->artifact_type);
                ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);

                if (MENDER_OK == ret) {
                    /* now we need to get outside of the loop so that a
                     * potential asynchronous reboot has a chance to kick in
                     * after a proper cleanup below */
                    mender_client_state = MENDER_CLIENT_STATE_PENDING_REBOOT;
                    ret                 = MENDER_DONE;
                    goto END;
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT:
                if (NULL != mender_update_module->callbacks[update_state]) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_FAILURE:
                mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_FAILURE);
                if (NULL != mender_update_module->callbacks[update_state]) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                NEXT_STATE;
                break; /* end of the failure path */

            case MENDER_UPDATE_STATE_END:
                /* This is only here to cover all possible values of the
                 * update_state enum, there is nothing to do here, the while
                 * loop shall stop when we get here. */
                break;
        }
    }
#undef NEXT_STATE /* should not be used anywhere else */

    ret = MENDER_DONE;

END:
    /* Release memory */
    deployment_destroy(deployment);
    DESTROY_AND_NULL(mender_delete_deployment_data, mender_client_deployment_data);
    mender_artifact_release_ctx(mender_artifact_ctx);

    return ret;
}

static mender_err_t
mender_client_download_artifact_callback(char *type, cJSON *meta_data, char *filename, size_t size, void *data, size_t index, size_t length) {

    assert(NULL != type);
    mender_err_t ret = MENDER_FAIL;

#if CONFIG_MENDER_LOG_LEVEL >= MENDER_LOG_LEVEL_INF
    static size_t download_progress = 0;
    /* New update */
    if (0 == index) {
        download_progress = 0;
    }
    /* Update every 10% */
    if (((index * 10) / size) > download_progress) {
        download_progress = (index * 10) / size;
        mender_log_info("Downloading '%s' %zu0%%... [%zu/%zu]", type, download_progress, index, size);
    }
#endif

    mender_update_module = mender_client_get_update_module(type);
    if (NULL == mender_update_module) {
        /* Content is not supported by the mender-mcu-client */
        mender_log_error("Unable to handle artifact type '%s'", type);
        goto END;
    }

    /* Retrieve ID and artifact name */
    const char *id;
    if (MENDER_OK != mender_deployment_data_get_id(mender_client_deployment_data, &id)) {
        mender_log_error("Unable to get ID from the deployment data");
        goto END;
    }
    const char *artifact_name;
    if (MENDER_OK != mender_deployment_data_get_artifact_name(mender_client_deployment_data, &artifact_name)) {
        mender_log_error("Unable to get artifact name from the deployment data");
        goto END;
    }

    /* Invoke update module download callback */
    struct mender_update_download_state_data_s download_state_data = { id, artifact_name, type, meta_data, filename, size, data, index, length, false };
    mender_update_state_data_t                 state_data          = { .download_state_data = &download_state_data };
    if (MENDER_OK != (ret = mender_update_module->callbacks[MENDER_UPDATE_STATE_DOWNLOAD](MENDER_UPDATE_STATE_DOWNLOAD, state_data))) {
        mender_log_error("An error occurred while processing data of the artifact '%s' of type '%s'", artifact_name, type);
        goto END;
    }

    /* Treatments related to the artifact type (once) */
    if (0 == index) {
        /* Add type to the deployment data */
        if (MENDER_OK != (ret = mender_deployment_data_add_payload_type(mender_client_deployment_data, type))) {
            /* Error already logged */
            goto END;
        }
    }

    ret = MENDER_OK;

END:
    return ret;
}

static mender_err_t
mender_client_publish_deployment_status(const char *id, mender_deployment_status_t deployment_status) {
    if (MENDER_FAIL == mender_client_ensure_authenticated()) {
        /* authentication errors logged already */
        mender_log_error("Cannot publish deployment status");
        return MENDER_FAIL;
    }

    mender_err_t ret;

    if (NULL == id) {
        mender_log_error("Cannot publish deployment status: unknown status");
        return MENDER_FAIL;
    }

    /* Publish status to the mender server */
    ret = mender_api_publish_deployment_status(id, deployment_status);

    /* Invoke deployment status callback if defined */
    if (NULL != mender_client_callbacks.deployment_status) {
        mender_client_callbacks.deployment_status(deployment_status, mender_utils_deployment_status_to_string(deployment_status));
    }

    return ret;
}
