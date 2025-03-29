/**
 * @file      client.c
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

#include "alloc.h"
#include "api.h"
#include "client.h"
#include "artifact.h"
#include "artifact-download.h"
#include "log.h"
#include "os.h"
#include "storage.h"
#include "tls.h"
#include "update-module.h"
#include "utils.h"
#include "deployment-data.h"
#include "error-counters.h"

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
#include "inventory.h"
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
 * @brief Default device type
 */
#ifndef CONFIG_MENDER_DEVICE_TYPE
#define CONFIG_MENDER_DEVICE_TYPE NULL
#endif /* CONFIG_MENDER_DEVICE_TYPE */

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
    /* MENDER_UPDATE_STATE_ROLLBACK_REBOOT        */ { MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT, MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT },
    /* MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT */ { MENDER_UPDATE_STATE_FAILURE, MENDER_UPDATE_STATE_ROLLBACK_REBOOT },
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
    "MENDER_UPDATE_STATE_END",
};
static const char *client_state_str[N_MENDER_CLIENT_STATES + 1] = {
    "MENDER_CLIENT_STATE_INITIALIZATION",
    "MENDER_CLIENT_STATE_OPERATIONAL",
    "MENDER_CLIENT_STATE_PENDING_REBOOT",
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
 * @brief Update module being used by the current deployment
 */
static mender_update_module_t *mender_update_module = NULL;

/**
 * @brief The main Mender work item
 */
static mender_work_t *mender_client_work = NULL;

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
 * @brief Publish deployment status of the device to the mender-server and invoke deployment status callback
 * @param id ID of the deployment
 * @param deployment_status Deployment status
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_client_publish_deployment_status(const char *id, mender_deployment_status_t deployment_status);

/**
 * @brief Set state in deployment data and store it in permanent storage
 * @param state State to set and store
 * @return MENDER_OK in case of success, error code otherwise
 */
static mender_err_t set_and_store_state(const mender_update_state_t state);

const char *
mender_client_version(void) {

    /* Return version as string */
    return MENDER_CLIENT_VERSION;
}

mender_err_t
mender_client_init(mender_client_config_t *config, mender_client_callbacks_t *callbacks) {
    assert(NULL != config);
    assert(NULL != callbacks);
    assert(NULL != callbacks->restart);

    /* Either all allocation functions set or none. */
    assert(
        ((NULL == config->allocation_funcs.malloc_func) && (NULL == config->allocation_funcs.realloc_func) && (NULL == config->allocation_funcs.free_func))
        || ((NULL != config->allocation_funcs.malloc_func) && (NULL != config->allocation_funcs.realloc_func) && (NULL != config->allocation_funcs.free_func)));

    mender_err_t ret;

    if (NULL != config->allocation_funcs.malloc_func) {
        mender_set_allocation_funcs(config->allocation_funcs.malloc_func, config->allocation_funcs.realloc_func, config->allocation_funcs.free_func);
    } else {
        mender_set_platform_allocation_funcs();
    }

    {
        cJSON_Hooks cjson_alloc_funcs = { mender_malloc, mender_free };
        cJSON_InitHooks(&cjson_alloc_funcs);
    }

    /* Prefer client config over Kconfig */
    mender_client_config.device_type = IS_NULL_OR_EMPTY(config->device_type) ? CONFIG_MENDER_DEVICE_TYPE : config->device_type;
    if (IS_NULL_OR_EMPTY(mender_client_config.device_type)) {
        mender_log_error("Invalid device type configuration, can't be null or empty");
        ret = MENDER_FAIL;
        goto END;
    }
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
    if (MENDER_OK != (ret = mender_os_scheduler_init())) {
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
        .identity_cb  = callbacks->get_identity,
    };
    if (MENDER_OK != (ret = mender_api_init(&mender_api_config))) {
        mender_log_error("Unable to initialize API");
        goto END;
    }

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
    if (MENDER_OK != (ret = mender_inventory_init(mender_client_config.inventory_update_interval, mender_client_config.device_type))) {
        mender_log_error("Failed to initialize the inventory functionality");
        goto END;
    }
    if (MENDER_OK != mender_inventory_add_default_callbacks()) {
        mender_log_error("Failed to enable default inventory");
        /* unlikely to happen and not a fatal issue, keep going */
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

END:

    return ret;
}

mender_err_t
mender_client_activate(void) {
    mender_err_t ret;

    mender_os_scheduler_work_params_t work_params = {
        .function = mender_client_work_function,
        .period   = mender_client_config.update_poll_interval,
        .name     = "mender_client_main",
    };

    if ((MENDER_OK != (ret = mender_os_scheduler_work_create(&work_params, &mender_client_work)))
        || (MENDER_OK != (ret = mender_os_scheduler_work_activate(mender_client_work)))) {
        mender_log_error("Unable to activate the main work");
        return ret;
    }

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
mender_client_deactivate(void) {
    mender_err_t ret;

    if (NULL != mender_client_work) {
        if (MENDER_OK != (ret = mender_os_scheduler_work_deactivate(mender_client_work))) {
            mender_log_error("Failed to deactivate main work");
            return ret;
        }
    }
#ifdef CONFIG_MENDER_CLIENT_INVENTORY
    if (MENDER_OK != (ret = mender_inventory_deactivate())) {
        /* error already logged */
        return ret;
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

    return MENDER_OK;
}

mender_err_t
mender_client_exit(void) {
    bool some_error = false;

    if (MENDER_OK != mender_client_deactivate()) {
        /* error already logged; keep going on, we want to do as much cleanup as possible */
        some_error = true;
    }

    if (NULL != mender_client_work) {
        if (MENDER_OK != mender_os_scheduler_work_delete(mender_client_work)) {
            mender_log_error("Failed to delete main work");
            /* keep going on, we want to do as much cleanup as possible */
            some_error = true;
        } else {
            mender_client_work = NULL;
        }
    }

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
    if (MENDER_OK != mender_inventory_exit()) {
        mender_log_error("Unable to cleanup after the inventory functionality");
        /* keep going on, we want to do as much cleanup as possible */
        some_error = true;
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

    /* Stop scheduling new work */
    mender_os_scheduler_exit();

    /* Release all modules */
    mender_api_exit();
    mender_tls_exit();
    mender_storage_exit();
    mender_log_exit();
    mender_client_network_release();

    /* Release memory */
    mender_client_config.device_type          = NULL;
    mender_client_config.host                 = NULL;
    mender_client_config.tenant_token         = NULL;
    mender_client_config.update_poll_interval = 0;
    DESTROY_AND_NULL(mender_delete_deployment_data, mender_client_deployment_data);

    mender_update_module_unregister_all();

    return some_error ? MENDER_FAIL : MENDER_OK;
}

static mender_err_t
mender_client_work_function(void) {
    mender_err_t ret;
    mender_log_debug("Inside work function [state: %s]", client_state_str[mender_client_state]);

    switch (mender_client_state) {
        case MENDER_CLIENT_STATE_PENDING_REBOOT:
            mender_log_info("Waiting for a reboot");
            if (MENDER_OK != mender_err_count_reboot_inc()) {
                /* It appears we are stuck in this state. The only thing we can do is to mark the
                   deployment as failed and revert to normal operation. */
                mender_log_error("Waiting for reboot for too long, trying unconditional reboot");
                mender_os_reboot();

                mender_log_error("Failed to reboot unconditionally, trying to resume operations");
                if (NULL == mender_client_deployment_data) {
                    mender_log_error("No deployment data to use for deployment abortion");
                } else {
                    mender_update_state_t update_state;
                    if (MENDER_OK != mender_deployment_data_get_state(mender_client_deployment_data, &update_state)) {
                        mender_log_error("Failed to get current update state, going to ROLLBACK state");
                        update_state = MENDER_UPDATE_STATE_ROLLBACK;
                    } else {
                        update_state = update_state_transitions[update_state].failure;
                    }
                    if (MENDER_OK != set_and_store_state(update_state)) {
                        mender_log_error("Failed to save new state");
                    }
                }

                mender_client_state = MENDER_CLIENT_STATE_OPERATIONAL;
            }
            /* else:
               Nothing to do, but let's make sure we have a chance to detect we are stuck in this
               state (i.e. MENDER_OK, not MENDER_DONE which would tell the scheduler we are
               done and don't need to run again). */
            return MENDER_OK;
        case MENDER_CLIENT_STATE_INITIALIZATION:
            /* Perform initialization of the client */
            mender_err_count_reboot_reset();
            if (MENDER_DONE != mender_client_initialization_work_function()) {
                return MENDER_FAIL;
            }
            mender_client_state = MENDER_CLIENT_STATE_OPERATIONAL;
            /* fallthrough */
        case MENDER_CLIENT_STATE_OPERATIONAL:
            mender_err_count_reboot_reset();
            ret = mender_client_update_work_function();
            if (MENDER_FAIL == ret) {
                if (MENDER_FAIL == mender_err_count_net_check()) {
                    /* Try to release network so that it gets set up again next
                       time. */
                    mender_client_network_release();
                }
            } else if (!MENDER_IS_ERROR(ret)) {
                mender_err_count_net_reset();
            }
            if (MENDER_DONE == ret) {
                /* We should only be done when waiting for a reboot. */
                assert(MENDER_CLIENT_STATE_PENDING_REBOOT == mender_client_state);

                /* We don't want to tell the scheduler we are done because
                   otherwise we won't have a chance to detect that we are
                   waiting for a reboot forever. */
                ret = MENDER_OK;
            }
            return ret;
    }

    /* This should never be reached, all the cases should be covered in the
       above switch and they all return. */
    return MENDER_FAIL;
}

/* Flag to indicate whether a deployment has had a spontaneous reboot */
static bool spontaneous_reboot;

static mender_err_t
mender_client_initialization_work_function(void) {

    mender_err_t ret   = MENDER_DONE;
    spontaneous_reboot = false;

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

    /* Handle spontaneous reboots in  MENDER_UPDATE_STATE_INSTALL and MENDER_UPDATE_STATE_COMMIT
     See https://docs.mender.io/artifact-creation/state-scripts#power-loss */
    mender_update_state_t update_state;
    if (MENDER_OK == (ret = mender_deployment_data_get_state(mender_client_deployment_data, &update_state))) {
        if ((MENDER_UPDATE_STATE_INSTALL == update_state) || (MENDER_UPDATE_STATE_COMMIT == update_state)) {
            mender_log_debug("Spontaneous reboot detected in state %s", update_state_str[update_state]);
            spontaneous_reboot = true;
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

    /* Invoke restart callback, application is responsible to shutdown properly and restart the system */
    /* Set the client's state to PENDING_REBOOT so that we can potentially
       detect a failure to reboot (i.e. waiting for reboot taking too long).  */
    mender_client_state = MENDER_CLIENT_STATE_PENDING_REBOOT;
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
        mender_utils_key_value_list_free(new_provides);
        return MENDER_FAIL;
    }
    mender_utils_key_value_list_free(new_provides);
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

    return MENDER_OK;
}

static mender_err_t
deployment_destroy(mender_api_deployment_data_t *deployment) {
    if (NULL != deployment) {
        mender_free(deployment->id);
        mender_free(deployment->artifact_name);
        mender_free(deployment->uri);
        for (size_t i = 0; i < deployment->device_types_compatible_size; ++i) {
            mender_free(deployment->device_types_compatible[i]);
        }
        mender_free(deployment->device_types_compatible);
        mender_free(deployment);
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

    mender_utils_key_value_list_free(*stored_provides);
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
        if (MENDER_OK != mender_utils_key_value_list_append(&provides, &mender_artifact_ctx->payloads.values[i].provides)) {
            mender_log_error("Unable to merge provides");
            mender_utils_key_value_list_free(stored_provides);
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
        mender_utils_key_value_list_free(stored_provides);
        return MENDER_FAIL;
    }

    /* Filter provides */
    /* `stored_provides` is freed in `mender_filter_provides` */
    if (MENDER_OK != mender_filter_provides(mender_artifact_ctx, &provides, &stored_provides)) {
        return MENDER_FAIL;
    }

    if (MENDER_OK != mender_utils_key_value_list_to_string(provides, new_provides)) {
        mender_utils_key_value_list_free(provides);
        return MENDER_FAIL;
    }

    mender_utils_key_value_list_free(provides);
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
        if (MENDER_OK != mender_utils_key_value_list_append(&depends, &mender_artifact_ctx->payloads.values[i].depends)) {
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
    mender_utils_key_value_list_free(stored_provides);
    return ret;
}
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
static mender_err_t
mender_check_artifact_requirements(mender_artifact_ctx_t *mender_artifact_ctx, mender_api_deployment_data_t *deployment) {
    mender_err_t ret;

    /* Retrieve device type from artifact */
    const char *device_type_artifact = NULL;
    if (MENDER_OK != (ret = mender_artifact_get_device_type(mender_artifact_ctx, &device_type_artifact))) {
        mender_log_error("Unable to get device type from artifact");
        return ret;
    }

    mender_log_debug("Checking device type compatibility");

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

    /* Check payload integrity by comparing computed checksum(s) with those
     * listed in the artifact manifest */
    if (MENDER_OK != mender_artifact_check_integrity_remaining(mender_artifact_ctx)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

static mender_err_t
mender_client_check_deployment(mender_api_deployment_data_t **deployment_data) {
    assert(NULL != deployment_data);

    if (MENDER_FAIL == mender_client_ensure_connected()) {
        /* network errors logged already */
        mender_log_error("Cannot check for new deployment");
        return MENDER_FAIL;
    }

    if (NULL == (*deployment_data = mender_calloc(1, sizeof(mender_api_deployment_data_t)))) {
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
set_and_store_state(const mender_update_state_t state) {

    /*
     * Set the state in `mender_client_deployment_data` and write it to the nvs
     */

    mender_err_t ret = MENDER_OK;

    /* Set state in deployment data */
    if (MENDER_OK != (ret = mender_deployment_data_set_state(mender_client_deployment_data, state))) {
        mender_log_error("Failed to set deployment data state");
        return ret;
    }

    /* Store deployment data */
    if (MENDER_OK != (ret = mender_set_deployment_data(mender_client_deployment_data))) {
        mender_log_error("Failed to store deployment data");
        return ret;
    }
    return ret;
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
        const char           *artifact_type;
        mender_update_state_t update_state_resume;
        if (MENDER_OK == (ret = mender_deployment_data_get_state(mender_client_deployment_data, &update_state_resume))
            && MENDER_OK == mender_deployment_data_get_payload_type(mender_client_deployment_data, &artifact_type)) {
            update_state = update_state_resume;
            mender_log_debug("Resuming from state %s", update_state_str[update_state]);

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
            if (MENDER_UPDATE_STATE_DOWNLOAD != update_state) {
                if (MENDER_OK != mender_deployment_logs_activate()) {
                    mender_log_error("Failed to activate deployment logs gathering");
                    /* Not a fatal issue to abort the deployment, keep going. */
                }
            }
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

            mender_update_module = mender_update_module_get(artifact_type);
            if (NULL == mender_update_module) {
                /* The artifact_type from the saved state does not match any update module */
                mender_log_error("No update module found for artifact type '%s'", artifact_type);
                mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_FAILURE);
                mender_storage_delete_deployment_data();
                goto END;
            }
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
#define NEXT_STATE                                                             \
    if (MENDER_OK == ret) {                                                    \
        update_state = update_state_transitions[update_state].success;         \
        assert(NULL != mender_update_module);                                  \
        mender_log_debug("Entering state %s", update_state_str[update_state]); \
        if (MENDER_LOOP_DETECTED == set_and_store_state(update_state)) {       \
            update_state = MENDER_UPDATE_STATE_FAILURE;                        \
        }                                                                      \
    } else {                                                                   \
        update_state = update_state_transitions[update_state].failure;         \
        mender_log_debug("Entering state %s", update_state_str[update_state]); \
        if (NULL != mender_update_module) {                                    \
            if (MENDER_LOOP_DETECTED == set_and_store_state(update_state)) {   \
                update_state = MENDER_UPDATE_STATE_FAILURE;                    \
            }                                                                  \
        }                                                                      \
        ret = MENDER_OK;                                                       \
        continue;                                                              \
    }

    if (spontaneous_reboot) {
        mender_log_error("Failing deployment, spontaneous reboot detected");
        spontaneous_reboot = false;
        update_state       = update_state_transitions[update_state].failure;
        mender_log_debug("Entering state %s", update_state_str[update_state]);
    }
    while (MENDER_UPDATE_STATE_END != update_state) {
        switch (update_state) {
            case MENDER_UPDATE_STATE_DOWNLOAD:
                /* This is usually logged in the NEXT_STATE macro, but since nothing
                 * transitions to this state, we log it here */
                mender_log_debug("Entering state %s", update_state_str[update_state]);

                /* Check for deployment */
                if (MENDER_OK != (ret = mender_client_check_deployment(&deployment))) {
                    /* No deployment available, but we are not done, we need to keep checking. */
                    if (MENDER_DONE == ret) {
                        ret = MENDER_OK;
                    }
                    goto END;
                }

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
                if (MENDER_OK != mender_storage_deployment_log_clear()) {
                    mender_log_error("Failed to clean old deployment logs");
                    /* Not a fatal issue to abort the deployment, keep going. */
                }
                if (MENDER_OK != mender_deployment_logs_activate()) {
                    mender_log_error("Failed to activate deployment logs gathering");
                    /* Not a fatal issue to abort the deployment, keep going. */
                }
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

#if CONFIG_MENDER_LOG_LEVEL >= MENDER_LOG_LEVEL_INF
                if (strlen(deployment->id) > 10) {
                    mender_log_info("Downloading artifact with id '%.7s...', name '%s', uri '%s'", deployment->id, deployment->artifact_name, deployment->uri);
                } else {
                    mender_log_info("Downloading artifact with id '%s', name '%s', uri '%s'", deployment->id, deployment->artifact_name, deployment->uri);
                }
#endif
                /* Set deployment_id */
                deployment_id = deployment->id;

                /* Check ret to see if the deployment is aborted */
                ret = mender_client_publish_deployment_status(deployment->id, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);
                if ((MENDER_ABORTED != ret)
                    && (MENDER_OK
                        == (ret = mender_download_artifact(deployment->uri, mender_client_deployment_data, &mender_update_module, &mender_artifact_ctx)))) {
                    assert(NULL != mender_update_module);
                    assert(NULL != mender_artifact_ctx);

                    /* Get artifact context if artifact download succeeded */
                    if ((NULL != mender_update_module) && (NULL != mender_artifact_ctx)) {
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
                                mender_free(new_provides);
                            } else {
                                mender_log_error("Unable to prepare new provides");
                            }
#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
                        } else {
                            mender_log_error("Artifact check failed");
                        }
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
                    } else {
                        mender_log_error("Unable to get artifact type and context");
                    }
                } else {
                    mender_log_error("Unable to download artifact");
                    /* Error logged in mender_client_download_artifact_callback() */
                    ret = MENDER_FAIL;
                }
                if (MENDER_OK != ret) {
                    mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_FAILURE);
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_INSTALL:
                mender_log_info("Download done, installing artifact");
                /* Check ret to see if the deployment is aborted */
                ret = mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_INSTALLING);
                if ((MENDER_ABORTED != ret) && (NULL != mender_update_module->callbacks[update_state])) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
                if ((MENDER_OK == ret) && !mender_update_module->requires_reboot) {
                    /* skip reboot */
                    update_state = MENDER_UPDATE_STATE_COMMIT;
                    mender_log_debug("Entering state %s", update_state_str[update_state]);
                    set_and_store_state(update_state);
                    continue;
                }
                /* else continue to the next successful/failure state */
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_REBOOT:
                assert(mender_update_module->requires_reboot);
                mender_log_info("Artifact installation done, rebooting");
                /* Check ret to see if the deployment is aborted */
                ret = mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_REBOOTING);
                if ((MENDER_ABORTED != ret) && (NULL != mender_update_module->callbacks[update_state])) {
                    /* Save the next state before running the reboot callback --
                     * if there is an interrupt (power, crash,...) right after,
                     * it will reboot anyway so after the new boot, reboot
                     * verification should happen anyway, the callback in that
                     * state should be able to see if things went well or
                     * wrong. */
                    set_and_store_state(MENDER_UPDATE_STATE_VERIFY_REBOOT);
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
#ifdef CONFIG_MENDER_COMMIT_REQUIRE_AUTH
                if (MENDER_OK != mender_api_drop_authentication_data()) {
                    mender_log_error("Failed to drop authentication data before artifact commit");
                    /* Unlikely (practically impossible?) to happen and if it does, we don't have
                       much to about it. */
                }
                if (MENDER_IS_ERROR(ret = mender_api_ensure_authenticated())) {
                    mender_log_error("Failed to authenticate before commit, rejecting the update");
                }
#endif /* CONFIG_MENDER_COMMIT_REQUIRE_AUTH */
                if (!MENDER_IS_ERROR(ret) && (MENDER_OK != (ret = mender_commit_artifact_data()))) {
                    mender_log_error("Unable to commit artifact data");
                }
                if (!MENDER_IS_ERROR(ret) && (NULL != mender_update_module->callbacks[update_state])) {
                    ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                }
#ifdef CONFIG_MENDER_CLIENT_INVENTORY
                /* If there was no reboot, we need to tell inventory to refresh
                   the persistent data (because the deployment must have changed
                   artifact name, at least) and we should trigger an inventory
                   submission to refresh the data on the server. */
                if (!mender_update_module->requires_reboot) {
                    if (MENDER_OK != (ret = mender_inventory_reset_persistent())) {
                        mender_log_error("Failed to reset persistent inventory after deployment commit with no reboot");
                    } else if (MENDER_OK != (ret = mender_inventory_execute())) {
                        mender_log_error("Failed to trigger inventory refresh after deployment commit with no reboot");
                    }
                }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */
                if (!MENDER_IS_ERROR(ret)) {
                    mender_client_publish_deployment_status(deployment_id, MENDER_DEPLOYMENT_STATUS_SUCCESS);
                }
                NEXT_STATE;
                /* fallthrough */

            case MENDER_UPDATE_STATE_CLEANUP:
                if (NULL != mender_update_module) {
                    if (NULL != mender_update_module->callbacks[update_state]) {
                        ret = mender_update_module->callbacks[update_state](update_state, (mender_update_state_data_t)NULL);
                    }
                } else {
                    ret = MENDER_FAIL;
                }
                NEXT_STATE;
                mender_storage_delete_deployment_data();
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
                set_and_store_state(MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT);
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

                if (MENDER_OK != ret) {
                    /* If the rollback verify reboot fails,
                     * we will retry the rollback reboot.
                     *
                     * The `rollback-reboot -> rollback-verify-reboot -> rollback-reboot -> ...`
                     * loop is broken when a state loop is detected
                     */
                    mender_log_error("Rollback verify reboot failed. Retry rollback reboot");
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

    ret = MENDER_OK;

END:
    /* Release memory */
    deployment_destroy(deployment);
    DESTROY_AND_NULL(mender_delete_deployment_data, mender_client_deployment_data);
    mender_artifact_release_ctx(mender_artifact_ctx);

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
    mender_deployment_logs_deactivate();
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

    return ret;
}

static mender_err_t
mender_client_publish_deployment_status(const char *id, mender_deployment_status_t deployment_status) {
    if (MENDER_FAIL == mender_client_ensure_connected()) {
        /* connection errors logged already */
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
