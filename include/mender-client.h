/**
 * @file      mender-client.h
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

#ifndef __MENDER_CLIENT_H__
#define __MENDER_CLIENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-utils.h"
#include "mender-update-module.h"

/**
 * @brief Mender client states
 */
typedef enum {
    MENDER_CLIENT_STATE_INITIALIZATION, /**< Perform initialization */
    MENDER_CLIENT_STATE_OPERATIONAL,    /**< Under standard operation */
    MENDER_CLIENT_STATE_PENDING_REBOOT, /**< Waiting for a reboot */
} mender_client_state_t;

/**
 * @brief Mender client state
 */
extern mender_client_state_t mender_client_state;

/**
 * @brief Mender client configuration
 */
typedef struct {
    char   *device_type;                  /**< Device type */
    char   *host;                         /**< URL of the mender server */
    char   *tenant_token;                 /**< Tenant token used to authenticate on the mender server (optional) */
    int32_t authentication_poll_interval; /**< Authentication poll interval, default is 60 seconds, -1 permits to disable periodic execution */
    int32_t update_poll_interval;         /**< Update poll interval, default is 1800 seconds, -1 permits to disable periodic execution */
#ifdef CONFIG_MENDER_CLIENT_INVENTORY
    uint32_t inventory_update_interval; /**< Inventory update interval, default is compile-time defined */
#endif                                  /* CONFIG_MENDER_CLIENT_INVENTORY */
    bool recommissioning;               /**< Used to force creation of new authentication keys */
} mender_client_config_t;

/**
 * @brief Mender client callbacks
 */
typedef struct {
    mender_err_t (*network_connect)(void);                                 /**< Invoked when mender-client requests access to the network */
    mender_err_t (*network_release)(void);                                 /**< Invoked when mender-client releases access to the network */
    mender_err_t (*deployment_status)(mender_deployment_status_t, char *); /**< Invoked on transition changes to inform of the new deployment status */
    mender_err_t (*restart)(void);                                         /**< Invoked to restart the device */
    mender_err_t (*get_identity)(mender_identity_t **identity);            /**< Invoked to retrieve identity */
    mender_err_t (*get_user_provided_keys)(
        char **user_provided_key, size_t *user_provided_key_length); /**< Invoked to retrieve buffer and buffer size of PEM encoded user-provided key */
} mender_client_callbacks_t;

extern mender_client_callbacks_t mender_client_callbacks;

/**
 * @brief Return mender client version
 * @return Mender client version as string
 */
char *mender_client_version(void);

/**
 * @brief Initialize mender client
 * @param config Mender client configuration
 * @param callbacks Mender client callbacks
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_client_init(mender_client_config_t *config, mender_client_callbacks_t *callbacks);

/**
 * @brief Activate mender client
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_client_activate(void);

/**
 * @brief Deactivate mender client
 * @note This function stops synchronization with the server
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_client_deactivate(void);

/**
 * @brief Function used to trigger execution of the authentication and update work
 * @note Calling this function is optional when the periodic execution of the work is configured
 * @note It only permits to execute the work as soon as possible to synchronize updates
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_client_execute(void);

/**
 * @brief  Ensures the client has a network connection
 * @return MENDER_DONE if already connected,
 *         MENDER_OK if successfully connected,
 *         MENDER_FAIL otherwise
 */
mender_err_t mender_client_ensure_connected(void);

/**
 * @brief  Ensures the client is authenticated to a Mender server API
 * @return MENDER_DONE if already authenticated,
 *         MENDER_OK if successfully authenticated,
 *         MENDER_FAIL otherwise
 */
mender_err_t mender_client_ensure_authenticated(void);

/**
 * @brief Release mender client
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_client_exit(void);

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
mender_err_t mender_client_download_artifact_callback(char *type, cJSON *meta_data, char *filename, size_t size, void *data, size_t index, size_t length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_CLIENT_H__ */
