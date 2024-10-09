/**
 * @file      mender-api.h
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

#ifndef __MENDER_API_H__
#define __MENDER_API_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-artifact.h"
#include "mender-http.h"
#include "mender-utils.h"

/**
 * @brief Mender API configuration
 */
typedef struct {
    char *device_type;  /**< Device type */
    char *host;         /**< URL of the mender server */
    char *tenant_token; /**< Tenant token used to authenticate on the mender server (optional) */
} mender_api_config_t;

/**
 * @brief Deployment API Struct
 */
typedef struct {
    char  *id;                           /**< ID of the deployment */
    char  *artifact_name;                /**< Artifact name of the deployment */
    char  *uri;                          /**< URI of the deployment */
    char **device_types_compatible;      /**< Array of compatible deployment types */
    size_t device_types_compatible_size; /**< Size of the deployment type array */
} mender_api_deployment_data_t;

/**
 * @brief Initialization of the API
 * @param config Mender API configuration
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_init(mender_api_config_t *config);

/**
 * @brief Whether a successful authentication to a Mender server has been performed or not
 */
bool mender_api_is_authenticated(void);

/**
 * @brief Perform authentication of the device, retrieve token from mender-server used for the next requests
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_perform_authentication(mender_err_t (*get_identity)(mender_identity_t **identity));

/**
 * @brief Check for deployments for the device from the mender-server
 * @param deployment Deployment structure to be filled with the deployment information, if one is pending
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_check_for_deployment(mender_api_deployment_data_t *deployment);

/**
 * @brief Publish deployment status of the device to the mender-server
 * @param id ID of the deployment received from mender_api_check_for_deployment function
 * @param deployment_status Deployment status
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_publish_deployment_status(const char *id, mender_deployment_status_t deployment_status);

/**
 * @brief Print response error
 * @param response HTTP response, NULL if not available
 * @param status HTTP status
 */
void mender_api_print_response_error(char *response, int status);

/**
 * @brief Download artifact from the mender-server
 * @param uri URI of the deployment received from mender_api_check_for_deployment function
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_download_artifact(char *uri);

/**
 * @brief HTTP callback used to handle artifact content
 * @param event HTTP client event
 * @param data Data received
 * @param data_length Data length
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_http_artifact_callback(mender_http_client_event_t event, void *data, size_t data_length);

#ifdef CONFIG_MENDER_CLIENT_INVENTORY

/**
 * @brief Publish inventory data of the device to the mender-server
 * @param inventory Mender inventory key/value pairs table, must end with a NULL/NULL element, NULL if not defined
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_publish_inventory_data(mender_keystore_t *inventory);

#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

/**
 * @brief Release mender API
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_exit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_API_H__ */
