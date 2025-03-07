/**
 * @file      api.h
 * @brief     Implementation of the Mender API (private API)
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

#ifndef __MENDER_API_PRIV_H__
#define __MENDER_API_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "artifact.h"
#include "http.h"
#include "utils.h"

/**
 * @brief Mender API configuration
 */
typedef struct {
    char *device_type;                                               /**< Device type */
    char *host;                                                      /**< URL of the mender server */
    char *tenant_token;                                              /**< Tenant token used to authenticate on the mender server (optional) */
    mender_err_t (*identity_cb)(const mender_identity_t **identity); /**< Invoked to retrieve identity */
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
 * @brief  Ensures being authenticated to a Mender server API
 * @return MENDER_DONE if already authenticated,
 *         MENDER_OK if successfully authenticated,
 *         MENDER_FAIL otherwise
 */
mender_err_t mender_api_ensure_authenticated(void);

/**
 * @brief Drops authentication data so the next request will have to re-authenticate
 * @return MENDER_OK in case of success, error otherwise
 */
mender_err_t mender_api_drop_authentication_data(void);

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
 * @param inventory Mender inventory data as a JSON array of key-value pairs (ownership transferred)
 * @param patch Whether to patch inventory data (PATCH) or replace the old data with new (PUT)
 * @return MENDER_OK if the function succeeds, error code otherwise
 * @note #inventory is consumed by the function (taken over and deallocated)
 */
mender_err_t mender_api_publish_inventory_data(cJSON *inventory, bool patch);

#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

/**
 * @brief Release mender API
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_api_exit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_API_PRIV_H__ */
