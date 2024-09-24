/**
 * @file      mender-deployment-data.h
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

#ifndef __MENDER_DEPLOYMENT_DATA_H__
#define __MENDER_DEPLOYMENT_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-utils.h"
#include "cJSON.h"

#define MENDER_DEPLOYMENT_DATA_KEY_VERSION                "version"
#define MENDER_DEPLOYMENT_DATA_KEY_ID                     "id"
#define MENDER_DEPLOYMENT_DATA_KEY_ARTIFACT_NAME          "artifact_name"
#define MENDER_DEPLOYMENT_DATA_KEY_PAYLOAD_TYPES          "payload_types"
#define MENDER_DEPLOYMENT_DATA_KEY_PROVIDES               "provides"
#define MENDER_DEPLOYMENT_DATA_KEY_STATE                  "state"
#define MENDER_DEPLOYMENT_DATA_KEY_STATE_DATA_STORE_COUNT "state_data_store_count"

typedef cJSON mender_deployment_data_t;

/**
 * @brief Delete deployment data object
 * @param deployment_data Deployment data
 * @note This does not delete it from the store
 */
#define mender_delete_deployment_data(deployment_data) cJSON_Delete(deployment_data)

/**
 * @brief Validate, marshal and write deployment data to store.
 * @param deployment_data Deployment data
 * @note Can fail due to invalid deployment data, max store count reached,
 *       memory allocation errors, or NVS errors.
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
mender_err_t mender_set_deployment_data(mender_deployment_data_t *deployment_data);

/**
 * @brief Read, unmarshal and validate deployment data from store.
 * @param deployment_data Deployment data
 * @return MENDER_OK on success, MENDER_NOT_FOUND if no deployment data
 *         available, otherwise MENDER_FAIL.
 */
mender_err_t mender_get_deployment_data(mender_deployment_data_t **deployment_data);

/**
 * @brief Create a deployment data object.
 * @param id Deployment ID or NULL
 * @param artifact_name Artifact name or NULL
 * @param deployment_data Deployment data
 * @note The version number field will be initialized to the current version and
 *       the state data store count field will be initialized to zero. This
 *       does not take ownership of any of the arguments.
 * @warning If NULL is passed in the arguments, the respective field will be
 *          initialized with the JSON 'null' value as a place holder. If you
 *          don't replace this value before storing the deployment data with
 *          mender_set_deployment_data(), the validation will fail.
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
mender_err_t mender_create_deployment_data(const char *id, const char *artifact_name, mender_deployment_data_t **deployment_data);

/**
 * @brief Append payload type
 * @param deployment_data Deployment data
 * @param payload_type Payload type
 * @note No operation is done if playload type already exists
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
mender_err_t mender_deployment_data_add_payload_type(mender_deployment_data_t *deployment_data, const char *payload_type);

/**
 * @warning Do not use this function directly.
 */
mender_err_t __mender_deployment_data_get_string(const mender_deployment_data_t *deployment_data, const char *key, const char **str);

/**
 * @brief Get artifact name
 * @param deployment_data Deployment data
 * @param artifact_name Artifact name
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_get_artifact_name(deployment_data, artifact_name) \
    __mender_deployment_data_get_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_ARTIFACT_NAME, artifact_name)

/**
 * @brief Get provides (filtered on clears provides)
 * @param deployment_data Deployment data
 * @param provides Provides
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_get_provides(deployment_data, provides) \
    __mender_deployment_data_get_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_PROVIDES, provides)

/**
 * @brief Get deployment ID
 * @param deployment_data Deployment data
 * @param id Deployment ID
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_get_id(deployment_data, id) __mender_deployment_data_get_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_ID, id)

/**
 * @brief Get state name
 * @param deployment_data Deployment data
 * @param name State name
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_get_state(deployment_data, name) __mender_deployment_data_get_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_STATE, state)

/**
 * @warning Do not use this function directly.
 */
mender_err_t __mender_deployment_data_set_string(mender_deployment_data_t *deployment_data, const char *key, const char *str);

/**
 * @brief Replace artifact name
 * @param deployment_data Deployment data
 * @param artifact_name Artifact name
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_set_artifact_name(deployment_data, artifact_name) \
    __mender_deployment_data_set_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_ARTIFACT_NAME, artifact_name)

/**
 * @brief Replace provides (filtered on clears provides)
 * @param deployment_data Deployment data
 * @param provides Provides
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_set_provides(deployment_data, provides) \
    __mender_deployment_data_set_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_PROVIDES, provides)

/**
 * @brief Replace deployment ID
 * @param deployment_data Deployment data
 * @param id Deployment ID
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_set_id(deployment_data, id) __mender_deployment_data_set_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_ID, id)

/**
 * @brief Replace state name
 * @param deployment_data Deployment data
 * @param name State name
 * @return MENDER_OK on success, otherwise MENDER_FAIL
 */
#define mender_deployment_data_set_state(deployment_data, name) __mender_deployment_data_set_string(deployment_data, MENDER_DEPLOYMENT_DATA_KEY_STATE, name)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_DEPLOYMENT_DATA_H__ */
