/**
 * @file      mender-artifact-download.h
 * @brief     Mender artifact download interface
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

#ifndef __MENDER_ARTIFACT_DOWNLOAD_H__
#define __MENDER_ARTIFACT_DOWNLOAD_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-deployment-data.h"
#include "mender-update-module.h"
#include "mender-utils.h"

/**
 * @brief Download artifact from the given URI
 * @param uri URI to download the artifact from
 * @param deployment_data Deployment data to extend with artifact metadata
 * @param update_module A place to store the update module selected for the artifact
 */
mender_err_t mender_download_artifact(const char *uri, mender_deployment_data_t *deployment_data, mender_update_module_t **update_module);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_ARTIFACT_DOWNLOAD_H__ */
