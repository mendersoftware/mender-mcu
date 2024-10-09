/**
 * @file      mender-artifact-download-data.h
 * @brief     Mender artifact download data definition
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

#ifndef __MENDER_ARTIFACT_DOWNLOAD_DATA_H__
#define __MENDER_ARTIFACT_DOWNLOAD_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-deployment-data.h"
#include "mender-http-client-event.h"
#include "mender-update-module.h"

typedef struct mender_artifact_download_data_t {
    mender_deployment_data_t *deployment;
    mender_update_module_t   *update_module;
    mender_err_t (*artifact_download_callback)(mender_http_client_event_t              event,
                                               void                                   *data,
                                               size_t                                  data_length,
                                               struct mender_artifact_download_data_t *dl_data);
    mender_err_t ret;
} mender_artifact_download_data_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_ARTIFACT_DOWNLOAD_DATA_H__ */
