/**
 * @file      mender-http.h
 * @brief     Mender HTTP interface
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

#ifndef __MENDER_HTTP_H__
#define __MENDER_HTTP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mender-artifact-download-data.h"
#include "mender-http-client-event.h"
#include "mender-utils.h"

/**
 * @brief Receive buffer length
 */
extern const size_t mender_http_recv_buf_length;

/**
 * @brief Mender HTTP configuration
 */
typedef struct {
    char *host; /**< URL of the mender server */
} mender_http_config_t;

/**
 * @brief HTTP methods
 */
typedef enum {
    MENDER_HTTP_GET,  /**< GET */
    MENDER_HTTP_POST, /**< POST */
    MENDER_HTTP_PUT,  /**< PUT */
    MENDER_HTTP_PATCH /**< PATCH */
} mender_http_method_t;

/**
 * @brief Initialize mender http
 * @param config Mender HTTP configuration
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_http_init(mender_http_config_t *config);

/**
 * @brief Perform HTTP request
 * @param jwt Token, NULL if not authenticated yet
 * @param path Path of the request
 * @param method Method
 * @param payload Payload, NULL if empty
 * @param signature Signature of the payload, NULL if it is not required
 * @param callback Callback invoked on HTTP events
 * @param params Parameters passed to the callback, NULL if not used
 * @param status Status code
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_http_perform(char                *jwt,
                                 char                *path,
                                 mender_http_method_t method,
                                 char                *payload,
                                 char                *signature,
                                 mender_err_t (*callback)(mender_http_client_event_t, void *, size_t, void *),
                                 void *params,
                                 int  *status);

/**
 * @brief Perform HTTP artifact download request
 * @param path Path of the request
 * @param status Status code
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_http_artifact_download(char *path, mender_artifact_download_data_t *dl_data, int *status);

/**
 * @brief Release mender http
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_http_exit(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_HTTP_H__ */
