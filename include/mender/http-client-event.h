/**
 * @file      mender-http-client-event.h
 * @brief     Mender HTTP client event type
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

#ifndef __MENDER_HTTP_CLIENT_EVENT_H__
#define __MENDER_HTTP_CLIENT_EVENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief HTTP client events
 */
typedef enum {
    MENDER_HTTP_EVENT_CONNECTED,     /**< Connected to the server */
    MENDER_HTTP_EVENT_DATA_RECEIVED, /**< Data received from the server */
    MENDER_HTTP_EVENT_DISCONNECTED,  /**< Disconnected from the server */
    MENDER_HTTP_EVENT_ERROR          /**< An error occurred */
} mender_http_client_event_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_HTTP_CLIENT_EVENT_H__ */
