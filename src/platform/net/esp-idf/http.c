/**
 * @file      http.c
 * @brief     Mender HTTP interface for the ESP-IDF platform
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

#include <errno.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>

#include "api.h"
#include "http.h"
#include "log.h"
#include "os.h"

/**
 * @brief HTTP User-Agent
 */
#define MENDER_HTTP_USER_AGENT "Mender/" MENDER_CLIENT_VERSION " MCU ESP-IDF/" IDF_VER "\r\n"

const size_t mender_http_recv_buf_length = 512;

/**
 * @brief Retry-After header value
 */
/* TODO: properly implement parsing of Retry-After (MEN-10030) */
static uint32_t retry_after_seconds = 0;

/**
 * @brief Mender HTTP configuration
 */
static mender_http_config_t http_config;

mender_err_t
mender_http_init(mender_http_config_t *config) {

    assert(NULL != config);
    assert(NULL != config->host);

    /* Save configuration */
    memcpy(&http_config, config, sizeof(mender_http_config_t));

    return MENDER_OK;
}

static esp_http_client_method_t
http_method_to_http_client_method(mender_http_method_t method) {
    /* Convert method */
    switch (method) {
        case MENDER_HTTP_GET:
            return HTTP_METHOD_GET;
        case MENDER_HTTP_POST:
            return HTTP_METHOD_POST;
        case MENDER_HTTP_PUT:
            return HTTP_METHOD_PUT;
        case MENDER_HTTP_PATCH:
            return HTTP_METHOD_PATCH;
        default:
            return -1;
    }
}

/* Request built will look like this:
    GET https://hosted.mender.io/api/devices/v1/deployments/artifacts/{id} HTTP/1.1
    Host: hosted.mender.io
    User-Agent: Mender/2.0.0 MCU ESP-IDF/2.7.0
    Authorization: Bearer <jwt token>
    X-MEN-Signature: <string>
    Content-Type: application/json
*/
mender_err_t
mender_http_perform(char                *jwt,
                    char                *path,
                    mender_http_method_t method,
                    char                *payload,
                    char                *signature,
                    mender_err_t (*callback)(mender_http_client_event_t, void *, size_t, void *),
                    void *params,
                    int  *status) {

    assert(NULL != path);
    assert(NULL != callback);
    assert(NULL != status);

    mender_err_t             ret    = MENDER_FAIL;
    char                    *url    = NULL;
    char                    *bearer = NULL;
    esp_http_client_handle_t client = NULL;

    /* TODO: Could this be static because we never have overlapping calls of
             this function? Or, on contrary, heap-allocated to spare the
             stack? */
    char      data[mender_http_recv_buf_length];
    esp_err_t err;

    /* Prepend host from config to the URL if required (esp_http_client_init()
       handles parsing/splitting of the URL, we don't have to do it
       ourselves) */
    if (!mender_utils_strbeginswith(path, "http://") && !mender_utils_strbeginswith(path, "https://")) {
        if (-1 == mender_utils_asprintf(&url, "%s%s", http_config.host, path)) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }
    }

    esp_http_client_config_t config = {
        .url               = (url ? url : path),
        .method            = http_method_to_http_client_method(method),
        .user_agent        = MENDER_HTTP_USER_AGENT,
        .crt_bundle_attach = esp_crt_bundle_attach,
        /* .buffer_size_tx = 2048, (being set in https://github.com/joelguittet/mender-mcu-client/blob/master/platform/net/esp-idf/src/mender-http.c#L93) */
    };

    /* Initialization of the client */
    client = esp_http_client_init(&config);
    if (NULL == client) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }

    if (NULL != jwt) {
        if (-1 == mender_utils_asprintf(&bearer, "Bearer %s", jwt)) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }
        err = esp_http_client_set_header(client, "Authorization", bearer);
        if (ESP_OK != err) {
            mender_log_error("Failed to add the Authorization header to HTTP the '%s' request", path);
            ret = MENDER_FAIL;
            goto END;
        }
    }
    if (NULL != signature) {
        err = esp_http_client_set_header(client, "X-MEN-Signature", signature);
        if (ESP_OK != err) {
            mender_log_error("Failed to add the X-MEN-Signature header to HTTP the '%s' request", path);
            ret = MENDER_FAIL;
            goto END;
        }
    }
    if (NULL != payload) {
        err = esp_http_client_set_header(client, "Content-Type", "application/json");
        if (ESP_OK != err) {
            mender_log_error("Failed to add the Content-Type header to HTTP the '%s' request", path);
            ret = MENDER_FAIL;
            goto END;
        }
    }

    /* Open connection */
    err = esp_http_client_open(client, (NULL != payload) ? (int)strlen(payload) : 0);
    if (ESP_OK != err) {
        mender_log_error("Unable to open HTTP connection to '%s': %s", path, esp_err_to_name(err));
        ret = MENDER_FAIL;
        goto END;
    }
    if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_CONNECTED, NULL, 0, params))) {
        mender_log_error("An error occurred while calling 'MENDER_HTTP_EVENT_CONNECTED' callback");
        goto END;
    }

    /* Write payload (if any) */
    if (NULL != payload) {
        if (esp_http_client_write(client, payload, (int)strlen(payload)) < 0) {
            mender_log_error("Unable to write payload data to the HTTP request to '%s'", path);
            ret = MENDER_FAIL;
            goto END;
        }
    }

    /* Fetch headers (returns the value of Content-Length or error) */
    if (esp_http_client_fetch_headers(client) < 0) {
        mender_log_error("Unable to fetch headers");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Read all data */
    do {
        int read_length = esp_http_client_read(client, data, sizeof(data));
        if (read_length < 0) {
            mender_log_error("An error occured, unable to read HTTP data from '%s'", path);
            callback(MENDER_HTTP_EVENT_ERROR, NULL, 0, params);
            ret = MENDER_FAIL;
            goto END;
        } else if (read_length > 0) {
            /* Transmit data received to the upper layer */
            if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_DATA_RECEIVED, data, (size_t)read_length, params))) {
                mender_log_error("An error occurred, stop reading data");
                goto END;
            }
        } else {
            if ((ECONNRESET == errno) || (ENOTCONN == errno)) {
                mender_log_error("An error occurred, HTTP connection has been closed: %s", strerror(errno));
                callback(MENDER_HTTP_EVENT_ERROR, NULL, 0, params);
                ret = MENDER_FAIL;
                goto END;
            }
        }
    } while (!esp_http_client_is_complete_data_received(client));

    /* Read HTTP status code */
    *status = esp_http_client_get_status_code(client);
    if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_DISCONNECTED, NULL, 0, params))) {
        mender_log_error("An error occurred");
        goto END;
    }

END:
    if (NULL != client) {
        esp_http_client_cleanup(client);
    }

    mender_free(url);
    mender_free(bearer);

    return ret;
}

mender_err_t
mender_http_artifact_download(const char *uri, mender_artifact_download_data_t *dl_data, int *status) {
    assert(NULL != dl_data);

    /* Unlike on Zephyr, we don't have to pass a callback with extra data
       containing another callback, calling another callback,... The logic in
       mender_http_perform() above is much simpler -- it opens a connection,
       reads headers, writes a payload (if any) and then repeatedly reads the
       response calling the one callback with give it to process the data. No
       extra callback, no extra complexity.
       Thus we can simply use it here and give it the artifact download callback
       (to process the response data) and the dl_data struct as extra data to
       use and populate. */
    return mender_http_perform(NULL,
                               (char *)uri,
                               MENDER_HTTP_GET,
                               NULL,
                               NULL,
                               (mender_err_t(*)(mender_http_client_event_t, void *, size_t, void *))dl_data->artifact_download_callback,
                               dl_data,
                               status);
}

mender_err_t
mender_http_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}

uint32_t
mender_http_get_retry_interval(void) {
    return retry_after_seconds;
}
