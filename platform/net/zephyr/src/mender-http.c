/**
 * @file      mender-http.c
 * @brief     Mender HTTP interface for Zephyr platform
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

#include <version.h>
#include <zephyr/net/http/client.h>
#include <zephyr/kernel.h>
#include "mender-api.h"
#include "mender-http.h"
#include "mender-log.h"
#include "mender-net.h"

/**
 * @brief HTTP User-Agent
 */
#define MENDER_HEADER_HTTP_USER_AGENT "User-Agent: Mender/" MENDER_CLIENT_VERSION " MCU Zephyr/" KERNEL_VERSION_STRING "\r\n"

/**
 * @brief Request timeout (milliseconds)
 */
#define MENDER_HTTP_REQUEST_TIMEOUT (60 * 1000)

const size_t mender_http_recv_buf_length = 512;

/**
 * @brief Request context
 */
typedef struct {
    mender_err_t (*callback)(mender_http_client_event_t, void *, size_t, void *); /**< Callback to be invoked when data are received */
    void        *params;                                                          /**< Callback parameters */
    mender_err_t ret;                                                             /**< Last callback return value */
} mender_http_request_context;

/**
 * @brief Mender HTTP configuration
 */
static mender_http_config_t mender_http_config;

/**
 * @brief HTTP response callback, invoked to handle data received
 * @param response HTTP response structure
 * @param final_call Indicate final call
 * @param user_data User data, used to retrieve request context data
 */
static void mender_http_response_cb(struct http_response *response, enum http_final_call final_call, void *user_data);

/**
 * @brief HTTP artifact response callback, invoked to handle data received
 * @param response HTTP response structure
 * @param final_call Indicate final call
 * @param user_data User data, used to retrieve request context data
 */
static void artifact_response_cb(struct http_response *response, enum http_final_call final_call, void *user_data);

/**
 * @brief Convert mender HTTP method to Zephyr HTTP client method
 * @param method Mender HTTP method
 * @return Zephyr HTTP client method if the function succeeds, -1 otherwise
 */
static enum http_method mender_http_method_to_zephyr_http_client_method(mender_http_method_t method);

mender_err_t
mender_http_init(mender_http_config_t *config) {

    assert(NULL != config);
    assert(NULL != config->host);

    /* Save configuration */
    memcpy(&mender_http_config, config, sizeof(mender_http_config_t));

    return MENDER_OK;
}

/* Request built will look like this:
    GET https://hosted.mender.io/api/devices/v1/deployments/artifacts/{id} HTTP/1.1
    Host: hosted.mender.io
    User-Agent: Mender/2.0.0 MCU Zephyr/2.7.0
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
    mender_err_t                ret                = MENDER_FAIL;
    struct http_request         request            = { 0 };
    mender_http_request_context request_context    = { callback = callback, params = params, ret = MENDER_OK };
    const char                 *header_fields[6]   = { NULL }; /* The list is NULL terminated; make sure the size reflects it */
    size_t                      header_fields_size = sizeof(header_fields) / sizeof(header_fields[0]);
    char                       *host               = NULL;
    char                       *port               = NULL;
    char                       *url                = NULL;
    int                         sock               = -1;
    int                         http_req_ret;

    /* Headers to be added to the request */
    char *host_header      = NULL;
    char *auth_header      = NULL;
    char *signature_header = NULL;

    /* Retrieve host, port and url */
    if (MENDER_OK != mender_net_get_host_port_url(path, mender_http_config.host, &host, &port, &url)) {
        mender_log_error("Unable to retrieve host/port/url");
        goto END;
    }

    /* Configuration of the client */
    request.method      = mender_http_method_to_zephyr_http_client_method(method);
    request.url         = url;
    request.host        = host;
    request.protocol    = "HTTP/1.1";
    request.payload     = payload;
    request.payload_len = (NULL != payload) ? strlen(payload) : 0;
    request.response    = mender_http_response_cb;
    if (NULL == (request.recv_buf = (uint8_t *)malloc(mender_http_recv_buf_length))) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }
    request.recv_buf_len = mender_http_recv_buf_length;

    /* Add headers */
    host_header = header_alloc_and_add(header_fields, header_fields_size, "Host: %s\r\n", host);
    if (NULL == host_header) {
        mender_log_error("Unable to add 'Host' header");
        goto END;
    }

    if (MENDER_FAIL == header_add(header_fields, header_fields_size, MENDER_HEADER_HTTP_USER_AGENT)) {
        mender_log_error("Unable to add 'User-Agent' header");
        goto END;
    }

    if (NULL != jwt) {
        auth_header = header_alloc_and_add(header_fields, header_fields_size, "Authorization: Bearer %s\r\n", jwt);
        if (NULL == auth_header) {
            mender_log_error("Unable to add 'Authorization' header");
            goto END;
        }
    }

    if (NULL != signature) {
        signature_header = header_alloc_and_add(header_fields, header_fields_size, "X-MEN-Signature: %s\r\n", signature);
        if (NULL == signature_header) {
            mender_log_error("Unable to add 'X-MEN-Signature' header");
            goto END;
        }
    }

    if (NULL != payload) {
        if (MENDER_FAIL == header_add(header_fields, header_fields_size, "Content-Type: application/json\r\n")) {
            mender_log_error("Unable to add 'Content-Type' header");
            goto END;
        }
    }

    request.header_fields = header_fields;

    /* Connect to the server */
    sock = mender_net_connect(host, port);
    if (sock < 0) {
        mender_log_error("Unable to open HTTP client connection");
        goto END;
    }
    if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_CONNECTED, NULL, 0, params))) {
        mender_log_error("An error occurred while calling 'MENDER_HTTP_EVENT_CONNECTED' callback");
        goto END;
    }

    /* Perform HTTP request */
    if ((http_req_ret = http_client_req(sock, &request, MENDER_HTTP_REQUEST_TIMEOUT, (void *)&request_context)) < 0) {
        mender_log_error("HTTP request failed: %s", strerror(-http_req_ret));
        goto END;
    }

    /* Check if an error occured during the treatment of data */
    if (MENDER_OK != (ret = request_context.ret)) {
        goto END;
    }

    /* Read HTTP status code */
    if (0 == request.internal.response.http_status_code) {
        mender_log_error("An error occurred, connection has been closed");
        callback(MENDER_HTTP_EVENT_ERROR, NULL, 0, params);
        goto END;
    } else {
        *status = request.internal.response.http_status_code;
    }
    if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_DISCONNECTED, NULL, 0, params))) {
        mender_log_error("An error occurred while calling 'MENDER_HTTP_EVENT_DISCONNECTED' callback");
        goto END;
    }

    ret = MENDER_OK;

END:

    /* Close connection */
    if (sock >= 0) {
        mender_net_disconnect(sock);
    }

    /* Release memory */
    free(host);
    free(port);
    free(url);
    free(host_header);
    free(auth_header);
    free(signature_header);

    free(request.recv_buf);

    return ret;
}

mender_err_t
mender_http_artifact_download(char *uri, mender_artifact_download_data_t *dl_data, int *status) {
    assert(NULL != dl_data);
    assert(NULL != status);

    mender_err_t        ret                = MENDER_FAIL;
    struct http_request request            = { 0 };
    mender_err_t        request_ret        = MENDER_OK;
    const char         *header_fields[3]   = { NULL }; /* The list is NULL terminated; make sure the size reflects it */
    size_t              header_fields_size = sizeof(header_fields) / sizeof(header_fields[0]);
    char               *host               = NULL;
    char               *port               = NULL;
    char               *url                = NULL;
    int                 sock               = -1;
    int                 http_req_ret;

    /* Headers to be added to the request */
    char *host_header = NULL;

    /* Retrieve host, port and url */
    if (MENDER_OK != mender_net_get_host_port_url(uri, mender_http_config.host, &host, &port, &url)) {
        mender_log_error("Unable to retrieve host/port/url");
        goto END;
    }

    /* Configuration of the client */
    request.method   = mender_http_method_to_zephyr_http_client_method(MENDER_HTTP_GET);
    request.url      = url;
    request.host     = host;
    request.protocol = "HTTP/1.1";
    request.response = artifact_response_cb;
    if (NULL == (request.recv_buf = (uint8_t *)malloc(mender_http_recv_buf_length))) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }
    request.recv_buf_len = mender_http_recv_buf_length;

    /* Add headers */
    host_header = header_alloc_and_add(header_fields, header_fields_size, "Host: %s\r\n", host);
    if (NULL == host_header) {
        mender_log_error("Unable to add 'Host' header");
        goto END;
    }
    if (MENDER_FAIL == header_add(header_fields, header_fields_size, MENDER_HEADER_HTTP_USER_AGENT)) {
        mender_log_error("Unable to add 'User-Agent' header");
        goto END;
    }
    request.header_fields = header_fields;

    /* Connect to the server */
    sock = mender_net_connect(host, port);
    if (sock < 0) {
        mender_log_error("Unable to open HTTP client connection");
        goto END;
    }
    if (MENDER_OK != (ret = dl_data->artifact_download_callback(MENDER_HTTP_EVENT_CONNECTED, NULL, 0, dl_data))) {
        mender_log_error("An error occurred while calling 'MENDER_HTTP_EVENT_CONNECTED' artifact callback");
        goto END;
    }

    /* Perform HTTP request */
    if ((http_req_ret = http_client_req(sock, &request, MENDER_HTTP_REQUEST_TIMEOUT, dl_data)) < 0) {
        mender_log_error("HTTP request failed: %s", strerror(-http_req_ret));
        goto END;
    }

    /* Check if an error occured during the treatment of data */
    if (MENDER_OK != (ret = request_ret)) {
        goto END;
    }

    /* Read HTTP status code */
    if (0 == request.internal.response.http_status_code) {
        mender_log_error("An error occurred, connection has been closed");
        dl_data->artifact_download_callback(MENDER_HTTP_EVENT_ERROR, NULL, 0, dl_data);
        goto END;
    } else {
        *status = request.internal.response.http_status_code;
    }
    if (MENDER_OK != (ret = dl_data->artifact_download_callback(MENDER_HTTP_EVENT_DISCONNECTED, NULL, 0, dl_data))) {
        mender_log_error("An error occurred while calling 'MENDER_HTTP_EVENT_DISCONNECTED' artifact callback");
        goto END;
    }

    ret = MENDER_OK;

END:

    /* Close connection */
    if (sock >= 0) {
        mender_net_disconnect(sock);
    }

    /* Release memory */
    free(host);
    free(port);
    free(url);
    free(host_header);

    free(request.recv_buf);

    return ret;
}

mender_err_t
mender_http_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}

static void
mender_http_response_cb(struct http_response *response, enum http_final_call final_call, void *user_data) {

    assert(NULL != response);
    (void)final_call;
    assert(NULL != user_data);

    /* Retrieve request context */
    mender_http_request_context *request_context = (mender_http_request_context *)user_data;

    /* Check if data is available */
    if ((true == response->body_found) && (NULL != response->body_frag_start) && (0 != response->body_frag_len) && (MENDER_OK == request_context->ret)) {

        /* Transmit data received to the upper layer */
        if (MENDER_OK
            != (request_context->ret = request_context->callback(
                    MENDER_HTTP_EVENT_DATA_RECEIVED, (void *)response->body_frag_start, response->body_frag_len, request_context->params))) {
            mender_log_error("An error occurred, stop reading data");
        }
    }
}

static void
artifact_response_cb(struct http_response *response, MENDER_ARG_UNUSED enum http_final_call final_call, void *user_data) {

    assert(NULL != response);
    assert(NULL != user_data);

    /* Retrieve request context */
    mender_artifact_download_data_t *dl_data = user_data;

    /* Check if data is available */
    if (response->body_found && (NULL != response->body_frag_start) && (0 != response->body_frag_len) && (MENDER_OK == (dl_data->ret))) {
        /* Transmit data received to the upper layer */
        dl_data->ret
            = dl_data->artifact_download_callback(MENDER_HTTP_EVENT_DATA_RECEIVED, (void *)response->body_frag_start, response->body_frag_len, dl_data);
        if (MENDER_OK != (dl_data->ret)) {
            mender_log_error("An error occurred, stop reading data");
        }
    }
}

static enum http_method
mender_http_method_to_zephyr_http_client_method(mender_http_method_t method) {

    /* Convert method */
    switch (method) {
        case MENDER_HTTP_GET:
            return HTTP_GET;
        case MENDER_HTTP_POST:
            return HTTP_POST;
        case MENDER_HTTP_PUT:
            return HTTP_PUT;
        case MENDER_HTTP_PATCH:
            return HTTP_PATCH;
        default:
            return -1;
    }
}
