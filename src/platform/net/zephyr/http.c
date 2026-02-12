/**
 * @file      http.c
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

#include <errno.h>
#include <version.h>
#include <zephyr/net/http/client.h>
#include <zephyr/sys/timeutil.h>
#include <zephyr/kernel.h>
#include "api.h"
#include "http.h"
#include "log.h"
#include "os.h"

#include "net.h"

/* Zephyr versions 4.2.0 and above return int, versions below 4.2.0 return void */
#if (ZEPHYR_VERSION_CODE < ZEPHYR_VERSION(4, 2, 0))
#define HTTP_CALLBACK_RETURN_VALUE
#define HTTP_CALLBACK_RETURN_TYPE void
#else
#define HTTP_CALLBACK_RETURN_VALUE 0
#define HTTP_CALLBACK_RETURN_TYPE  int
#endif

#ifndef CONFIG_MENDER_HTTP_REQUEST_TIMEOUT_MS
#define CONFIG_MENDER_HTTP_REQUEST_TIMEOUT_MS (60000)
#endif /* CONFIG_MENDER_HTTP_REQUEST_TIMEOUT */

/**
 * @brief HTTP User-Agent
 */
#define MENDER_HEADER_HTTP_USER_AGENT "User-Agent: Mender/" MENDER_CLIENT_VERSION " MCU Zephyr/" KERNEL_VERSION_STRING "\r\n"

/**
 * @brief Request timeout (milliseconds)
 */
#define MENDER_HTTP_REQUEST_TIMEOUT CONFIG_MENDER_HTTP_REQUEST_TIMEOUT_MS

/**
 * @brief Rate limit HTTP status code
 */
#define MENDER_HTTP_RATE_LIMIT_HTTP_CODE 429

const size_t mender_http_recv_buf_length = 512;

/**
 * @brief Request context
 */
typedef struct {
    mender_err_t (*callback)(mender_http_client_event_t, void *, size_t, void *); /**< Callback to be invoked when data are received */
    void        *params;                                                          /**< Callback parameters */
    mender_err_t ret;                                                             /**< Last callback return value */
    bool         parsing_retry_after;                                             /**< Flag indicating if currently parsing Retry-After header */
#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
    bool parsing_date; /**< Flag indicating if currently parsing Date header */
#endif
} mender_http_request_context;

/**
 * @brief Mender HTTP configuration
 */
static mender_http_config_t http_config;

/**
 * @brief Retry-After header value
 */
static uint32_t retry_after_seconds = 0;

#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
/**
 * @brief Server time from Date header (used for calculating retry delay)
 */
static time_t server_time = 0;
#endif

/**
 * @brief HTTP response callback, invoked to handle data received
 * @param response HTTP response structure
 * @param final_call Indicate final call
 * @param user_data User data, used to retrieve request context data
 * @return HTTP_CALLBACK_RETURN_VALUE, 0 if Zephyr >= 4.2.0, void otherwise
 */
static HTTP_CALLBACK_RETURN_TYPE http_response_cb(struct http_response *response, enum http_final_call final_call, void *user_data);

/**
 * @brief HTTP artifact response callback, invoked to handle data received
 * @param response HTTP response structure
 * @param final_call Indicate final call
 * @param user_data User data, used to retrieve request context data
 * @return HTTP_CALLBACK_RETURN_VALUE, 0 if Zephyr >= 4.2.0, void otherwise
 */
static HTTP_CALLBACK_RETURN_TYPE artifact_response_cb(struct http_response *response, enum http_final_call final_call, void *user_data);

/**
 * @brief Convert mender HTTP method to Zephyr HTTP client method
 * @param method Mender HTTP method
 * @return Zephyr HTTP client method if the function succeeds, -1 otherwise
 */
static enum http_method http_method_to_zephyr_http_client_method(mender_http_method_t method);

/**
 * @brief HTTP parser callback for header field names
 * @param parser HTTP parser structure
 * @param at Pointer to header field name
 * @param length Length of header field name
 * @return 0 on success
 */
static int
on_header_field(struct http_parser *parser, const char *at, size_t length) {
    struct http_request *req = CONTAINER_OF(parser, struct http_request, internal.parser);

    /* Only parse header field on 429 status codes */
    if (MENDER_HTTP_RATE_LIMIT_HTTP_CODE != parser->status_code) {
        return 0;
    }

    mender_http_request_context *ctx             = req->internal.user_data;
    const char                  *retry_after_str = "Retry-After";
#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
    const char *date_str = "Date";
#endif

    if ((length == strlen(retry_after_str)) && StringEqualN(retry_after_str, at, length)) {
        ctx->parsing_retry_after = true;
    }
#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
    else if ((length == strlen(date_str)) && StringEqualN(date_str, at, length)) {
        ctx->parsing_date = true;
    }
#endif
    return 0;
}

#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
/**
 * @brief Parse HTTP-date -- https://www.rfc-editor.org/rfc/rfc9110.html#name-date-time-formats
 * @param str Date string (e.g., "Sun, 27 Jan 2026 15:00:00 GMT")
 * @param tm Output tm structure
 * @return 0 on success, -1 on failure
 */
static int
parse_http_date(const char *str, struct tm *tm) {
    static const char *const months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    char                     day_name[4];
    char                     mon[4];
    int                      day, year, hour, min, sec;

    if (7 != sscanf(str, "%3s, %d %3s %d %d:%d:%d", day_name, &day, mon, &year, &hour, &min, &sec)) {
        mender_log_error("Failed to parse HTTP-date format: '%s'", str);
        return -1;
    }

    /* Convert month name to number */
    for (int i = 0; i < 12; i++) {
        if (StringEqual(mon, months[i])) {
            tm->tm_mon   = i;
            tm->tm_mday  = day;
            tm->tm_year  = year - 1900;
            tm->tm_hour  = hour;
            tm->tm_min   = min;
            tm->tm_sec   = sec;
            tm->tm_isdst = 0;
            return 0;
        }
    }

    mender_log_error("Unknown month name in HTTP-date: '%s'", mon);
    return -1;
}
#endif

/**
 * @brief HTTP parser callback for header values
 * @param parser HTTP parser structure
 * @param at Pointer to header value
 * @param length Length of header value
 * @return 0 on success
 */
static int
on_header_value(struct http_parser *parser, const char *at, size_t length) {
    struct http_request         *req = CONTAINER_OF(parser, struct http_request, internal.parser);
    mender_http_request_context *ctx = req->internal.user_data;

    if (MENDER_HTTP_RATE_LIMIT_HTTP_CODE != parser->status_code) {
        return 0;
    }

#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
    /* We're not guaranteed to have the correct time set on the device, so we attempt to parse the Date header on a response instead.
     * According to https://httpwg.org/specs/rfc9110.html#field.date, the Date header is sent on 4xx (Client Error) responses
     * as long as the server has a clock. If we fail to parse the header and the server responds with an HTTP-date
     * in Retry-After, we will fall back to using regular backoff intervals */
    if (ctx->parsing_date) {
        ctx->parsing_date = false;

        char string[length + 1];
        string[length] = '\0';
        memcpy(string, at, length);

        struct tm tm_date;
        if (0 == parse_http_date(string, &tm_date)) {
            server_time = timeutil_timegm(&tm_date);
            mender_log_debug("Parsed server time from Date header");
        } else {
            mender_log_warning("Failed to parse Date header: '%s'", string);
            server_time = 0;
        }
        return 0;
    }
#endif

    if (ctx->parsing_retry_after) {
        ctx->parsing_retry_after = false;

        char string[length + 1];
        string[length] = '\0';
        memcpy(string, at, length);

        char *endptr;
        errno            = 0;
        uint32_t seconds = strtoul(string, &endptr, 10);

        /* If not numeric, try parsing as HTTP-date */
        if ((string == endptr) || ('\0' != *endptr) || (ERANGE == errno) || (0 == seconds)) {
#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
            /* Try to parse the Retry-After value as an HTTP-date. We compare the Retry-After HTTP-date
             * with the HTTP-date from the Date header of the HTTP response.
             * Normally this won't be the case, as Mender Server returns the Retry-After value in seconds */
            struct tm tm_retry;
            if ((0 < server_time) && (0 == parse_http_date(string, &tm_retry))) {
                time_t retry_time = timeutil_timegm(&tm_retry);
                if (server_time < retry_time) {
                    seconds = (uint32_t)(retry_time - server_time);
                }
            }
#endif
        }

        if (0 < seconds) {
            retry_after_seconds = seconds;
            mender_log_debug("Retry-After: %u seconds", retry_after_seconds);
        } else {
            mender_log_warning("Unable to parse Retry-After: '%s'", string);
        }
    }

    return 0;
}

mender_err_t
mender_http_init(mender_http_config_t *config) {

    assert(NULL != config);
    assert(NULL != config->host);

    /* Save configuration */
    memcpy(&http_config, config, sizeof(mender_http_config_t));

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

    /* Clear previous Retry-After value */
    retry_after_seconds = 0;
#ifdef CONFIG_MENDER_HTTP_PARSE_DATE_HEADER
    server_time = 0;
#endif

    mender_err_t                ret                = MENDER_FAIL;
    struct http_request         request            = { 0 };
    mender_http_request_context request_context    = { .callback = callback, .params = params, .ret = MENDER_OK };
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
    if (MENDER_OK != mender_net_get_host_port_url(path, http_config.host, &host, &port, &url)) {
        mender_log_error("Unable to retrieve host/port/url");
        goto END;
    }

    /* Configuration of the client */
    request.method      = http_method_to_zephyr_http_client_method(method);
    request.url         = url;
    request.host        = host;
    request.protocol    = "HTTP/1.1";
    request.payload     = payload;
    request.payload_len = (NULL != payload) ? strlen(payload) : 0;
    request.response    = http_response_cb;

    /* Set up HTTP parser callbacks to capture Retry-After header */
    static struct http_parser_settings parser_settings = {
        .on_header_field = on_header_field,
        .on_header_value = on_header_value,
    };
    request.http_cb = &parser_settings;

    if (NULL == (request.recv_buf = (uint8_t *)mender_malloc(mender_http_recv_buf_length))) {
        mender_log_error("Unable to allocate memory");
        goto END;
    }
    request.recv_buf_len = mender_http_recv_buf_length;

    /* Add headers */

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
    mender_free(host);
    mender_free(port);
    mender_free(url);
    mender_free(host_header);
    mender_free(auth_header);
    mender_free(signature_header);

    mender_free(request.recv_buf);

    /* Return MENDER_RETRY_ERROR if ret is MENDER_FAIL, otherwise return ret */
    return (MENDER_FAIL != ret) ? ret : MENDER_RETRY_ERROR;
}

mender_err_t
mender_http_artifact_download(const char *uri, mender_artifact_download_data_t *dl_data, int *status) {
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
    if (MENDER_OK != mender_net_get_host_port_url(uri, http_config.host, &host, &port, &url)) {
        mender_log_error("Unable to retrieve host/port/url");
        goto END;
    }

    /* Configuration of the client */
    request.method   = http_method_to_zephyr_http_client_method(MENDER_HTTP_GET);
    request.url      = url;
    request.host     = host;
    request.protocol = "HTTP/1.1";
    request.response = artifact_response_cb;
    if (NULL == (request.recv_buf = (uint8_t *)mender_malloc(mender_http_recv_buf_length))) {
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

    /* Artifact download failed*/
    if (MENDER_OK != dl_data->ret) {
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
    mender_free(host);
    mender_free(port);
    mender_free(url);
    mender_free(host_header);

    mender_free(request.recv_buf);

    /* Return MENDER_RETRY_ERROR if ret is MENDER_FAIL, otherwise return ret */
    return (MENDER_FAIL != ret) ? ret : MENDER_RETRY_ERROR;
}

mender_err_t
mender_http_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}

static HTTP_CALLBACK_RETURN_TYPE
http_response_cb(struct http_response *response, MENDER_ARG_UNUSED enum http_final_call final_call, void *user_data) {
    assert(NULL != response);
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
    return HTTP_CALLBACK_RETURN_VALUE;
}

static HTTP_CALLBACK_RETURN_TYPE
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
    return HTTP_CALLBACK_RETURN_VALUE;
}

static enum http_method
http_method_to_zephyr_http_client_method(mender_http_method_t method) {

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

uint32_t
mender_http_get_retry_interval(void) {
    return retry_after_seconds;
}
