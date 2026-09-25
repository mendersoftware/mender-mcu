/**
 * @file      log.c
 * @brief     Mender logging interface for ESP-IDF
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

#include <stdarg.h>
#include <stdio.h>

#include "esp_log.h"

#include "log.h"

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "storage.h"

/* Keep in sync with the related constant in storage.c (+1 byte for the
   terminating '\0'). Slightly generous on purpose: the storage backend
   truncates further if needed. */
#define DEPL_LOGS_MAX_MSG_SIZE 255

/**
 * @brief The previous log output function, so it can still be used (and restored)
 */
static vprintf_like_t prev_vprintf_func = NULL;

/**
 * @brief Format the current wall-clock time as an ISO8601 UTC timestamp (the server requires it)
 * @note Unlike Zephyr, ESP-IDF's own logging has no ISO8601 timestamp option (and the tick count
 *       it does embed in log lines is uptime, not epoch time, so it can't just be reformatted).
 *       This queries the system time directly instead; it is only meaningful once that has been
 *       set (e.g. via SNTP), same caveat as Zephyr's own ISO8601 timestamps.
 * @param buf Buffer to write the timestamp to
 * @param buf_size Size of #buf
 * @return true if #buf was filled in, false on failure (e.g. no time source available), in which
 *         case #buf is left untouched and the caller should fall back to not having a timestamp
 */
static bool
depl_logs_iso8601_timestamp(char *buf, size_t buf_size) {
    struct timeval tv;
    if (0 != gettimeofday(&tv, NULL)) {
        return false;
    }
    struct tm tm_info;
    if (NULL == gmtime_r(&tv.tv_sec, &tm_info)) {
        return false;
    }
    size_t len = strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%S", &tm_info);
    if ((0 == len) || ((buf_size - len) <= sizeof(".000Z"))) {
        return false;
    }
    snprintf(buf + len, buf_size - len, ".%03ldZ", (long)(tv.tv_usec / 1000));
    return true;
}

/**
 * @brief Log output function capturing warning/error messages into the deployment logs storage
 * @note Installed via esp_log_set_vprintf() while a deployment log capture is active. As noted by
 *       the esp_log_set_vprintf() documentation, this can be invoked in parallel from multiple
 *       tasks; #mender_storage_deployment_log_append is expected to tolerate that the same way
 *       the ESP-IDF logging subsystem itself does (single global lock around output).
 */
static int
depl_logs_vprintf(const char *fmt, va_list args) {
    char    msg[DEPL_LOGS_MAX_MSG_SIZE];
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(msg, sizeof(msg), fmt, args_copy);
    va_end(args_copy);

    if (len > 0) {
        size_t      msg_len = MIN((size_t)len, sizeof(msg) - 1);
        const char *start   = msg;

        /* Skip a leading ANSI color escape sequence, if present (CONFIG_LOG_COLORS). */
        if ('\033' == *start) {
            const char *color_end = (const char *)memchr(start, 'm', msg_len);
            if (NULL != color_end) {
                msg_len -= (size_t)(color_end + 1 - start);
                start = color_end + 1;
            }
        }

        /* Deployment logs only care about warnings and errors. */
        if (('E' == *start) || ('W' == *start)) {
            char  level_char = *start;
            char *end        = (char *)start + msg_len;

            /* Strip trailing newline(s) first: the byte order is
               "<message>\033[0m\n", so the reset sequence is only at the very
               end once the newline(s) are gone. */
            while ((end > start) && (('\n' == *(end - 1)) || ('\r' == *(end - 1)))) {
                end--;
            }
            /* Strip a trailing ANSI reset sequence, if present. */
            static const char reset[]   = "\033[0m";
            size_t            reset_len = sizeof(reset) - 1;
            if (((size_t)(end - start) >= reset_len) && (0 == memcmp(end - reset_len, reset, reset_len))) {
                end -= reset_len;
            }
            *end = '\0';

            /* ESP-IDF's default log format is "<E/W/...> (<ticks>) <tag>: <message>".
               append_depl_log_msg() (src/core/api.c) expects
               "[<timestamp>] <<level>> <tag>: <message>" (as produced by Zephyr's
               logging, e.g. "[2024-05-20T13:45:30.123Z] <err> mender: ..."); reformat
               to match, using a single-character level and an ISO8601 timestamp
               (the Mender server requires ISO8601) in place of the tick count. */
            const char *paren_close = strchr(start, ')');
            char        formatted[DEPL_LOGS_MAX_MSG_SIZE];
            const char *to_store = start;
            if (NULL != paren_close) {
                const char *rest = paren_close + 1;
                if (' ' == *rest) {
                    rest++;
                }
                char timestamp[32];
                if (depl_logs_iso8601_timestamp(timestamp, sizeof(timestamp))) {
                    int written = snprintf(formatted, sizeof(formatted), "[%s] <%c> %s", timestamp, level_char, rest);
                    if (written > 0) {
                        to_store = formatted;
                    }
                }
                /* else: no usable timestamp, fall back to storing the raw ESP-IDF line as-is */
            }

            MENDER_NDEBUG_UNUSED mender_err_t ret = mender_storage_deployment_log_append(to_store, strlen(to_store) + 1);
            assert(MENDER_OK == ret);
        }
    }

    return (NULL != prev_vprintf_func) ? prev_vprintf_func(fmt, args) : vprintf(fmt, args);
}

mender_err_t
mender_deployment_logs_activate(void) {
    prev_vprintf_func = esp_log_set_vprintf(depl_logs_vprintf);
    return MENDER_OK;
}

mender_err_t
mender_deployment_logs_deactivate(void) {
    /* Make sure multiple calls to deactivate() don't cause issues. */
    if (NULL != prev_vprintf_func) {
        esp_log_set_vprintf(prev_vprintf_func);
        prev_vprintf_func = NULL;
    }
    return MENDER_OK;
}
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

mender_err_t
mender_log_init(void) {
    static const esp_log_level_t levels[] = { ESP_LOG_NONE, ESP_LOG_ERROR, ESP_LOG_WARN, ESP_LOG_INFO, ESP_LOG_DEBUG };
    esp_log_level_set("mender", levels[CONFIG_MENDER_LOG_LEVEL]);
    return MENDER_OK;
}

mender_err_t
mender_log_print(uint8_t level, MENDER_ARG_UNUSED const char *filename, const char *function, int line, char *format, ...) {
    char    msg[256] = "";
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    esp_log_level_t esp_level;
    switch (level) {
        case MENDER_LOG_LEVEL_ERR:
            esp_level = ESP_LOG_ERROR;
            break;
        case MENDER_LOG_LEVEL_WRN:
            esp_level = ESP_LOG_WARN;
            break;
        case MENDER_LOG_LEVEL_DBG:
            esp_level = ESP_LOG_DEBUG;
            break;
        case MENDER_LOG_LEVEL_INF:
        default:
            esp_level = ESP_LOG_INFO;
            break;
    }

    ESP_LOG_LEVEL_LOCAL(esp_level, "mender", "%s:%d: %s", function, line, msg);

    return MENDER_OK;
}

mender_err_t
mender_log_exit(void) {
    /* Nothing to do */
    return MENDER_OK;
}
