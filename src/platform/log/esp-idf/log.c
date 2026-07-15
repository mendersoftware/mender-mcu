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

mender_err_t
mender_log_init(void) {
    /* Nothing to do */
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

    ESP_LOG_LEVEL(esp_level, "mender", "%s:%d: %s", function, line, msg);

    return MENDER_OK;
}

mender_err_t
mender_log_exit(void) {
    /* Nothing to do */
    return MENDER_OK;
}
