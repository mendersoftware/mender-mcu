/**
 * @file      log.c
 * @brief     Mender logging interface for Posix platform
 *
 * Copyright joelguittet and mender-mcu-client contributors
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

#include <time.h>
#include "log.h"

static mender_err_t
default_mender_log_init(void) {

    /* Nothing to do */
    return MENDER_OK;
}

static mender_err_t
default_mender_log_print(uint8_t level, const char *filename, const char *function, int line, char *format, ...) {

    (void)function;
    struct timespec now;
    char            log[256] = { 0 };

    /* Get time */
    clock_gettime(CLOCK_REALTIME, &now);

    /* Format message */
    va_list args;
    va_start(args, format);
    vsnprintf(log, sizeof(log), format, args);
    va_end(args);

    /* Switch depending log level */
    switch (level) {
        case MENDER_LOG_LEVEL_ERR:
            printf("[%ld] <err> %s (%d): %s\n", now.tv_sec, filename, line, log);
            break;
        case MENDER_LOG_LEVEL_WRN:
            printf("[%ld] <war> %s (%d): %s\n", now.tv_sec, filename, line, log);
            break;
        case MENDER_LOG_LEVEL_INF:
            printf("[%ld] <inf> %s (%d): %s\n", now.tv_sec, filename, line, log);
            break;
        case MENDER_LOG_LEVEL_DBG:
            printf("[%ld] <dbg> %s (%d): %s\n", now.tv_sec, filename, line, log);
            break;
        default:
            break;
    }

    return MENDER_OK;
}

static mender_err_t
default_mender_log_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
static mender_err_t
default_mender_deployment_logs_activate(void) {
    /* Default activation logic */
    return MENDER_OK;
}

static mender_err_t
default_mender_deployment_logs_deactivate(void) {
    /* Default deactivation logic */
    return MENDER_OK;
}
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

mender_log_t mender_log = {
    .init  = default_mender_log_init,
    .exit  = default_mender_log_exit,
    .print = default_mender_log_print,
#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
    .deployment_logs_activate   = default_mender_deployment_logs_activate,
    .deployment_logs_deactivate = default_mender_deployment_logs_deactivate,
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */
};
