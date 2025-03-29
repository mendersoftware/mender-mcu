/**
 * @file      log.c
 * @brief     Mender logging interface for Zephyr platform
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

#include <zephyr/logging/log.h>

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
#include <zephyr/logging/log_backend.h>
#include <zephyr/logging/log_backend_std.h>
#include <zephyr/logging/log_output.h>

#include "storage.h"
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

/* XXX: Cannot #include "log.h" here because LOG_MODULE_DECLARE() and
        LOG_MODULE_REGISTER() cannot be present in the same source file
        (compilation unit).  */

#include "utils.h"

LOG_MODULE_REGISTER(mender, CONFIG_MENDER_LOG_LEVEL);

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS

/* The deployment logs API
   (https://docs.mender.io/api/#device-api-deployments-schemas-deploymentlog)
   requires an ISO8601 timestamp. */
#ifndef CONFIG_LOG_OUTPUT_FORMAT_ISO8601_TIMESTAMP
#error Mender Deployment Logs require ISO8601 timestamps (LOG_OUTPUT_FORMAT_ISO8601_TIMESTAMP)
#endif

/* XXX: keep in sync with the related constant in storage.c (+1 byte for the
        terminating '\0')*/
#define DEPL_LOGS_MAX_MSG_SIZE 256

static int depl_logs_log(uint8_t *data, size_t length, void *ctx);

static uint8_t msg_buf[DEPL_LOGS_MAX_MSG_SIZE];
LOG_OUTPUT_DEFINE(depl_log_output, depl_logs_log, msg_buf, sizeof(msg_buf));

static uint8_t msg_tmp[sizeof(msg_buf)];
static uint8_t msg_tmp_idx = 0;

static void panic(struct log_backend const *const backend);
static void dropped(const struct log_backend *const backend, uint32_t cnt);
static void process(const struct log_backend *const backend, union log_msg_generic *msg);

static const struct log_backend_api log_backend_depl_logs_api = {
    .process = process,
    .panic   = panic,
    .dropped = dropped,
};

LOG_BACKEND_DEFINE(log_backend_mender_depl_logs, log_backend_depl_logs_api, false /* autostart */);
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

mender_err_t
mender_log_init(void) {

    /* Nothing to do */
    return MENDER_OK;
}

mender_err_t
mender_log_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
mender_err_t
mender_deployment_logs_activate(void) {
    log_backend_activate(&log_backend_mender_depl_logs, NULL);
    return MENDER_OK;
}

mender_err_t
mender_deployment_logs_deactivate(void) {
    MENDER_NDEBUG_UNUSED mender_err_t ret;

    /* In case there is an incomplete log message, save it. */
    if (0 != msg_tmp_idx) {
        msg_tmp[msg_tmp_idx++] = '\0';
        ret                    = mender_storage_deployment_log_append((const char *)msg_tmp, msg_tmp_idx);
        assert(MENDER_OK == ret);
        msg_tmp_idx = 0;
    }

    log_backend_deactivate(&log_backend_mender_depl_logs);
    return MENDER_OK;
}

static int
depl_logs_log(uint8_t *data, size_t length, MENDER_ARG_UNUSED void *ctx) {
    MENDER_NDEBUG_UNUSED mender_err_t ret;

    /* This function can be called even for every character of a log message logged. */
    for (uint8_t i = 0; i < length; i++) {
        if ('\r' == (char)data[i]) {
            /* throw away carriage-returns */
            continue;
        } else if ('\n' == (char)data[i]) {
            /* newline terminates a log message */
            msg_tmp[msg_tmp_idx++] = '\0';
            ret                    = mender_storage_deployment_log_append((const char *)msg_tmp, msg_tmp_idx);
            assert(MENDER_OK == ret);
            msg_tmp_idx = 0;
        } else {
            /* just append the character to the message being constructed */
            msg_tmp[msg_tmp_idx++] = data[i];
        }
    }

    /* This function ought to return the number of bytes processed so even in
       case of a failure we have no other choice. */
    return length;
}

static void
panic(struct log_backend const *const backend) {
    log_backend_deactivate(backend);
}

static void
dropped(MENDER_ARG_UNUSED const struct log_backend *const backend, uint32_t cnt) {
    log_output_dropped_process(&depl_log_output, cnt);
}

static void
process(MENDER_ARG_UNUSED const struct log_backend *const backend, union log_msg_generic *msg) {
    /* We only care about warning and error log messages */
    if (msg->log.hdr.desc.level > LOG_LEVEL_WRN) {
        return;
    }

    uint32_t          flags           = log_backend_std_get_flags() & ~LOG_OUTPUT_FLAG_COLORS;
    log_format_func_t log_format_func = log_format_func_t_get(LOG_OUTPUT_TEXT);

    log_format_func(&depl_log_output, &msg->log, flags);
}
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */
