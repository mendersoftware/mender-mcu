/**
 * @file      utils.h
 * @brief     Mender utility functions (public API)
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

#ifndef __MENDER_UTILS_H__
#define __MENDER_UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <cJSON.h>

#include <mender/alloc.h>

/**
 * @brief A utility macro to make marking unused arguments less noisy/disruptive
 */
#define MENDER_ARG_UNUSED __attribute__((unused))

/**
 * For variables only used in debug builds, in particular only in assert()
 * calls, use MENDER_NDEBUG_UNUSED.
 */
#ifdef NDEBUG
#define MENDER_NDEBUG_UNUSED __attribute__((unused))
#else
#define MENDER_NDEBUG_UNUSED
#endif

/**
 * @brief A utility macro to make marking weak functions less noisy/disruptive
 */
#define MENDER_FUNC_WEAK __attribute__((weak))

/**
 * @brief Mender error codes
 */
typedef enum {
    MENDER_DONE            = 1,  /**< Done */
    MENDER_OK              = 0,  /**< OK */
    MENDER_FAIL            = -1, /**< Failure */
    MENDER_NOT_FOUND       = -2, /**< Not found */
    MENDER_NOT_IMPLEMENTED = -3, /**< Not implemented */
    MENDER_LOOP_DETECTED   = -4, /**< Loop detected */
    MENDER_LOCK_FAILED     = -5, /**< Locking failed */
    MENDER_ABORTED         = -6, /**< Aborted */
    MENDER_RETRY_ERROR     = -7, /**< Retry error */
} mender_err_t;

#define MENDER_IS_ERROR(err_t_ret) ((err_t_ret) < 0)

/**
 * @brief Deployment status
 */
typedef enum {
    MENDER_DEPLOYMENT_STATUS_DOWNLOADING,      /**< Status is "downloading" */
    MENDER_DEPLOYMENT_STATUS_INSTALLING,       /**< Status is "installing" */
    MENDER_DEPLOYMENT_STATUS_REBOOTING,        /**< Status is "rebooting" */
    MENDER_DEPLOYMENT_STATUS_SUCCESS,          /**< Status is "success" */
    MENDER_DEPLOYMENT_STATUS_FAILURE,          /**< Status is "failure" */
    MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED /**< Status is "already installed" */
} mender_deployment_status_t;

/**
 * @brief Item struct
 */
typedef struct {
    char *name;  /**< Name of the item */
    char *value; /**< Value of the item */
} mender_item_t;

/**
 * @brief Key-store
 */
typedef mender_item_t mender_keystore_t;

/**
 * @brief Identity
 */
typedef mender_item_t mender_identity_t;

/**
 * @brief Function used to print deployment status as string
 * @param deployment_status Deployment status
 * @return Deployment status as string, NULL if it is not found
 */
const char *mender_utils_deployment_status_to_string(mender_deployment_status_t deployment_status);

/**
 * @brief Duplicate string using Mender memory allocation
 */
char *mender_utils_strdup(const char *str);
char *mender_utils_strndup(const char *str, size_t n);

/**
 * @brief Format a new string using Mender memory allocation
 */
int mender_utils_asprintf(char **result, const char *fmt, ...);
int mender_utils_vasprintf(char **result, const char *fmt, va_list ap);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_UTILS_H__ */
