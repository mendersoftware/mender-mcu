/**
 * @file      mender-os.c
 * @brief     Mender OS interface for weak platform
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

#include "mender-os.h"
#include "mender-utils.h"

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_init(void) {
    /* Nothing to do */
    return MENDER_OK;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_work_create(MENDER_ARG_UNUSED mender_os_scheduler_work_params_t *work_params, MENDER_ARG_UNUSED mender_work_t **work) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_work_activate(MENDER_ARG_UNUSED mender_work_t *work) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_work_set_period(MENDER_ARG_UNUSED mender_work_t *work, MENDER_ARG_UNUSED uint32_t period) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_work_execute(MENDER_ARG_UNUSED mender_work_t *work) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_work_deactivate(MENDER_ARG_UNUSED mender_work_t *work) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_work_delete(MENDER_ARG_UNUSED mender_work_t *work) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_mutex_create(void **handle) {

    (void)handle;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_mutex_take(void *handle, int32_t delay_ms) {

    (void)handle;
    (void)delay_ms;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_mutex_give(void *handle) {

    (void)handle;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_mutex_delete(void *handle) {

    (void)handle;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_os_scheduler_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}

MENDER_FUNC_WEAK void
mender_os_reboot(void) {
    return;
}
