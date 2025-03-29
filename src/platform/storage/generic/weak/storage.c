/**
 * @file      storage.c
 * @brief     Mender storage interface for weak platform
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

#include "log.h"
#include "storage.h"

MENDER_FUNC_WEAK mender_err_t
mender_storage_init(void) {

    /* Nothing to do */
    return MENDER_OK;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_set_authentication_keys(unsigned char *private_key, size_t private_key_length, unsigned char *public_key, size_t public_key_length) {

    (void)private_key;
    (void)private_key_length;
    (void)public_key;
    (void)public_key_length;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_get_authentication_keys(unsigned char **private_key, size_t *private_key_length, unsigned char **public_key, size_t *public_key_length) {

    (void)private_key;
    (void)private_key_length;
    (void)public_key;
    (void)public_key_length;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_delete_authentication_keys(void) {

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_set_deployment_data(char *deployment_data) {

    (void)deployment_data;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_get_deployment_data(char **deployment_data) {

    (void)deployment_data;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_delete_deployment_data(void) {

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_set_provides(mender_key_value_list_t *provides) {

    (void)provides;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_get_provides(mender_key_value_list_t **provides) {

    (void)provides;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_set_artifact_name(const char *artifact_name) {

    (void)artifact_name;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_get_artifact_name(const char **artifact_name) {

    (void)artifact_name;

    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
MENDER_FUNC_WEAK mender_err_t
mender_storage_deployment_log_append(MENDER_ARG_UNUSED const char *msg, MENDER_ARG_UNUSED size_t msg_size) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_deployment_log_walk(MENDER_ARG_UNUSED MenderDeploymentLogVisitor visitor_fn, MENDER_ARG_UNUSED void *ctx) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}

MENDER_FUNC_WEAK mender_err_t
mender_storage_deployment_log_clear(void) {
    /* Nothing to do */
    return MENDER_NOT_IMPLEMENTED;
}
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

MENDER_FUNC_WEAK mender_err_t
mender_storage_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}
