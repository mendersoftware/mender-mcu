/**
 * @file      mender-update-module.h
 * @brief     Mender Update Module interface
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

#ifndef __MENDER_UPDATE_MODULE_H__
#define __MENDER_UPDATE_MODULE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdbool.h>
#include <stdint.h>
#include <cJSON.h>

#include "mender-utils.h"

typedef enum mender_update_state_t {
    MENDER_UPDATE_STATE_DOWNLOAD = 0,
    MENDER_UPDATE_STATE_INSTALL,
    MENDER_UPDATE_STATE_REBOOT,
    MENDER_UPDATE_STATE_VERIFY_REBOOT,
    MENDER_UPDATE_STATE_COMMIT,
    MENDER_UPDATE_STATE_CLEANUP,
    MENDER_UPDATE_STATE_ROLLBACK,
    MENDER_UPDATE_STATE_ROLLBACK_REBOOT,
    MENDER_UPDATE_STATE_ROLLBACK_VERIFY_REBOOT,
    MENDER_UPDATE_STATE_FAILURE,
    MENDER_UPDATE_STATE_END
} mender_update_state_t;
#define N_MENDER_UPDATE_STATES ((size_t)MENDER_UPDATE_STATE_END)

/* The structs below are not supposed to be used directly, only as arguments
 * passed by in the union below. */
/**
 * @param id ID of the deployment
 * @param artifact name Artifact name
 * @param type Type from header-info payloads
 * @param meta_data Meta-data from header tarball
 * @param filename Artifact filename
 * @param size Artifact file size
 * @param data Artifact data
 * @param index Artifact data index
 * @param length Artifact data length
 */
struct mender_update_download_state_data_s {
    const char    *id;
    const char    *artifact_name;
    const char    *type;
    const cJSON   *meta_data;
    const char    *filename;
    size_t         size;
    const uint8_t *data;
    size_t         offset;
    size_t         length;
    bool           done;
};

struct mender_update_install_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

struct mender_update_reboot_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

struct mender_update_verify_reboot_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

struct mender_update_commit_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

struct mender_update_cleanup_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

struct mender_update_rollback_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

struct mender_update_rollback_reboot_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

struct mender_update_failure_state_data_s {
    /* TBD; a NULL pointer in the union below until there is something here */
};

/* The last member allows to type-cast NULL to mender_update_state_data_t,
 * otherwise we would have to type-cast NULL to one of the other member types
 * first. */
/* Should we just use (void *data) as parameter of the callbacks? */
typedef union mender_update_state_data_u {
    struct mender_update_download_state_data_s        *download_state_data;
    struct mender_update_install_state_data_s         *install_state_data;
    struct mender_update_reboot_state_data_s          *reboot_state_data;
    struct mender_update_verify_reboot_state_data_s   *verify_reboot_state_data;
    struct mender_update_commit_state_data_s          *commit_state_data;
    struct mender_update_cleanup_state_data_s         *cleanup_state_data;
    struct mender_update_rollback_state_data_s        *rollback_state_data;
    struct mender_update_rollback_reboot_state_data_s *rollback_reboot_state_data;
    struct mender_update_failure_state_data_s         *failure_state_data;
    void                                              *only_for_nicer_type_casting;
} mender_update_state_data_t;

typedef mender_err_t (*MenderUpdateStateCallback)(mender_update_state_t state, mender_update_state_data_t callback_data);

typedef struct mender_update_module_s {
    MenderUpdateStateCallback callbacks[N_MENDER_UPDATE_STATES];
    const char               *artifact_type;
    bool                      requires_reboot;
    bool                      supports_rollback;
} mender_update_module_t;

/**
 * @brief Register update module
 * @param update_module The update module to register
 * @return MENDER_OK if the function succeeds, error code otherwise
 * @note Takes ownership of #update_module in case of success
 */
mender_err_t mender_update_module_register(mender_update_module_t *update_module);

/**
 * @brief Unregister all registered update modules
 */
void mender_update_module_unregister_all(void);

/**
 * @brief Get update module for the given artifact type
 * @param artifact_type Artifact type to get the update module for
 * @return An update module or %NULL if no matching one found
 */
mender_update_module_t *mender_update_module_get(const char *artifact_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_UPDATE_MODULE_H__ */
