/**
 * @file      mender-update-module.c
 * @brief     Mender update Module implementation
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

#include "mender-log.h"
#include "mender-update-module.h"

/**
 * @brief Mender update modules list
 */
static mender_update_module_t **update_modules_list  = NULL;
static size_t                   update_modules_count = 0;

mender_err_t
mender_update_module_register(mender_update_module_t *update_module) {
    assert(NULL != update_module);

    mender_update_module_t **tmp;
    mender_err_t             ret = MENDER_OK;

    /* Add mender artifact type to the list */
    if (NULL == (tmp = (mender_update_module_t **)realloc(update_modules_list, (update_modules_count + 1) * sizeof(mender_update_module_t *)))) {
        mender_log_error("Unable to allocate memory for update modules list");
        ret = MENDER_FAIL;
        goto END;
    }
    update_modules_list                         = tmp;
    update_modules_list[update_modules_count++] = update_module;
    ret                                         = MENDER_OK;

END:

    return ret;
}

void
mender_update_module_unregister_all(void) {
    if (NULL != update_modules_list) {
        for (size_t update_module_index = 0; update_module_index < update_modules_count; update_module_index++) {
            free(update_modules_list[update_module_index]);
        }
        FREE_AND_NULL(update_modules_list);
    }
    update_modules_count = 0;
}

mender_update_module_t *
mender_update_module_get(const char *artifact_type) {
    mender_update_module_t *ret = NULL;

    /* Treatment depending of the type */
    if (NULL != update_modules_list) {
        for (size_t update_module_index = 0; (NULL == ret) && (update_module_index < update_modules_count); update_module_index++) {
            /* Check artifact type */
            if (StringEqual(artifact_type, update_modules_list[update_module_index]->artifact_type)) {
                ret = update_modules_list[update_module_index];
            }
        }
    }

    return ret;
}
