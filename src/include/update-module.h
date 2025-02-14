/**
 * @file      update-module.h
 * @brief     Mender Update Module interface (private API)
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

#ifndef __MENDER_UPDATE_MODULE_PRIV_H__
#define __MENDER_UPDATE_MODULE_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mender/update-module.h>

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

#endif /* __MENDER_UPDATE_MODULE_PRIV_H__ */
