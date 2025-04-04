/**
 * @file      certs.h
 * @brief     Mender MCU Certificate (private API)
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

#ifndef __MENDER_CERTS_PRIV_H__
#define __MENDER_CERTS_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "utils.h"

/**
 * @brief Add dormant certificate for potential disaster recovery scenarios
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_add_dormant_cert(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_CERTS_PRIV_H__ */
