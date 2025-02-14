/**
 * @file      alloc.h
 * @brief     Mender memory management functions (private API)
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

#ifndef __MENDER_ALLOC_PRIV_H__
#define __MENDER_ALLOC_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mender/alloc.h>

/**
 * @brief Set platform-specific memory allocation functions (if any)
 */
void mender_set_platform_allocation_funcs(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_ALLOC_PRIV_H__ */
