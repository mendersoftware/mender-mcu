/**
 * @file      mender-alloc.h
 * @brief     Mender memory management functions
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

#ifndef __MENDER_ALLOC_H__
#define __MENDER_ALLOC_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stddef.h> /* size_t */

/**
 * Standard parameters and semantics apply to the three types and functions below.
 */
typedef void *(*MenderAllocator)(size_t size);
typedef void *(*MenderReallocator)(void *ptr, size_t size);
typedef void (*MenderDeallocator)(void *ptr);

void mender_set_allocation_funcs(MenderAllocator mender_malloc_func, MenderReallocator mender_realloc_func, MenderDeallocator free_func);
void mender_set_platform_allocation_funcs(void);

void *mender_malloc(size_t size);
void *mender_calloc(size_t n, size_t size);
void *mender_realloc(void *ptr, size_t size);
void  mender_free(void *ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_ALLOC_H__ */