/**
 * @file      alloc.c
 * @brief     Platform-independent parts of the Mender memory management implementation
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

#include <stdlib.h> /* malloc(),... */
#include <string.h> /* memset() */

#include <mender/alloc.h>

static MenderAllocator   malloc_fn  = NULL;
static MenderReallocator realloc_fn = NULL;
static MenderDeallocator free_fn    = NULL;

void
mender_set_allocation_funcs(MenderAllocator malloc_func, MenderReallocator realloc_func, MenderDeallocator free_func) {
    malloc_fn  = malloc_func;
    realloc_fn = realloc_func;
    free_fn    = free_func;
}

void *
mender_malloc(size_t size) {
    if (NULL == malloc_fn) {
        return malloc(size);
    }
    return malloc_fn(size);
}

void *
mender_calloc(size_t n, size_t size) {
    void *ret = mender_malloc(n * size);
    if (NULL != ret) {
        memset(ret, 0, n * size);
    }
    return ret;
}

void *
mender_realloc(void *ptr, size_t size) {
    if (NULL == realloc_fn) {
        return realloc(ptr, size);
    }
    return realloc_fn(ptr, size);
}

void
mender_free(void *ptr) {
    if (NULL == free_fn) {
        free(ptr);
        return;
    }
    free_fn(ptr);
}
