/**
 * @file      alloc.c
 * @brief     Zephyr-specific implementation of the Mender memory management functions
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

#include <zephyr/kernel.h>

#include <mender/alloc.h>

#ifdef CONFIG_MENDER_SEPARATE_HEAP
K_HEAP_DEFINE(mender_heap, CONFIG_MENDER_HEAP_SIZE * 1024);
#endif

static void *
mender_zephyr_malloc(size_t size) {
#ifdef CONFIG_MENDER_SEPARATE_HEAP
    return k_heap_alloc(&mender_heap, size, K_NO_WAIT);
#else
    return k_malloc(size);
#endif
}

static void *
mender_zephyr_realloc(void *ptr, size_t size) {
#ifdef CONFIG_MENDER_SEPARATE_HEAP
    return k_heap_realloc(&mender_heap, ptr, size, K_NO_WAIT);
#else
    return k_realloc(ptr, size);
#endif
}

static void
mender_zephyr_free(void *ptr) {
#ifdef CONFIG_MENDER_SEPARATE_HEAP
    k_heap_free(&mender_heap, ptr);
#else
    k_free(ptr);
#endif
}

void
mender_set_platform_allocation_funcs(void) {
    mender_set_allocation_funcs(mender_zephyr_malloc, mender_zephyr_realloc, mender_zephyr_free);
}
