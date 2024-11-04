/**
 * @file      mender-scheduler.c
 * @brief     Mender scheduler interface for Zephyr platform
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

#ifdef CONFIG_MENDER_CLIENT_INVENTORY
#error This stable branch does not work with Inventory
#endif /* CONFIG_MENDER_CLIENT_INVENTORY */

#include <zephyr/kernel.h>
#include "mender-log.h"
#include "mender-scheduler.h"
#include "mender-utils.h"

#ifdef CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE
/**
 * @brief Default work queue stack size (kB)
 */
#ifndef CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE
#define CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE (12)
#endif /* CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE */

/**
 * @brief Default work queue priority
 */
#ifndef CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY
#define CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY (5)
#endif /* CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY */

/**
 * @brief Mender scheduler work queue
 */
static struct k_work_q work_queue;

/**
 * @brief Mender scheduler work queue stack
 */
K_THREAD_STACK_DEFINE(work_queue_stack, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE * 1024);
#endif /* CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE */

/**
 * @brief User parameters
 */
static mender_scheduler_work_function_t user_function = NULL;
static uint32_t                         user_interval = 0;

/**
 * @brief Work item
 */
static struct k_work_delayable delayable_work_item;

static void
mender_work_function(MENDER_ARG_UNUSED struct k_work *work) {
    assert(NULL != user_function);

    MENDER_NDEBUG_UNUSED mender_err_t status = (*user_function)();
    mender_log_debug("Executed work function [%d]", status);

#ifdef CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE
    k_work_reschedule_for_queue(&work_queue, &delayable_work_item, K_SECONDS(user_interval));
#else
    k_work_reschedule(&delayable_work_item, K_SECONDS(user_interval));
#endif /* CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE */
}

mender_err_t
mender_scheduler_init(void) {
#ifdef CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE
    /* Create and start work queue */
    k_work_queue_init(&work_queue);
    k_work_queue_start(&work_queue, work_queue_stack, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE * 1024, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY, NULL);
    k_thread_name_set(k_work_queue_thread_get(&work_queue), "mender_scheduler_work_queue");
#endif /* CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE */

    return MENDER_OK;
}

/**
 * @brief Start work
 */
mender_err_t
mender_scheduler_activate(mender_scheduler_work_function_t main_work_func, uint32_t interval) {
    assert(NULL != main_work_func);
    assert(0 != interval);

    user_function = main_work_func;
    user_interval = interval;

    k_work_init_delayable(&delayable_work_item, mender_work_function);

#ifdef CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE
    k_work_reschedule_for_queue(&work_queue, &delayable_work_item, K_NO_WAIT);
#else
    k_work_reschedule(&delayable_work_item, K_SECONDS(1));
#endif /* CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE */

    return MENDER_OK;
}

mender_err_t
mender_scheduler_exit(void) {
    k_work_cancel_delayable(&delayable_work_item);

#ifdef CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE
    k_work_queue_drain(&work_queue, true);
#endif /* CONFIG_MENDER_SCHEDULER_SEPARATE_WORK_QUEUE */

    return MENDER_OK;
}

mender_err_t
mender_scheduler_mutex_create(void **handle) {
    assert(NULL != handle);

    /* Create mutex */
    if (NULL == (*handle = malloc(sizeof(struct k_mutex)))) {
        return MENDER_FAIL;
    }
    if (0 != k_mutex_init((struct k_mutex *)(*handle))) {
        FREE_AND_NULL(*handle);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_scheduler_mutex_take(void *handle, int32_t delay_ms) {
    assert(NULL != handle);

    /* Take mutex */
    if (0 != k_mutex_lock((struct k_mutex *)handle, (delay_ms >= 0) ? K_MSEC(delay_ms) : K_FOREVER)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_scheduler_mutex_give(void *handle) {
    assert(NULL != handle);

    /* Give mutex */
    if (0 != k_mutex_unlock((struct k_mutex *)handle)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_scheduler_mutex_delete(void *handle) {

    /* Release memory */
    free(handle);

    return MENDER_OK;
}
