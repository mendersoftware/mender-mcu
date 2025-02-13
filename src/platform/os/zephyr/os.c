/**
 * @file      os.c
 * @brief     Mender OS interface for Zephyr platform
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

#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h> /* sys_reboot() */
#include "alloc.h"
#include "log.h"
#include "os.h"
#include "utils.h"

#ifdef CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE
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
 * @brief Mender scheduler work queue stack
 */
K_THREAD_STACK_DEFINE(work_queue_stack, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE * 1024);

/**
 * @brief Mender work queue
 */
static struct k_work_q            work_queue;
static struct k_work_queue_config work_queue_config;
#endif /* CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE */

/**
 * @brief Work context
 */
typedef struct mender_platform_work_t {
    mender_os_scheduler_work_params_t params;    /**< Work parameters */
    struct k_work_delayable           delayable; /**< The delayable work item executing the work function */
    bool                              activated; /**< Flag indicating the work is activated */
} mender_platform_work_t;

static void mender_os_scheduler_work_handler(struct k_work *work_item);

mender_err_t
mender_os_scheduler_init(void) {
#ifdef CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE
    /* Create and start work queue */
    work_queue_config.name      = "mender_work_queue";
    work_queue_config.no_yield  = false;
    work_queue_config.essential = true; /* TODO: configurable? */

    k_work_queue_init(&work_queue);
    k_work_queue_start(
        &work_queue, work_queue_stack, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE * 1024, CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY, &work_queue_config);
    k_thread_name_set(k_work_queue_thread_get(&work_queue), "mender_work_queue");
#endif /* CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE */

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_create(mender_os_scheduler_work_params_t *work_params, mender_work_t **work) {
    assert(NULL != work_params);
    assert(NULL != work_params->function);
    assert(NULL != work_params->name);
    assert(NULL != work);

    /* Create work context */
    mender_platform_work_t *work_context = mender_calloc(1, sizeof(mender_platform_work_t));
    if (NULL == work_context) {
        mender_log_error("Unable to allocate memory");
        goto FAIL;
    }

    /* Copy work parameters */
    work_context->params.function = work_params->function;
    work_context->params.period   = work_params->period;
    if (NULL == (work_context->params.name = mender_utils_strdup(work_params->name))) {
        mender_log_error("Unable to allocate memory");
        goto FAIL;
    }

    k_work_init_delayable(&(work_context->delayable), mender_os_scheduler_work_handler);

    /* Return handle to the new work context */
    *work = work_context;

    return MENDER_OK;

FAIL:

    /* Release memory */
    if (NULL != work_context) {
        mender_free(work_context->params.name);
        mender_free(work_context);
    }

    return MENDER_FAIL;
}

mender_err_t
mender_os_scheduler_work_activate(mender_work_t *work) {
    assert(NULL != work);
    assert(0 != work->params.period);

    mender_log_debug("Activating %s every %ju seconds", work->params.name, (uintmax_t)work->params.period);

#ifdef CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE
    k_work_reschedule_for_queue(&work_queue, &(work->delayable), K_NO_WAIT);
#else
    k_work_reschedule(&(work->delayable), K_SECONDS(1));
#endif /* CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE */

    /* Indicate the work has been activated */
    work->activated = true;

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_execute(mender_work_t *work) {
    assert(NULL != work);

#ifdef CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE
    k_work_reschedule_for_queue(&work_queue, &(work->delayable), K_NO_WAIT);
#else
    k_work_reschedule(&(work->delayable), K_NO_WAIT);
#endif /* CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE */

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_set_period(mender_work_t *work, uint32_t period) {
    assert(NULL != work);

    /* Set timer period */
    work->params.period = period;
    if (work->params.period > 0) {
#ifdef CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE
        k_work_reschedule_for_queue(&work_queue, &(work->delayable), K_SECONDS(period));
#else
        k_work_reschedule(&(work->delayable), K_SECONDS(period));
#endif /* CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE */
    } else {
        k_work_cancel_delayable(&(work->delayable));
        work->activated = false;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_deactivate(mender_work_t *work) {
    assert(NULL != work);

    /* Check if the work was activated */
    if (work->activated) {
        k_work_cancel_delayable(&(work->delayable));

        /* Indicate the work has been deactivated */
        work->activated = false;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_delete(mender_work_t *work) {
    if (NULL == work) {
        return MENDER_OK;
    }

    mender_free(work->params.name);
    mender_free(work);

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_exit(void) {
#ifdef CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE
    k_work_queue_drain(&work_queue, true);
#endif /* CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE */
    return MENDER_OK;
}

static void
mender_os_scheduler_work_handler(struct k_work *work_item) {
    assert(NULL != work_item);
    mender_err_t ret;

    /* Get work context */
    struct k_work_delayable *delayable_item = k_work_delayable_from_work(work_item);
    mender_platform_work_t  *work           = CONTAINER_OF(delayable_item, mender_platform_work_t, delayable);
    assert(NULL != work);

    if (!work->activated) {
        /* nothing more to do */
        return;
    }

    /* Call work function */
    mender_log_debug("Executing %s work", work->params.name);
    if (MENDER_DONE == (ret = work->params.function())) {
        /* nothing more to do */
        return;
    }
    if (MENDER_OK != ret) {
        mender_log_error("Work %s failed", work->params.name);
    }

    /* Reschedule self for the next period */
#ifdef CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE
    k_work_reschedule_for_queue(&work_queue, delayable_item, K_SECONDS(work->params.period));
#else
    k_work_reschedule(delayable_item, K_SECONDS(work->params.period));
#endif /* CONFIG_MENDER_OS_SEPARATE_WORK_QUEUE */
}

mender_err_t
mender_os_mutex_create(void **handle) {
    assert(NULL != handle);

    /* Create mutex */
    if (NULL == (*handle = mender_malloc(sizeof(struct k_mutex)))) {
        return MENDER_FAIL;
    }
    if (0 != k_mutex_init((struct k_mutex *)(*handle))) {
        FREE_AND_NULL(*handle);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_mutex_take(void *handle, int32_t delay_ms) {
    assert(NULL != handle);

    /* Take mutex */
    if (0 != k_mutex_lock((struct k_mutex *)handle, (delay_ms >= 0) ? K_MSEC(delay_ms) : K_FOREVER)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_mutex_give(void *handle) {
    assert(NULL != handle);

    /* Give mutex */
    if (0 != k_mutex_unlock((struct k_mutex *)handle)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_mutex_delete(void *handle) {

    /* Release memory */
    mender_free(handle);

    return MENDER_OK;
}

void
mender_os_reboot(void) {
    sys_reboot(SYS_REBOOT_WARM);
}
