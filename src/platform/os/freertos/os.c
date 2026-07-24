/**
 * @file      os.c
 * @brief     Mender OS interface for FreeRTOS platform
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

#include <inttypes.h>

#include <FreeRTOS.h>
#include <task.h>
#include <queue.h>
#include <semphr.h>
#include <timers.h>

#include "alloc.h"
#include "log.h"
#include "os.h"
#include "utils.h"

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
#define CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY (tskIDLE_PRIORITY + 1)
#endif /* CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY */

/**
 * @brief Default work queue length
 */
#ifndef CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH
#define CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH (10)
#endif /* CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH */

/**
 * @brief Work context
 */
typedef struct mender_platform_work_t {
    mender_os_scheduler_work_params_t params;       /**< Work parameters */
    SemaphoreHandle_t                 sem_handle;   /**< Semaphore used to indicate work is pending or executing */
    TimerHandle_t                     timer_handle; /**< Timer used to periodically execute work */
    bool                              activated;    /**< Flag indicating the work is activated */
} mender_platform_work_t;

/**
 * @brief Timer callback used to enqueue work when the timer expires
 * @param timer_handle Timer handle
 */
static void mender_os_scheduler_timer_callback(TimerHandle_t timer_handle);

/**
 * @brief Callback pended on the timer daemon task to signal it has processed the timer delete command
 * @param sem_handle Semaphore to give
 * @param arg Not used
 */
static void mender_os_scheduler_timer_deleted_callback(void *sem_handle, uint32_t arg);

/**
 * @brief Task used to handle work queue
 * @param arg Not used
 */
static void mender_os_scheduler_work_queue_task(void *arg);

/**
 * @brief Work queue handle
 */
static QueueHandle_t mender_os_scheduler_work_queue_handle;

/**
 * @brief Semaphore given by the work queue task when it terminates
 */
static SemaphoreHandle_t mender_os_scheduler_exit_sem_handle;

mender_err_t
mender_os_scheduler_init(void) {

    /* Create work queue */
    mender_os_scheduler_work_queue_handle = xQueueCreate(CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH, sizeof(mender_platform_work_t *));
    if (NULL == mender_os_scheduler_work_queue_handle) {
        mender_log_error("Unable to create work queue");
        return MENDER_FAIL;
    }

    /* Create semaphore used to wait for the work queue task termination */
    mender_os_scheduler_exit_sem_handle = xSemaphoreCreateBinary();
    if (NULL == mender_os_scheduler_exit_sem_handle) {
        mender_log_error("Unable to create exit semaphore");
        DESTROY_AND_NULL(vQueueDelete, mender_os_scheduler_work_queue_handle);
        return MENDER_FAIL;
    }

    /* Create work queue task */
    if (pdPASS
        != xTaskCreate(mender_os_scheduler_work_queue_task,
                       "mender_work_queue",
                       (CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE * 1024) / sizeof(StackType_t),
                       NULL,
                       CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY,
                       NULL)) {
        mender_log_error("Unable to create work queue task");
        DESTROY_AND_NULL(vSemaphoreDelete, mender_os_scheduler_exit_sem_handle);
        DESTROY_AND_NULL(vQueueDelete, mender_os_scheduler_work_queue_handle);
        return MENDER_FAIL;
    }

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

    /* Copy work parameters.
     * Note: backoff parameters are ignored; failed work simply retries at its
     * regular period. Proper backoff and rate-limit handling is a follow-up. */
    work_context->params.function = work_params->function;
    work_context->params.period   = work_params->period;

    if (NULL == (work_context->params.name = mender_utils_strdup(work_params->name))) {
        mender_log_error("Unable to allocate memory");
        goto FAIL;
    }

    /* Create semaphore used to protect work function */
    work_context->sem_handle = xSemaphoreCreateBinary();
    if (NULL == work_context->sem_handle) {
        mender_log_error("Unable to create semaphore");
        goto FAIL;
    }

    /* Create auto-reload timer to handle the work periodically.
     * Use a period of 1 tick as placeholder; actual period is set on activation. */
    work_context->timer_handle = xTimerCreate(work_context->params.name, 1, pdTRUE, (void *)work_context, mender_os_scheduler_timer_callback);
    if (NULL == work_context->timer_handle) {
        mender_log_error("Unable to create timer");
        goto FAIL;
    }

    /* Return handle to the new work */
    *work = work_context;

    return MENDER_OK;

FAIL:

    /* Release resources */
    if (NULL != work_context) {
        if (NULL != work_context->timer_handle) {
            xTimerDelete(work_context->timer_handle, portMAX_DELAY);
        }
        if (NULL != work_context->sem_handle) {
            vSemaphoreDelete(work_context->sem_handle);
        }
        mender_free(work_context->params.name);
        mender_free(work_context);
    }

    return MENDER_FAIL;
}

mender_err_t
mender_os_scheduler_work_activate(mender_work_t *work) {
    assert(NULL != work);
    assert(0 != work->params.period);

    /* Ignore repeated activation; giving the semaphore again would allow the
     * same work to be enqueued twice, breaking the one-instance-in-flight
     * invariant the semaphore enforces */
    if (work->activated) {
        return MENDER_OK;
    }

    /* Give semaphore used to protect the work function */
    xSemaphoreGive(work->sem_handle);

    mender_log_debug("Activating %s every %" PRIu32 " seconds", work->params.name, work->params.period);

    /* Start the timer to handle the work. Convert directly to ticks;
     * pdMS_TO_TICKS(period * 1000) overflows 32 bits for periods
     * beyond ~12 hours (e.g. the default 7 day poll interval). */
    if (pdPASS != xTimerChangePeriod(work->timer_handle, (TickType_t)work->params.period * configTICK_RATE_HZ, portMAX_DELAY)) {
        mender_log_error("Unable to start timer");
        return MENDER_FAIL;
    }

    /* Execute the work now by enqueuing it */
    mender_os_scheduler_timer_callback(work->timer_handle);

    /* Indicate the work has been activated */
    work->activated = true;

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_execute(mender_work_t *work) {
    assert(NULL != work);

    /* Execute the work now by enqueuing it */
    mender_os_scheduler_timer_callback(work->timer_handle);

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_deactivate(mender_work_t *work) {
    assert(NULL != work);

    /* Check if the work was activated */
    if (work->activated) {

        /* Stop the timer used to periodically execute the work */
        xTimerStop(work->timer_handle, portMAX_DELAY);

        /* Wait if the work is pending or executing */
        if (pdTRUE != xSemaphoreTake(work->sem_handle, portMAX_DELAY)) {
            mender_log_error("Work '%s' is pending or executing", work->params.name);
            return MENDER_FAIL;
        }

        /* Indicate the work has been deactivated */
        work->activated = false;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_work_delete(mender_work_t *work) {
    /* Callers must deactivate the work first; the handshake below only guards
     * against the timer daemon race, not work still in the work queue */
    if (NULL == work) {
        return MENDER_OK;
    }

    if (NULL != work->timer_handle) {
        xTimerDelete(work->timer_handle, portMAX_DELAY);
        /* xTimerDelete only queues a command for the timer daemon task, and an
         * already-expired timer still runs its callback before the daemon
         * drains pending commands. Wait for the daemon to process the delete
         * (commands are FIFO, so our pended callback runs after it) before
         * freeing the work the callback would dereference. */
        xSemaphoreTake(work->sem_handle, 0);
        xTimerPendFunctionCall(mender_os_scheduler_timer_deleted_callback, work->sem_handle, 0, portMAX_DELAY);
        xSemaphoreTake(work->sem_handle, portMAX_DELAY);
    }
    if (NULL != work->sem_handle) {
        vSemaphoreDelete(work->sem_handle);
    }
    mender_free(work->params.name);
    mender_free(work);

    return MENDER_OK;
}

mender_err_t
mender_os_scheduler_exit(void) {

    /* Submit empty work to the work queue, this asks the work queue task to terminate */
    mender_platform_work_t *work = NULL;
    if (pdPASS != xQueueSend(mender_os_scheduler_work_queue_handle, &work, portMAX_DELAY)) {
        mender_log_error("Unable to submit empty work to the work queue");
        return MENDER_FAIL;
    }

    /* Wait for the task to signal its termination */
    xSemaphoreTake(mender_os_scheduler_exit_sem_handle, portMAX_DELAY);

    /* Clean up */
    DESTROY_AND_NULL(vSemaphoreDelete, mender_os_scheduler_exit_sem_handle);
    DESTROY_AND_NULL(vQueueDelete, mender_os_scheduler_work_queue_handle);

    return MENDER_OK;
}

static void
mender_os_scheduler_timer_callback(TimerHandle_t timer_handle) {
    /* Get work context */
    mender_platform_work_t *work = (mender_platform_work_t *)pvTimerGetTimerID(timer_handle);
    assert(NULL != work);

    /* Exit if the work is already pending or executing */
    if (pdTRUE != xSemaphoreTake(work->sem_handle, 0)) {
        mender_log_debug("Work '%s' is not activated, already pending or executing", work->params.name);
        return;
    }

    /* Submit the work to the work queue */
    if (pdPASS != xQueueSend(mender_os_scheduler_work_queue_handle, &work, 0)) {
        mender_log_warning("Unable to submit work '%s' to the work queue", work->params.name);
        xSemaphoreGive(work->sem_handle);
    }
}

static void
mender_os_scheduler_timer_deleted_callback(void *sem_handle, MENDER_ARG_UNUSED uint32_t arg) {
    xSemaphoreGive((SemaphoreHandle_t)sem_handle);
}

static void
mender_os_scheduler_work_queue_task(MENDER_ARG_UNUSED void *arg) {
    mender_platform_work_t *work = NULL;

    /* Handle work to be executed */
    while (pdTRUE == xQueueReceive(mender_os_scheduler_work_queue_handle, &work, portMAX_DELAY)) {

        /* Check if empty work is received from the work queue, this asks the work queue task to terminate */
        if (NULL == work) {
            goto END;
        }

        /* Call work function */
        mender_log_debug("Executing %s work", work->params.name);
        mender_err_t ret = work->params.function();

        if (MENDER_DONE == ret) {
            /* Nothing more to do, stop the periodic timer */
            xTimerStop(work->timer_handle, portMAX_DELAY);
        } else if (MENDER_OK != ret) {
            /* No backoff or rate-limit handling; the auto-reload timer retries
             * the work at its regular period. Proper backoff is a follow-up. */
            mender_log_error("Work %s failed, retrying in %" PRIu32 " seconds", work->params.name, work->params.period);
        }

        /* Release semaphore used to protect the work function */
        xSemaphoreGive(work->sem_handle);
    }

END:
    /* Signal the termination and terminate the work queue task; the semaphore
     * and queue are deleted by mender_os_scheduler_exit() after this point */
    xSemaphoreGive(mender_os_scheduler_exit_sem_handle);
    vTaskDelete(NULL);
}

mender_err_t
mender_os_mutex_create(void **handle) {
    assert(NULL != handle);

    /* Create mutex */
    *handle = (void *)xSemaphoreCreateMutex();
    if (NULL == *handle) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_mutex_take(void *handle, int32_t delay_ms) {
    assert(NULL != handle);

    /* Take mutex */
    TickType_t ticks = (delay_ms >= 0) ? pdMS_TO_TICKS((uint32_t)delay_ms) : portMAX_DELAY;
    if (pdTRUE != xSemaphoreTake((SemaphoreHandle_t)handle, ticks)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_mutex_give(void *handle) {
    assert(NULL != handle);

    /* Give mutex */
    if (pdTRUE != xSemaphoreGive((SemaphoreHandle_t)handle)) {
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_os_mutex_delete(void *handle) {

    /* Release mutex */
    if (NULL != handle) {
        vSemaphoreDelete((SemaphoreHandle_t)handle);
    }

    return MENDER_OK;
}

void
mender_os_sleep(uint32_t period_ms) {
    vTaskDelay(pdMS_TO_TICKS(period_ms));
}
