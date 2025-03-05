/**
 * @file      client.h
 * @brief     Mender MCU client implementation (private API)
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

#ifndef __MENDER_CLIENT_PRIV_H__
#define __MENDER_CLIENT_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mender/client.h>

/**
 * @brief Mender client states
 */
typedef enum {
    MENDER_CLIENT_STATE_INITIALIZATION, /**< Perform initialization */
    MENDER_CLIENT_STATE_OPERATIONAL,    /**< Under standard operation */
    MENDER_CLIENT_STATE_PENDING_REBOOT, /**< Waiting for a reboot */
} mender_client_state_t;
#define N_MENDER_CLIENT_STATES ((size_t)MENDER_CLIENT_STATE_PENDING_REBOOT)

/**
 * @brief Mender client state
 */
extern mender_client_state_t mender_client_state;

/**
 * @brief  Ensures the client has a network connection
 * @return MENDER_DONE if already connected,
 *         MENDER_OK if successfully connected,
 *         MENDER_FAIL otherwise
 */
mender_err_t mender_client_ensure_connected(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_CLIENT_PRIV_H__ */
