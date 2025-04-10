/**
 * @file      net.h
 * @brief     Mender network common file interface for Zephyr platform
 *
 * Copyright joelguittet and mender-mcu-client contributors
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

#ifndef __MENDER_NET_H__
#define __MENDER_NET_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "utils.h"

/**
 * @brief Returns host name, port and URL from path
 * @param path Path
 * @param config_host Host name from configuration
 * @param host Host name
 * @param port Port as string
 * @param url URL
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_net_get_host_port_url(const char *path, char *config_host, char **host, char **port, char **url);

/**
 * @brief Add a header to the header list
 * @param header_list Header list
 * @param header_list_size Header list size
 * @param header Header to add
 * @return MENDER_OK if the function succeeds, MENDER_FAIL otherwise
 */
mender_err_t header_add(const char **header_list, size_t header_list_size, const char *header);

/**
 * @brief Allocate and add a header to the header list
 * @param header_list Header list
 * @param header_list_size Header list size
 * @param format Format string
 * @return Pointer to the allocated string if the function succeeds, NULL otherwise
 */
char *header_alloc_and_add(const char **header_list, size_t header_list_size, const char *format, ...);

/**
 * @brief Perform connection with the server
 * @param host Host
 * @param port Port
 * @return socket descriptor if the function succeeds, -1 otherwise
 */
int mender_net_connect(const char *host, const char *port);

/**
 * @brief Close connection with the server
 * @param sock Client socket
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_net_disconnect(int sock);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_NET_H__ */
