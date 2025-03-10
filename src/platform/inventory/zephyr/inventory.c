/**
 * @file      inventory.c
 * @brief     Mender inventory code for Zephyr platform
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

#include <zephyr/net/net_if.h>
#include <zephyr/version.h> /* a file generated during build */

#include "alloc.h"
#include "inventory.h"
#include "log.h"
#include "utils.h"

#ifdef CONFIG_MENDER_CLIENT_INVENTORY_BUILD_INFO
static mender_err_t
build_info_callback(mender_keystore_t **inventory, uint8_t *inventory_len) {
    static mender_keystore_t build_info[] = {
        { "mender_client", "Mender MCU client (Zephyr)" },
        { "mender_client_version", MENDER_CLIENT_VERSION },
        { "zephyr_version", KERNEL_VERSION_STRING },
    };
    *inventory     = build_info;
    *inventory_len = 3;

    return MENDER_OK;
}
#endif /* CONFIG_MENDER_CLIENT_INVENTORY_BUILD_INFO */

#ifdef CONFIG_MENDER_CLIENT_INVENTORY_NETWORK_INFO
static mender_err_t
network_info_callback(mender_keystore_t **inventory, uint8_t *inventory_len) {
    mender_keystore_t *network_info = NULL;
    struct net_if     *iface        = NULL;
    const char        *ifname       = NULL;

    if (NULL == (iface = net_if_get_default())) {
        mender_log_debug("No network interface");
        return MENDER_FAIL;
    }
    ifname = net_if_get_device(iface)->name;

    network_info = mender_calloc(4, sizeof(mender_keystore_t));
    if (NULL == network_info) {
        mender_log_error("Unable to allocate memory");
        goto ERR;
    }

    /* Default interface name */
    network_info[0].name  = mender_utils_strdup("Default network interface");
    network_info[0].value = mender_utils_strdup(ifname);

    /* The first IP of the iface */
    if (mender_utils_asprintf(&(network_info[1].name), "IPv4[%s]", ifname) <= 0) {
        mender_log_error("Failed to construct network inventory data");
        goto ERR;
    }
    if (NULL == (network_info[1].value = mender_malloc(NET_IPV4_ADDR_LEN))) {
        mender_log_error("Unable to allocate memory");
        goto ERR;
    }
    if (NULL == net_addr_ntop(AF_INET, &iface->config.ip.ipv4->unicast[0].ipv4.address.in_addr, network_info[1].value, NET_IPV4_ADDR_LEN)) {
        mender_log_error("Failed to construct network inventory data");
        goto ERR;
    }

    /* Netmask of the first IP */
    if (mender_utils_asprintf(&(network_info[2].name), "Netmask[%s]", ifname) <= 0) {
        mender_log_error("Failed to construct network inventory data");
        goto ERR;
    }
    if (NULL == (network_info[2].value = mender_malloc(NET_IPV4_ADDR_LEN))) {
        mender_log_error("Unable to allocate memory");
        goto ERR;
    }
    if (NULL == net_addr_ntop(AF_INET, &iface->config.ip.ipv4->unicast[0].netmask, network_info[2].value, NET_IPV4_ADDR_LEN)) {
        mender_log_error("Failed to construct network inventory data");
        goto ERR;
    }

    /* Gateway */
    if (mender_utils_asprintf(&(network_info[3].name), "Gateway[%s]", ifname) <= 0) {
        mender_log_error("Failed to construct network inventory data");
        goto ERR;
    }
    if (NULL == (network_info[3].value = mender_malloc(NET_IPV4_ADDR_LEN))) {
        mender_log_error("Unable to allocate memory");
        goto ERR;
    }
    if (NULL == net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw, network_info[3].value, NET_IPV4_ADDR_LEN)) {
        mender_log_error("Failed to construct network inventory data");
        goto ERR;
    }

    /* Error cases jump over this */
    *inventory     = network_info;
    *inventory_len = 4;
    return MENDER_OK;

ERR:
    mender_utils_keystore_delete(network_info, 4);
    return MENDER_FAIL;
}
#endif /* CONFIG_MENDER_CLIENT_INVENTORY_NETWORK_INFO */

mender_err_t
mender_inventory_add_default_callbacks(void) {
    bool some_error = false;

#ifdef CONFIG_MENDER_CLIENT_INVENTORY_BUILD_INFO
    if (MENDER_OK != mender_inventory_add_callback(build_info_callback, true)) {
        mender_log_error("Failed to add build info inventory callback");
        some_error = true;
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY_BUILD_INFO */

#ifdef CONFIG_MENDER_CLIENT_INVENTORY_NETWORK_INFO
    /* Not a persistent callback -- DHCP lease expires and network config can
       change (plus we need to construct the data dynamically, see above). */
    if (MENDER_OK != mender_inventory_add_callback(network_info_callback, false)) {
        mender_log_error("Failed to add network info inventory callback");
        some_error = true;
    }
#endif /* CONFIG_MENDER_CLIENT_INVENTORY_NETWORK_INFO */

    return some_error ? MENDER_FAIL : MENDER_OK;
}
