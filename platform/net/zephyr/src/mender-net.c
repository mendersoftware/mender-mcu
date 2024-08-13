/**
 * @file      mender-net.c
 * @brief     Mender network common file for Zephyr platform
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

#include <errno.h>
#include <zephyr/net/socket.h>
#ifdef CONFIG_NET_SOCKETS_SOCKOPT_TLS
#include <zephyr/net/tls_credentials.h>
#endif /* CONFIG_NET_SOCKETS_SOCKOPT_TLS */
#include "mender-log.h"
#include "mender-net.h"
#include "mender-utils.h"

/**
 * @brief Default TLS_PEER_VERIFY option
 */
#ifndef CONFIG_MENDER_NET_TLS_PEER_VERIFY
#define CONFIG_MENDER_NET_TLS_PEER_VERIFY (2)
#endif /* CONFIG_MENDER_NET_TLS_PEER_VERIFY */

mender_err_t
mender_net_get_host_port_url(char *path, char *config_host, char **host, char **port, char **url) {

    assert(NULL != path);
    assert(NULL != host);
    assert(NULL != port);

    char *path_no_prefix = NULL;
    bool  is_https       = false;

    /* Check if the path start with protocol (meaning we have the full path); alternatively we have only URL (path/to/resource) */
    if ((false == mender_utils_strbeginwith(path, "http://")) && (false == mender_utils_strbeginwith(path, "https://"))) {

        /* Path contains the URL only, retrieve host and port from configuration (config_host) */
        assert(NULL != url);
        if (NULL == (*url = strdup(path))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
        return mender_net_get_host_port_url(config_host, NULL, host, port, NULL);
    }

    /* Determine protocol and default port */
    if (mender_utils_strbeginwith(path, "http://")) {
        path_no_prefix = path + strlen("http://");
    } else if (mender_utils_strbeginwith(path, "https://")) {
        path_no_prefix = path + strlen("https://");
        is_https       = true;
    }

    /* Extract url path: next '/' character in the path after finding protocol must be the beginning of url */
    char *path_url = strchr(path_no_prefix, '/');
    if ((NULL != path_url) && (NULL != url)) {
        if (NULL == (*url = strdup(path_url))) {
            mender_log_error("Unable to allocate memory for URL");
            return MENDER_FAIL;
        }
    }

    /* Extract host and port */
    char *path_port = strchr(path_no_prefix, ':');
    if ((NULL == path_port) && (NULL == path_url)) {
        *port = strdup(is_https ? "443" : "80");
        *host = strdup(path_no_prefix);
    } else if ((NULL == path_port) && (NULL != path_url)) {
        *port = strdup(is_https ? "443" : "80");
        *host = strndup(path_no_prefix, path_url - path_no_prefix);
    } else if ((NULL != path_port) && (NULL == path_url)) {
        *port = strdup(path_port + 1);
        *host = strndup(path_no_prefix, path_port - path_no_prefix);
    } else {
        *host = strndup(path_no_prefix, path_port - path_no_prefix);
        *port = strndup(path_port + 1, path_url - path_port - 1);
    }

    if (NULL == *host || NULL == *port) {
        /* Clean up */
        free(*host);
        free(*port);
        free(*url);

        mender_log_error("Unable to allocate memory for host or port");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_net_connect(const char *host, const char *port, int *sock) {

    assert(NULL != host);
    assert(NULL != port);
    assert(NULL != sock);
    int                    result;
    mender_err_t           ret = MENDER_OK;
    struct zsock_addrinfo  hints;
    struct zsock_addrinfo *addr = NULL;

    /* Set hints */
    memset(&hints, 0, sizeof(hints));
    if (IS_ENABLED(CONFIG_NET_IPV6)) {
        hints.ai_family = AF_INET6;
    } else if (IS_ENABLED(CONFIG_NET_IPV4)) {
        hints.ai_family = AF_INET;
    }
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Perform DNS resolution of the host */
    if (0 != (result = zsock_getaddrinfo(host, port, &hints, &addr))) {
        mender_log_error("Unable to resolve host name '%s:%s', result = %d, errno = %d", host, port, result, errno);
        ret = MENDER_FAIL;
        goto END;
    }

    /* Create socket */
#ifdef CONFIG_NET_SOCKETS_SOCKOPT_TLS
    if ((result = zsock_socket(addr->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2)) < 0) {
#else
    if ((result = zsock_socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
#endif /* CONFIG_NET_SOCKETS_SOCKOPT_TLS */
        mender_log_error("Unable to create socket, result = %d, errno= %d", result, errno);
        ret = MENDER_FAIL;
        goto END;
    }
    *sock = result;

#ifdef CONFIG_NET_SOCKETS_SOCKOPT_TLS

    /* Set TLS_SEC_TAG_LIST option */
    sec_tag_t sec_tag[] = {
        CONFIG_MENDER_NET_CA_CERTIFICATE_TAG,
    };
    if ((result = zsock_setsockopt(*sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag, sizeof(sec_tag))) < 0) {
        mender_log_error("Unable to set TLS_SEC_TAG_LIST option, result = %d, errno = %d", result, errno);
        zsock_close(*sock);
        *sock = -1;
        ret   = MENDER_FAIL;
        goto END;
    }

    /* Set TLS_HOSTNAME option */
    if ((result = zsock_setsockopt(*sock, SOL_TLS, TLS_HOSTNAME, host, strlen(host))) < 0) {
        mender_log_error("Unable to set TLS_HOSTNAME option, result = %d, errno = %d", result, errno);
        zsock_close(*sock);
        *sock = -1;
        ret   = MENDER_FAIL;
        goto END;
    }

    /* Set TLS_PEER_VERIFY option */
    int verify = CONFIG_MENDER_NET_TLS_PEER_VERIFY;
    if ((result = zsock_setsockopt(*sock, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(int))) < 0) {
        mender_log_error("Unable to set TLS_PEER_VERIFY option, result = %d, errno = %d", result, errno);
        zsock_close(*sock);
        *sock = -1;
        ret   = MENDER_FAIL;
        goto END;
    }

#endif /* CONFIG_NET_SOCKETS_SOCKOPT_TLS */

    /* Connect to the host */
    if (0 != (result = zsock_connect(*sock, addr->ai_addr, addr->ai_addrlen))) {
        mender_log_error("Unable to connect to the host '%s:%s', result = %d, errno = %d", host, port, result, errno);
        mender_log_error("result = %d, errno = %d", result, errno);
        zsock_close(*sock);
        *sock = -1;
        ret   = MENDER_FAIL;
        goto END;
    }

END:

    /* Release memory */
    if (NULL != addr) {
        zsock_freeaddrinfo(addr);
    }

    return ret;
}

mender_err_t
mender_net_disconnect(int sock) {

    /* Close socket */
    zsock_close(sock);

    return MENDER_OK;
}
