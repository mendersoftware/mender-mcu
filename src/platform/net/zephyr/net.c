/**
 * @file      net.c
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
#include <zephyr/kernel.h>
#ifdef CONFIG_NET_SOCKETS_SOCKOPT_TLS
#include <zephyr/net/tls_credentials.h>
#endif /* CONFIG_NET_SOCKETS_SOCKOPT_TLS */
#include "log.h"
#include "utils.h"

#include "net.h"

/**
 * @brief Default TLS_PEER_VERIFY option
 */
#ifndef CONFIG_MENDER_NET_TLS_PEER_VERIFY
#define CONFIG_MENDER_NET_TLS_PEER_VERIFY (2)
#endif /* CONFIG_MENDER_NET_TLS_PEER_VERIFY */

#define RESOLVE_ATTEMPTS (10)

mender_err_t
mender_net_get_host_port_url(const char *path, const char *config_host, char **host, char **port, char **url) {

    assert(NULL != path);
    assert(NULL != host);
    assert(NULL != port);

    const char *path_no_prefix = NULL;
    bool        is_https       = false;

    /* Check if the path start with protocol (meaning we have the full path); alternatively we have only URL (path/to/resource) */
    if ((false == mender_utils_strbeginswith(path, "http://")) && (false == mender_utils_strbeginswith(path, "https://"))) {

        /* Path contains the URL only, retrieve host and port from configuration (config_host) */
        assert(NULL != url);
        if (NULL == (*url = mender_utils_strdup(path))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
        return mender_net_get_host_port_url(config_host, NULL, host, port, NULL);
    }

    /* Determine protocol and default port */
    if (mender_utils_strbeginswith(path, "http://")) {
        path_no_prefix = path + strlen("http://");
    } else if (mender_utils_strbeginswith(path, "https://")) {
        path_no_prefix = path + strlen("https://");
        is_https       = true;
    }

    /* Extract url path: next '/' character in the path after finding protocol must be the beginning of url */
    char *path_url = strchr(path_no_prefix, '/');
    if ((NULL != path_url) && (NULL != url)) {
        if (NULL == (*url = mender_utils_strdup(path_url))) {
            mender_log_error("Unable to allocate memory for URL");
            return MENDER_FAIL;
        }
    }

    /* Extract host and port */
    char *path_port = strchr(path_no_prefix, ':');
    if ((NULL == path_port) && (NULL == path_url)) {
        *port = mender_utils_strdup(is_https ? "443" : "80");
        *host = mender_utils_strdup(path_no_prefix);
    } else if ((NULL == path_port) && (NULL != path_url)) {
        *port = mender_utils_strdup(is_https ? "443" : "80");
        *host = mender_utils_strndup(path_no_prefix, path_url - path_no_prefix);
    } else if ((NULL != path_port) && (NULL == path_url)) {
        *port = mender_utils_strdup(path_port + 1);
        *host = mender_utils_strndup(path_no_prefix, path_port - path_no_prefix);
    } else {
        *host = mender_utils_strndup(path_no_prefix, path_port - path_no_prefix);
        *port = mender_utils_strndup(path_port + 1, path_url - path_port - 1);
    }

    if (NULL == *host || NULL == *port) {
        /* Clean up */
        mender_free(*host);
        mender_free(*port);
        mender_free(*url);

        mender_log_error("Unable to allocate memory for host or port");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
header_add(const char **header_list, size_t header_list_size, const char *header) {

    // Headers are added to the header list one by one so that there are no empty spaces in the list
    if (NULL == header_list) {
        return MENDER_FAIL;
    }

    // The list that we pass to the Zephyr request needs to be NULL-terminated so the last element need to stay NULL
    for (size_t i = 0; i < header_list_size - 1; i++) {
        if (NULL == header_list[i]) {
            header_list[i] = header;
            return MENDER_OK;
        }
    }

    mender_log_error("Unable to add header: list is full");
    return MENDER_FAIL;
}

char *
header_alloc_and_add(const char **header_list, size_t header_list_size, const char *format, ...) {

    char   *header = NULL;
    va_list args;

    va_start(args, format);
    int ret = mender_utils_vasprintf(&header, format, args);
    va_end(args);
    if (ret < 0) {
        mender_log_error("Unable to allocate memory, failed to create header");
        return NULL;
    }

    if (MENDER_FAIL == header_add(header_list, header_list_size, header)) {
        mender_log_error("Unable to add header to the list");
        mender_free(header);
        return NULL;
    }
    return header;
}

int
mender_net_connect(const char *host, const char *port) {

    assert(NULL != host);
    assert(NULL != port);

    int                    result;
    int                    sock             = -1;
    struct zsock_addrinfo  hints            = { 0 };
    struct zsock_addrinfo *addr             = NULL;
    unsigned int           resolve_attempts = RESOLVE_ATTEMPTS;

    /* Set hints */
    if (IS_ENABLED(CONFIG_NET_IPV6)) {
        hints.ai_family = AF_INET6;
    } else if (IS_ENABLED(CONFIG_NET_IPV4)) {
        hints.ai_family = AF_INET;
    }
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Perform DNS resolution of the host; try RESOLVE_ATTEMPTS times */
    do {
        result = zsock_getaddrinfo(host, port, &hints, &addr);
        if (0 == result) {
            break;
        }
        mender_log_debug("Unable to resolve host name '%s:%s': %s", host, port, zsock_gai_strerror(result));
        /* Introduce a backoff mechanism to try every 10ms, 20ms, ..., 100ms */
        k_sleep(K_MSEC(10 * (RESOLVE_ATTEMPTS - resolve_attempts + 1)));
    } while (0 != --resolve_attempts);

    if (0 != result) {
        mender_log_error("Unable to resolve host name '%s:%s': %s", host, port, zsock_gai_strerror(result));
        goto END;
    }

    /* Create socket */
#ifdef CONFIG_NET_SOCKETS_SOCKOPT_TLS
    if ((sock = zsock_socket(addr->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2)) < 0) {
#else
    if ((sock = zsock_socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
#endif /* CONFIG_NET_SOCKETS_SOCKOPT_TLS */
        mender_log_error("Unable to create socket, result = %d, error: %s", sock, strerror(errno));
        goto END;
    }

#ifdef CONFIG_NET_SOCKETS_SOCKOPT_TLS

    /* Set TLS_SEC_TAG_LIST option */
#ifdef CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_SECONDARY_ENABLED
    sec_tag_t sec_tag[2] = {
        CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_PRIMARY,
        CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_SECONDARY,
    };
#else
    sec_tag_t sec_tag[1] = {
        CONFIG_MENDER_NET_CA_CERTIFICATE_TAG_PRIMARY,
    };
#endif

    if ((result = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag, sizeof(sec_tag))) < 0) {
        mender_log_error("Unable to set TLS_SEC_TAG_LIST option, result = %d, error: %s", result, strerror(errno));
        goto END;
    }

    /* Set TLS_HOSTNAME option */
    if ((result = zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, host, strlen(host))) < 0) {
        mender_log_error("Unable to set TLS_HOSTNAME option, result = %d, error: %s", result, strerror(errno));
        goto END;
    }

    /* Set TLS_PEER_VERIFY option */
    int verify = CONFIG_MENDER_NET_TLS_PEER_VERIFY;
    if ((result = zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(int))) < 0) {
        mender_log_error("Unable to set TLS_PEER_VERIFY option, result = %d, error: %s", result, strerror(errno));
        goto END;
    }

#endif /* CONFIG_NET_SOCKETS_SOCKOPT_TLS */

    /* Connect to the host */
    if (0 != (result = zsock_connect(sock, addr->ai_addr, addr->ai_addrlen))) {
        mender_log_error("Unable to connect to the host '%s:%s', result = %d, error: %s", host, port, result, strerror(errno));
        goto END;
    }

    /* Free the address info */
    if (NULL != addr) {
        zsock_freeaddrinfo(addr);
    }
    return sock;

END:
    /* Close socket */
    if (sock >= 0) {
        zsock_close(sock);
    }

    if (NULL != addr) {
        zsock_freeaddrinfo(addr);
    }

    return -1; /* Error */
}

mender_err_t
mender_net_disconnect(int sock) {

    /* Close socket */
    zsock_close(sock);

    return MENDER_OK;
}
