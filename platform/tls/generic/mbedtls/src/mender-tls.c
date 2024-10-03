/**
 * @file      mender-tls.c
 * @brief     Mender TLS interface for mbedTLS platform
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

#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#ifdef MBEDTLS_ERROR_C
#include <mbedtls/error.h>
#endif /* MBEDTLS_ERROR_C */
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/x509.h>
#include "mender-log.h"
#include "mender-storage.h"
#include "mender-tls.h"

#include "mender-utils.h"

/**
 * @brief Keys buffer length
 */
#define MENDER_TLS_PRIVATE_KEY_LENGTH (2048)
#define MENDER_TLS_PUBLIC_KEY_LENGTH  (768)

/**
 * @brief Signature buffer length (base64 encoded)
 * @note base64 produces 4 bytes of output per 3 bytes of input (padded to be
 *       divisible), see RFC-4648 or man:EVP_EncodeBlock(3)
 */
#define MENDER_TLS_SIGNATURE_LENGTH (((MBEDTLS_PK_SIGNATURE_MAX_SIZE + 2) / 3) * 4)

#ifdef MBEDTLS_ERROR_C
#define MBEDTLS_ERR_BUF char err[128]

/**
 * @brief Macro for logging errors coming from mbedtls
 * @note  Make sure to declare the buffer using the #MBEDTLS_ERR_BUF macro above
 */
#define LOG_MBEDTLS_ERROR(msg, ret)                        \
    do {                                                   \
        mbedtls_strerror(ret, err, sizeof(err));           \
        mender_log_error(msg " (-0x%04x: %s)", -ret, err); \
    } while (0)
#else
#define MBEDTLS_ERR_BUF
#define LOG_MBEDTLS_ERROR(msg, ret) mender_log_error(msg " (-0x%04x)", -ret)
#endif /* MBEDTLS_ERROR_C */

/**
 * @brief Private and public keys of the device
 */
static unsigned char *mender_tls_private_key        = NULL;
static size_t         mender_tls_private_key_length = 0;
static unsigned char *mender_tls_public_key         = NULL;
static size_t         mender_tls_public_key_length  = 0;

/**
 * @brief Generate authentication keys
 * @param pk_context PK context
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_tls_generate_authentication_keys(mbedtls_pk_context *pk_context);

/**
 * @brief Get user provided authentication keys
 * @param pk_context PK context
 * @param user_provided_key Buffer of user provided key
 * @param user_provided_key_length Length of buffer of user provided key
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_tls_user_provided_authentication_keys(mbedtls_pk_context *pk_context,
                                                                 const char         *user_provided_key,
                                                                 size_t              user_provided_key_length);

/**
 * @brief Generate authentication keys
 * @param private_key Private key generated
 * @param private_key_length Private key length
 * @param public_key Public key generated
 * @param public_key_length Public key length
 * @param user_provided_key Path to user-provided key
 * @param user_provided_key_length Length of buffer of user provided key
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_tls_get_authentication_keys(unsigned char **private_key,
                                                       size_t         *private_key_length,
                                                       unsigned char **public_key,
                                                       size_t         *public_key_length,
                                                       const char     *user_provided_key,
                                                       size_t          user_provided_key_length);

/**
 * @brief Write a buffer of PEM information from a DER encoded buffer
 * @note This function is derived from mbedtls_pem_write_buffer with const header and footer
 * @param der_data The DER data to encode
 * @param der_len The length of the DER data
 * @param buf The buffer to write to
 * @param buf_len The length of the output buffer
 * @param olen The address at which to store the total length written or required output buffer length is not enough
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_tls_pem_write_buffer(const unsigned char *der_data, size_t der_len, char *buf, size_t buf_len, size_t *olen);

mender_err_t
mender_tls_init(void) {

    /* Nothing to do */
    return MENDER_OK;
}

mender_err_t
mender_tls_init_authentication_keys(mender_err_t (*get_user_provided_keys)(char **user_provided_key, size_t *user_provided_key_length), bool recommissioning) {

    /* Release memory */
    FREE_AND_NULL(mender_tls_private_key);
    mender_tls_private_key_length = 0;
    FREE_AND_NULL(mender_tls_public_key);
    mender_tls_public_key_length = 0;

    /* Check if recommissioning is forced */
    if (recommissioning) {
        /* Erase authentication keys */
        mender_log_debug("Deleting authentication keys");
        if (MENDER_OK != mender_storage_delete_authentication_keys()) {
            mender_log_warning("Unable to delete authentication keys");
        }
    }

    /* Get user provided key (callback is optional) */
    if (NULL != get_user_provided_keys) {
        char  *user_provided_key        = NULL;
        size_t user_provided_key_length = 0;

        mender_log_debug("Retrieving user provided authentication keys");

        if (MENDER_OK != get_user_provided_keys(&user_provided_key, &user_provided_key_length)) {
            mender_log_error("Unable to get user provided authentication key");
            return MENDER_FAIL;
        }

        if ((NULL == user_provided_key) || (0 == user_provided_key_length)) {
            mender_log_error("User provided authentication key is empty");
            return MENDER_FAIL;
        }

        if (MENDER_OK
            != mender_tls_get_authentication_keys(&mender_tls_private_key,
                                                  &mender_tls_private_key_length,
                                                  &mender_tls_public_key,
                                                  &mender_tls_public_key_length,
                                                  user_provided_key,
                                                  user_provided_key_length)) {
            mender_log_error("Unable to get user provided authentication key");
            free(user_provided_key);
            return MENDER_FAIL;
        }

        free(user_provided_key);
        return MENDER_OK;
    }

    /* Get keys from store */
    mender_log_debug("Trying to read authentication keys from store");
    switch (mender_storage_get_authentication_keys(
        &mender_tls_private_key, &mender_tls_private_key_length, &mender_tls_public_key, &mender_tls_public_key_length)) {
        case MENDER_OK:
            /* Keys found! */
            return MENDER_OK;
        case MENDER_NOT_FOUND:
            mender_log_debug("Authentication keys not found in store");
            break;
        case MENDER_DONE:
            /* fallthrough */
        case MENDER_NOT_IMPLEMENTED:
            assert(false && "Unexpected return value");
            /* fallthrough */
        case MENDER_FAIL:
            mender_log_error("Unable to get authentication keys from store");
            return MENDER_FAIL;
    }

    /* We failed to get keys from store. Hence, we need to generate them */
    mender_log_info("Generating authentication keys");
    if (MENDER_OK
        != mender_tls_get_authentication_keys(
            &mender_tls_private_key, &mender_tls_private_key_length, &mender_tls_public_key, &mender_tls_public_key_length, NULL, 0)) {
        mender_log_error("Unable to generate authentication keys");
        return MENDER_FAIL;
    }

    /* Store newly generated keys */
    mender_log_debug("Writing authentication keys to store");
    if (MENDER_OK
        != mender_storage_set_authentication_keys(mender_tls_private_key, mender_tls_private_key_length, mender_tls_public_key, mender_tls_public_key_length)) {
        mender_log_error("Unable to store authentication keys");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_tls_get_public_key_pem(char **public_key) {

    assert(NULL != public_key);
    mender_err_t ret;

    /* Compute size of the public key */
    size_t olen = 0;
    mender_tls_pem_write_buffer(mender_tls_public_key, mender_tls_public_key_length, NULL, 0, &olen);
    if (0 == olen) {
        mender_log_error("Unable to compute public key size");
        return MENDER_FAIL;
    }
    if (NULL == (*public_key = (char *)malloc(olen))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Convert public key from DER to PEM format */
    if (MENDER_OK != (ret = mender_tls_pem_write_buffer(mender_tls_public_key, mender_tls_public_key_length, *public_key, olen, &olen))) {
        mender_log_error("Unable to convert public key");
        return ret;
    }

    return MENDER_OK;
}

mender_err_t
mender_tls_sign_payload(char *payload, char **signature, size_t *signature_length) {

    assert(NULL != payload);
    assert(NULL != signature);
    assert(NULL != signature_length);
    int                       ret;
    mbedtls_pk_context       *pk_context = NULL;
    mbedtls_ctr_drbg_context *ctr_drbg   = NULL;
    mbedtls_entropy_context  *entropy    = NULL;
    unsigned char            *sig        = NULL;
    size_t                    sig_length;
    MBEDTLS_ERR_BUF;

    /* Initialize mbedtls */
    if (NULL == (pk_context = (mbedtls_pk_context *)malloc(sizeof(mbedtls_pk_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_pk_init(pk_context);
    if (NULL == (ctr_drbg = (mbedtls_ctr_drbg_context *)malloc(sizeof(mbedtls_ctr_drbg_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_ctr_drbg_init(ctr_drbg);
    if (NULL == (entropy = (mbedtls_entropy_context *)malloc(sizeof(mbedtls_entropy_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_entropy_init(entropy);

    /* Setup CRT DRBG */
    if (0 != (ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)"mender", strlen("mender")))) {
        LOG_MBEDTLS_ERROR("Unable to initialize ctr drbg", ret);
        goto END;
    }

    /* Parse private key (IMPORTANT NOTE: length must include the ending \0 character) */
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    if (0 != (ret = mbedtls_pk_parse_key(pk_context, mender_tls_private_key, mender_tls_private_key_length, NULL, 0, mbedtls_ctr_drbg_random, ctr_drbg))) {
#else
    if (0 != (ret = mbedtls_pk_parse_key(pk_context, mender_tls_private_key, mender_tls_private_key_length, NULL, 0))) {
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03000000 */
        LOG_MBEDTLS_ERROR("Unable to parse private key", ret);
        goto END;
    }

    /* Generate digest */
    uint8_t digest[32];
    if (0 != (ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (unsigned char *)payload, strlen(payload), digest))) {
        LOG_MBEDTLS_ERROR("Unable to generate digest", ret);
        goto END;
    }

    /* Compute signature */
    if (NULL == (sig = (unsigned char *)malloc(MBEDTLS_PK_SIGNATURE_MAX_SIZE))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    sig_length = MBEDTLS_PK_SIGNATURE_MAX_SIZE;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    if (0 != (ret = mbedtls_pk_sign(pk_context, MBEDTLS_MD_SHA256, digest, sizeof(digest), sig, sig_length, &sig_length, mbedtls_ctr_drbg_random, ctr_drbg))) {
#else
    if (0 != (ret = mbedtls_pk_sign(pk_context, MBEDTLS_MD_SHA256, digest, sizeof(digest), sig, &sig_length, mbedtls_ctr_drbg_random, ctr_drbg))) {
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03000000 */
        LOG_MBEDTLS_ERROR("Unable to compute signature", ret);
        goto END;
    }

    /* Encode signature to base64 (1 extra byte for the NUL character) */
    if (NULL == (*signature = (char *)malloc(MENDER_TLS_SIGNATURE_LENGTH + 1))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    *signature_length = MENDER_TLS_SIGNATURE_LENGTH + 1;
    if (0 != (ret = mbedtls_base64_encode((unsigned char *)*signature, *signature_length, signature_length, sig, sig_length))) {
        LOG_MBEDTLS_ERROR("Unable to encode signature", ret);
        if (MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL == ret) {
            mender_log_error("This is a bug, please report it");
        }
        FREE_AND_NULL(*signature);
        *signature_length = 0;
        goto END;
    }

END:

    /* Release mbedtls */
    mbedtls_entropy_free(entropy);
    free(entropy);
    mbedtls_ctr_drbg_free(ctr_drbg);
    free(ctr_drbg);
    mbedtls_pk_free(pk_context);
    free(pk_context);

    /* Release memory */
    free(sig);

    return (0 != ret) ? MENDER_FAIL : MENDER_OK;
}

mender_err_t
mender_tls_exit(void) {

    /* Release memory */
    FREE_AND_NULL(mender_tls_private_key);
    mender_tls_private_key_length = 0;
    FREE_AND_NULL(mender_tls_public_key);
    mender_tls_public_key_length = 0;

    return MENDER_OK;
}

static mender_err_t
mender_tls_generate_authentication_keys(mbedtls_pk_context *pk_context) {

    mbedtls_ctr_drbg_context     *ctr_drbg   = NULL;
    mbedtls_entropy_context      *entropy    = NULL;
    const mbedtls_ecp_curve_info *curve_info = NULL;
    int                           ret;
    MBEDTLS_ERR_BUF;

    if (NULL == (ctr_drbg = (mbedtls_ctr_drbg_context *)malloc(sizeof(mbedtls_ctr_drbg_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_ctr_drbg_init(ctr_drbg);
    if (NULL == (entropy = (mbedtls_entropy_context *)malloc(sizeof(mbedtls_entropy_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_entropy_init(entropy);

    /* Setup CRT DRBG */
    if (0 != (ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)"mender", strlen("mender")))) {
        LOG_MBEDTLS_ERROR("Unable to initialize ctr drbg", ret);
        goto END;
    }

    /* PK setup */
    if (0 != (ret = mbedtls_pk_setup(pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))) {
        LOG_MBEDTLS_ERROR("Unable to setup pk", ret);
        goto END;
    }

    /* Find a supported curve */
    for (curve_info = mbedtls_ecp_curve_list(); MBEDTLS_ECP_DP_NONE != curve_info->grp_id; curve_info++) {
        if (1 == mbedtls_ecdsa_can_do(curve_info->grp_id)) {
            mender_log_debug("Found supported ECDSA curve: %s", curve_info->name);
            break;
        }
    }
    if (MBEDTLS_ECP_DP_NONE == curve_info->grp_id) {
        mender_log_error("Unable to find a ECDSA valid curve");
        goto END;
    }

    /* Generate key pair */
    if (0 != (ret = mbedtls_ecdsa_genkey(mbedtls_pk_ec(*pk_context), curve_info->grp_id, mbedtls_ctr_drbg_random, ctr_drbg))) {
        LOG_MBEDTLS_ERROR("Unable to generate key", ret);
        goto END;
    }

END:
    /* Release mbedtls */
    mbedtls_entropy_free(entropy);
    free(entropy);
    mbedtls_ctr_drbg_free(ctr_drbg);
    free(ctr_drbg);

    return (0 != ret) ? MENDER_FAIL : MENDER_OK;
}

static mender_err_t
mender_tls_user_provided_authentication_keys(mbedtls_pk_context *pk_context, const char *user_provided_key, size_t user_provided_key_length) {

    assert(NULL != user_provided_key);
    assert(0 != user_provided_key_length);

    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    mbedtls_entropy_context  *entropy  = NULL;
    int                       ret;
    MBEDTLS_ERR_BUF;

    if (NULL == (ctr_drbg = (mbedtls_ctr_drbg_context *)malloc(sizeof(mbedtls_ctr_drbg_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_ctr_drbg_init(ctr_drbg);
    if (NULL == (entropy = (mbedtls_entropy_context *)malloc(sizeof(mbedtls_entropy_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_entropy_init(entropy);

    /* Setup CRT DRBG */
    if (0 != (ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)"mender", strlen("mender")))) {
        LOG_MBEDTLS_ERROR("Unable to initialize ctr drbg", ret);
        goto END;
    }

    /* Load and parse the private key buffer */
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    if (0
        != (ret = mbedtls_pk_parse_key(
                pk_context, (const unsigned char *)user_provided_key, user_provided_key_length, NULL, 0, mbedtls_ctr_drbg_random, ctr_drbg))) {
#else
    if (0 != (ret = mbedtls_pk_parse_key(pk_context, (const unsigned char *)user_provided_key, user_provided_key_length, NULL, 0))) {
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03000000 */
        LOG_MBEDTLS_ERROR("Unable to parse private key", ret);
        goto END;
    }

END:
    /* Release mbedtls */
    mbedtls_entropy_free(entropy);
    free(entropy);
    mbedtls_ctr_drbg_free(ctr_drbg);
    free(ctr_drbg);

    return (0 != ret) ? MENDER_FAIL : MENDER_OK;
}

static mender_err_t
mender_tls_get_authentication_keys(unsigned char **private_key,
                                   size_t         *private_key_length,
                                   unsigned char **public_key,
                                   size_t         *public_key_length,
                                   const char     *user_provided_key,
                                   size_t          user_provided_key_length) {

    assert(NULL != private_key);
    assert(NULL != private_key_length);
    assert(NULL != public_key);
    assert(NULL != public_key_length);

    int                 ret;
    mbedtls_pk_context *pk_context = NULL;
    unsigned char      *tmp;
    MBEDTLS_ERR_BUF;

    /* Initialize mbedtls */
    if (NULL == (pk_context = (mbedtls_pk_context *)malloc(sizeof(mbedtls_pk_context)))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    mbedtls_pk_init(pk_context);
    /* Get user provided key, else generate key  */
    if (NULL != user_provided_key) {
        if (MENDER_OK != mender_tls_user_provided_authentication_keys(pk_context, user_provided_key, user_provided_key_length)) {
            ret = -1;
            goto END;
        }
    } else {
        /* Generate key */
        if (MENDER_OK != mender_tls_generate_authentication_keys(pk_context)) {
            ret = -1;
            goto END;
        }
    }

    /* Export private key */
    if (NULL == (*private_key = (unsigned char *)malloc(MENDER_TLS_PRIVATE_KEY_LENGTH))) {
        mender_log_error("Unable to allocate memory");
        ret = -1;
        goto END;
    }
    if ((ret = mbedtls_pk_write_key_der(pk_context, *private_key, MENDER_TLS_PRIVATE_KEY_LENGTH)) < 0) {
        LOG_MBEDTLS_ERROR("Unable to write private key to PEM format", ret);
        FREE_AND_NULL(*private_key);
        goto END;
    }
    *private_key_length = (size_t)ret;
    memcpy(*private_key, *private_key + MENDER_TLS_PRIVATE_KEY_LENGTH - *private_key_length, *private_key_length);
    if (NULL == (tmp = realloc(*private_key, *private_key_length))) {
        mender_log_error("Unable to allocate memory");
        FREE_AND_NULL(*private_key);
        ret = -1;
        goto END;
    }
    *private_key = tmp;

    /* Export public key */
    if (NULL == (*public_key = (unsigned char *)malloc(MENDER_TLS_PUBLIC_KEY_LENGTH))) {
        mender_log_error("Unable to allocate memory");
        FREE_AND_NULL(*private_key);
        ret = -1;
        goto END;
    }
    if ((ret = mbedtls_pk_write_pubkey_der(pk_context, *public_key, MENDER_TLS_PUBLIC_KEY_LENGTH)) < 0) {
        LOG_MBEDTLS_ERROR("Unable to write public key to PEM format", ret);
        FREE_AND_NULL(*private_key);
        FREE_AND_NULL(*public_key);
        goto END;
    }
    *public_key_length = (size_t)ret;
    memcpy(*public_key, *public_key + MENDER_TLS_PUBLIC_KEY_LENGTH - *public_key_length, *public_key_length);
    if (NULL == (tmp = realloc(*public_key, *public_key_length))) {
        mender_log_error("Unable to allocate memory");
        FREE_AND_NULL(*private_key);
        FREE_AND_NULL(*public_key);
        ret = -1;
        goto END;
    }
    *public_key = tmp;
    ret         = 0;

END:

    /* Release mbedtls */
    mbedtls_pk_free(pk_context);
    free(pk_context);

    return (0 != ret) ? MENDER_FAIL : MENDER_OK;
}

static mender_err_t
mender_tls_pem_write_buffer(const unsigned char *der_data, size_t der_len, char *buf, size_t buf_len, size_t *olen) {

#define PEM_BEGIN_PUBLIC_KEY "-----BEGIN PUBLIC KEY-----"
#define PEM_END_PUBLIC_KEY   "-----END PUBLIC KEY-----"

    mender_err_t   ret        = MENDER_OK;
    unsigned char *encode_buf = NULL;
    unsigned char *p          = (unsigned char *)buf;

    /* Compute length required to convert DER data */
    size_t use_len = 0;
    mbedtls_base64_encode(NULL, 0, &use_len, der_data, der_len);
    if (0 == use_len) {
        mender_log_error("Unable to compute length");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Compute length required to format PEM */
    size_t add_len = strlen(PEM_BEGIN_PUBLIC_KEY) + 1 + strlen(PEM_END_PUBLIC_KEY) + ((use_len / 64) + 1);

    /* Check buffer length */
    if (use_len + add_len > buf_len) {
        *olen = use_len + add_len;
        ret   = MENDER_FAIL;
        goto END;
    }

    /* Check buffer */
    if (NULL == p) {
        ret = MENDER_FAIL;
        goto END;
    }

    /* Allocate memory to store PEM data */
    if (NULL == (encode_buf = (unsigned char *)malloc(use_len))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Convert DER data */
    if (0 != mbedtls_base64_encode(encode_buf, use_len, &use_len, der_data, der_len)) {
        mender_log_error("Unable to convert data to base64 format");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Copy header */
    memcpy(p, PEM_BEGIN_PUBLIC_KEY, strlen(PEM_BEGIN_PUBLIC_KEY));
    p += strlen(PEM_BEGIN_PUBLIC_KEY);
    *p++ = '\n';

    /* Copy PEM data */
    unsigned char *c = encode_buf;
    while (use_len) {
        size_t len = (use_len > 64) ? 64 : use_len;
        memcpy(p, c, len);
        use_len -= len;
        p += len;
        c += len;
        *p++ = '\n';
    }

    /* Copy footer */
    memcpy(p, PEM_END_PUBLIC_KEY, strlen(PEM_END_PUBLIC_KEY));
    p += strlen(PEM_END_PUBLIC_KEY);
    *p++ = '\0';

    /* Compute output length */
    *olen = p - (unsigned char *)buf;

    /* Clean any remaining data previously written to the buffer */
    memset(buf + *olen, 0, buf_len - *olen);

END:

    /* Release memory */
    free(encode_buf);

    return ret;
}
