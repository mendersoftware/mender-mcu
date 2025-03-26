/**
 * @file      artifact.h
 * @brief     Mender artifact parser (private API)
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

#ifndef __MENDER_ARTIFACT_PRIV_H__
#define __MENDER_ARTIFACT_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "artifact-download-data.h"
#include "utils.h"
#include "sha.h"

/**
 * @brief TAR block size
 */
#define MENDER_ARTIFACT_STREAM_BLOCK_SIZE (512)

/**
 * @brief Artifact state machine used to process input data stream
 */
typedef enum {
    MENDER_ARTIFACT_STREAM_STATE_PARSING_HEADER = 0, /**< Currently parsing header */
    MENDER_ARTIFACT_STREAM_STATE_PARSING_DATA        /**< Currently parsing data */
} mender_artifact_stream_state_t;

/**
 * @brief Artifact payloads
 */
typedef struct {
    char *type; /**< Type of the payload */
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
    /* Provides and depends are key-value pairs e.g.: `artifact_name: "test" */
    mender_key_value_list_t *provides; /**< Provides of the payload */
    mender_key_value_list_t *depends;  /**< Depends of the payload */
    /* Clears provides is an array of provides to clear  e.g.: ["artifact_name", "artifact_group"] */
    char **clears_provides;      /**< Clears provides of the payload (string list) */
    size_t clears_provides_size; /**< Number of clears provides of the payload */
#endif
    cJSON *meta_data; /**< Meta-data from the header tarball, NULL if no meta-data */
} mender_artifact_payload_t;

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
typedef struct mender_artifact_checksum_t mender_artifact_checksum_t;
struct mender_artifact_checksum_t {
    char                       *filename;
    unsigned char               manifest[MENDER_DIGEST_BUFFER_SIZE];
    mender_sha256_context_t     context;
    mender_artifact_checksum_t *next;
};
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

/**
 * @brief Artifact context
 */
typedef struct {
    mender_artifact_stream_state_t stream_state; /**< Stream state of the artifact processing */
    struct {
        void  *data;      /**< Data received, concatenated chunk by chunk */
        size_t length;    /**< Length of the data received */
        size_t size;      /**< Current size of the buffer */
        size_t orig_size; /**< Original size of the buffer */
    } input;              /**< Input data of the artifact */
    struct {
        size_t                     size;   /**< Number of payloads in the artifact */
        mender_artifact_payload_t *values; /**< Values of payloads in the artifact */
    } payloads;                            /**< Payloads of the artifact */
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
    struct {
        mender_artifact_checksum_t *checksums; /**< Contains checksums of the artifact */
        mender_key_value_list_t    *provides;  /**< Provides of the artifact */
        mender_key_value_list_t    *depends;   /**< Depends of the artifact */
    } artifact_info;                           /**< Global information about the artifact */
#endif                                         /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
    struct {
        char  *name;  /**< Name of the file currently parsed */
        size_t size;  /**< Size of the file currently parsed (bytes) */
        size_t index; /**< Index of the data in the file currently parsed (bytes), incremented block by block */
    } file;           /**< Information about the file currently parsed */
} mender_artifact_ctx_t;

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
/**
 * @brief Function used to retrieve device type from artifact context
 * @param ctx Artifact context
 * @param device_type Device type
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_artifact_get_device_type(mender_artifact_ctx_t *ctx, const char **device_type);
#endif

/**
 * @brief Function used to create a new artifact context
 * @param buf_size Size of the internal buffer
 * @return Artifact context if the function succeeds, NULL otherwise
 */
mender_artifact_ctx_t *mender_artifact_create_ctx(size_t buf_size);

/**
 * @brief Function used to get the artifact context
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_artifact_get_ctx(mender_artifact_ctx_t **ctx);

/**
 * @brief Function used to process data from artifact stream
 * @param ctx Artifact context
 * @param input_data Input data from the stream
 * @param input_length Length of the input data from the stream
 * @param dl_data Download data for the artifact
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_artifact_process_data(mender_artifact_ctx_t *ctx, void *input_data, size_t input_length, mender_artifact_download_data_t *dl_data);

/**
 * @brief Do integrity check to one item by comparing the manifest checksum to the computed one and remove it from the list.
 * @param ctx Artifact context
 * @param filename Unique key for the integrity item to check
 * @return MENDER_OK if integrity is enforced, error code otherwise
 * @note Call this for early validation after the processing the data of an item in the artifact stream
 */
mender_err_t mender_artifact_check_integrity_and_remove_item(mender_artifact_ctx_t *ctx, const char *filename);

/**
 * @brief Do integrity checks to the remaining items by comparing the manifest checksums to the computed ones.
 * @param ctx Artifact context
 * @return MENDER_OK if integrity is enforced, error code otherwise
 * @note Call this after the processing of the data from the artifact stream is complete
 */
mender_err_t mender_artifact_check_integrity_remaining(mender_artifact_ctx_t *ctx);

/**
 * @brief Compact the artifact context by dropping its auxiliary buffers
 */
void mender_artifact_compact_ctx(mender_artifact_ctx_t *ctx);

/**
 * @brief Function used to release artifact context
 * @param ctx Artifact context
 */
void mender_artifact_release_ctx(mender_artifact_ctx_t *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_ARTIFACT_PRIV_H__ */
