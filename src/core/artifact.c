/**
 * @file      artifact.c
 * @brief     Mender artifact parser
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

#include <errno.h>

#include "alloc.h"
#include "artifact.h"
#include "deployment-data.h"
#include "log.h"
#include "utils.h"

/**
 * @brief Device type key
 */
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#define MENDER_ARTIFACT_DEVICE_TYPE_KEY "device_type"
#endif

/**
 * @brief TAR file header
 */
typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
} mender_artifact_tar_header_t;

struct data_mdata_cache {
    const char *filename;
    char       *checksum_fname;
    cJSON      *meta_data;
    const char *deployment_id;
    const char *artifact_name;
    const char *payload_type;
    bool        valid;
};

/**
 * @brief Supported artifact format and version
 */
#define MENDER_ARTIFACT_SUPPORTED_FORMAT  "mender"
#define MENDER_ARTIFACT_SUPPORTED_VERSION 3

/**
 * @brief Parse header of TAR file
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_parse_tar_header(mender_artifact_ctx_t *ctx);

/**
 * @brief Read version file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and version verified, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_read_version(mender_artifact_ctx_t *ctx);

/**
 * @brief Read header-info file of the artifact
 * @param ctx Artifact context
 * @param dl_data Download data for the artifact
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_read_header_info(mender_artifact_ctx_t *ctx, mender_artifact_download_data_t *dl_data);

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
/**
 * @brief Read manifest file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and checksums retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_read_manifest(mender_artifact_ctx_t *ctx);

/**
 * @brief Read type-info file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_read_type_info(mender_artifact_ctx_t *ctx);

/**
 * @brief Parse provides/depends from JSON object
 * @param json_provides_depends JSON object to parse
 * @param provides_depends Pointer to the list of provides or depends
 * @return MENDER_SUCCESS if the function succeeds, MENDER_FAIL otherwise
 */
static mender_err_t artifact_parse_provides_depends(cJSON *json_provides_depends, mender_key_value_list_t **provides_depends);
#endif

/**
 * @brief Read meta-data file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_read_meta_data(mender_artifact_ctx_t *ctx);

/**
 * @brief Read data file of the artifact
 * @param ctx Artifact context
 * @param dl_data Download data for the artifact
 * @param mdata_cache Cache with metadata for the current data being processed
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_read_data(mender_artifact_ctx_t *ctx, mender_artifact_download_data_t *dl_data, struct data_mdata_cache *mdata_cache);

/**
 * @brief Prepare a cache with metadata for the current data being processed
 * @param ctx Artifact context
 * @param dl_data Download data for the artifact
 * @param mdata_cache Cache to populate
 * @return MENDER_OK in case of success, error otherwise
 */
static mender_err_t artifact_read_data_prepare(mender_artifact_ctx_t *ctx, mender_artifact_download_data_t *dl_data, struct data_mdata_cache *mdata_cache);

/**
 * @brief Invalidate the cache with metadata for the current data being processed
 * @param mdata_cache Cache to invalidate
 */
static inline void
data_mdata_cache_invalidate(struct data_mdata_cache *mdata_cache) {
    assert(NULL != mdata_cache);

    FREE_AND_NULL(mdata_cache->checksum_fname);
    mdata_cache->valid = false;
}

/**
 * @brief Process chunk of artifact data
 */
static mender_err_t process_artifact_data_callback(const char                      *deployment_id,
                                                   const char                      *type,
                                                   const char                      *artifact_name,
                                                   const cJSON                     *meta_data,
                                                   const char                      *filename,
                                                   size_t                           size,
                                                   void                            *data,
                                                   size_t                           index,
                                                   size_t                           length,
                                                   mender_artifact_download_data_t *dl_data);

/**
 * @brief Drop content of the current file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and dropped, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t artifact_drop_file(mender_artifact_ctx_t *ctx);

/**
 * @brief Shift data after parsing and update the respective checksum context
 * @param checksum_key Key under which the checksum for the data is calculated/checked
 * @param checksum_len Length of the data to include in the checksum update
 * @return MENDER_OK if the function succeeds, error code otherwise
 * @see artifact_shift_data()
 */
static mender_err_t artifact_shift_and_checksum_data(mender_artifact_ctx_t *ctx, size_t length, const char *checksum_key, size_t checksum_len);

/**
 * @brief Shift data after parsing
 * @param ctx Artifact context
 * @param length Length of data to shift
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t artifact_shift_data(mender_artifact_ctx_t *ctx, size_t length);

/**
 * @brief Compute length rounded up to increment (usually the block size)
 * @param length Length
 * @param incr Increment
 * @return Rounded length
 */
static size_t artifact_round_up(size_t length, size_t incr);

/**
 * @brief Artifact context
 */
static mender_artifact_ctx_t *artifact_ctx = NULL;

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
/**
 * @brief Get checksum entry for a file in the context
 * @param ctx The mender artifact context
 * @param filename The name of the file in the artifact
 * @return The checksum entry or NULL on error.
 * @note Since other files may be parsed before the manifest file, we need to
 *       create these entries in a lazy fashion.
 */
static mender_artifact_checksum_t *
artifact_checksum_get_or_create(mender_artifact_ctx_t *ctx, const char *filename) {
    assert(NULL != ctx);
    assert(NULL != filename);

    /* See if we already have an entry for this file */
    mender_artifact_checksum_t *checksum;
    for (checksum = ctx->artifact_info.checksums; NULL != checksum; checksum = checksum->next) {
        if (StringEqual(checksum->filename, filename)) {
            break;
        }
    }

    if (NULL == checksum) {
        /* Create new if entry not found */
        checksum = (mender_artifact_checksum_t *)mender_calloc(1, sizeof(mender_artifact_checksum_t));
        if (NULL == checksum) {
            mender_log_error("Unable to allocate memory");
            return NULL;
        }
        checksum->filename = mender_utils_strdup(filename);
        if (NULL == checksum->filename) {
            mender_log_error("Unable to allocate memory");
            mender_free(checksum);
            return NULL;
        }
        checksum->next               = ctx->artifact_info.checksums;
        ctx->artifact_info.checksums = checksum;

        /* Start SHA-256 checksum computation */
        if (MENDER_OK != mender_sha256_begin(&(checksum->context))) {
            mender_log_error("Failed to start checksum for file '%s'", filename);
            return NULL;
        }
    }

    return checksum;
}
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

static mender_err_t
is_checksum_valid(mender_artifact_checksum_t *checksum) {
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
    unsigned char computed[MENDER_DIGEST_BUFFER_SIZE];
    mender_log_debug("Checking integrity for artifact file '%s'", checksum->filename);

    if (MENDER_OK != mender_sha256_finish(checksum->context, computed)) {
        mender_log_error("Failed to finish checksum for file '%s'", checksum->filename);
        checksum->context = NULL;
        return MENDER_FAIL;
    }
    checksum->context = NULL;

    if (0 != memcmp(checksum->manifest, computed, MENDER_DIGEST_BUFFER_SIZE)) {
        mender_log_error("Computed checksum for file '%s' does not match manifest", checksum->filename);
#if CONFIG_MENDER_LOG_LEVEL >= MENDER_LOG_LEVEL_DBG
        /* Log the mismatching checksums for debugging */
        char checksum_str[(MENDER_DIGEST_BUFFER_SIZE * 2) + 1];

        for (int i = 0; i < MENDER_DIGEST_BUFFER_SIZE; i++) {
            if (2 != snprintf(checksum_str + (i * 2), 3, "%02hhx", checksum->manifest[i])) {
                break;
            }
        }
        mender_log_debug("%s: '%s' (manifest)", checksum->filename, checksum_str);

        for (int i = 0; i < MENDER_DIGEST_BUFFER_SIZE; i++) {
            if (2 != snprintf(checksum_str + (i * 2), 3, "%02hhx", computed[i])) {
                break;
            }
        }
        mender_log_debug("%s: '%s' (computed)", checksum->filename, checksum_str);
#endif /* CONFIG_MENDER_LOG_LEVEL >= MENDER_LOG_LEVEL_DBG */
        return MENDER_FAIL;
    }
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */
    return MENDER_OK;
}

mender_err_t
mender_artifact_check_integrity_and_remove_item(mender_artifact_ctx_t *ctx, const char *filename) {
    assert(NULL != ctx);

    mender_err_t                 ret          = MENDER_FAIL;
    mender_artifact_checksum_t **checksum_ptr = &ctx->artifact_info.checksums;
    mender_artifact_checksum_t  *checksum     = *checksum_ptr;
    while (NULL != checksum) {
        if (StringEqual(filename, checksum->filename)) {
            ret = is_checksum_valid(checksum);

            // Remove the node from the list and free the data
            *checksum_ptr = checksum->next;
            mender_free(checksum->filename);
            mender_sha256_finish(checksum->context, NULL);
            mender_free(checksum);
            checksum = *checksum_ptr;
        } else {
            checksum_ptr = &checksum->next;
            checksum     = checksum->next;
        }
    }
    return ret;
}

mender_err_t
mender_artifact_check_integrity_remaining(mender_artifact_ctx_t *ctx) {
    assert(NULL != ctx);
    for (mender_artifact_checksum_t *checksum = ctx->artifact_info.checksums; NULL != checksum; checksum = checksum->next) {
        if (MENDER_OK != is_checksum_valid(checksum)) {
            return MENDER_FAIL;
        }
    }
    return MENDER_OK;
}

mender_artifact_ctx_t *
mender_artifact_create_ctx(size_t buf_size) {

    mender_artifact_ctx_t *ctx;

    /* Create new context */
    if (NULL == (ctx = (mender_artifact_ctx_t *)mender_calloc(1, sizeof(mender_artifact_ctx_t)))) {
        mender_log_error("Unable to allocate memory for artifact context");
        return NULL;
    }
    if (NULL == (ctx->input.data = mender_malloc(buf_size))) {
        mender_log_error("Unable to allocate memory for artifact context buffer");
        mender_free(ctx);
        return NULL;
    }
    ctx->input.size      = buf_size;
    ctx->input.orig_size = buf_size;

    /* Save context */
    artifact_ctx = ctx;

    return ctx;
}

mender_err_t
mender_artifact_get_ctx(mender_artifact_ctx_t **ctx) {

    assert(NULL != ctx);

    if (NULL == artifact_ctx) {
        return MENDER_FAIL;
    }

    *ctx = artifact_ctx;
    return MENDER_OK;
}

static bool
is_compressed(const char *filename) {

    /* Mender artifact supports `.gz`, `.xz`, and `.zst` */
    static const char *compression_suffixes[] = { ".gz", ".xz", ".zst", NULL };

    for (size_t i = 0; NULL != compression_suffixes[i]; i++) {
        if (mender_utils_strendswith(filename, compression_suffixes[i])) {
            return true;
        }
    }

    return false;
}

static struct data_mdata_cache data_mdata_cache = { 0 };

mender_err_t
mender_artifact_process_data(mender_artifact_ctx_t *ctx, void *input_data, size_t input_length, mender_artifact_download_data_t *dl_data) {

    assert(NULL != ctx);
    mender_err_t ret = MENDER_OK;
    void        *tmp;
    size_t       new_size;
    size_t       expected_required;

    /* Copy data to the end of the internal buffer */
    if ((NULL != input_data) && (0 != input_length)) {
        if ((ctx->input.length + input_length) > ctx->input.size) {
            new_size = ctx->input.length + input_length;
            /* data/ files are processed per block for which the original size of the buffer should
               be enough, but metadata is processed as whole files so there we expect we will need
               more, except for header.tar (and tarballs in general) which are processed
               transparently. */
            if (mender_utils_strbeginswith(ctx->file.name, "data/")) {
                expected_required = ctx->input.orig_size;
            } else if (mender_utils_strendswith(ctx->file.name, ".tar")) {
                expected_required = ctx->input.orig_size;
            } else {
                expected_required = artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE) + MENDER_ARTIFACT_STREAM_BLOCK_SIZE;
            }
            if (new_size > expected_required) {
                mender_log_debug("Reallocating artifact context buffer to %zd [SHOULD NOT BE HAPPENING!]", new_size);
            }
            /* Let's try to get what we expect we will need anyway and if we don't get that much,
               let's get the minimum required now, leaving us with a chance to get more later. */
            if (NULL == (tmp = mender_realloc(ctx->input.data, MAX(new_size, expected_required)))) {
                if (NULL == (tmp = mender_realloc(ctx->input.data, new_size))) {
                    /* Unable to allocate memory */
                    return MENDER_FAIL;
                }
                ctx->input.size = new_size;
            } else {
                ctx->input.size = MAX(new_size, expected_required);
            }
            ctx->input.data = tmp;
        }
        memcpy((void *)(((uint8_t *)ctx->input.data) + ctx->input.length), input_data, input_length);
        ctx->input.length += input_length;
    }

    /* Parse data */
    do {

        /* Treatment depending of the stream state */
        if (MENDER_ARTIFACT_STREAM_STATE_PARSING_HEADER == ctx->stream_state) {

            /* Parse TAR header */
            ret = artifact_parse_tar_header(ctx);

            /* Processing a new (data) file, invalidate the cache */
            data_mdata_cache_invalidate(&data_mdata_cache);

        } else if (MENDER_ARTIFACT_STREAM_STATE_PARSING_DATA == ctx->stream_state) {

            /* Treatment depending of the file name */
            if (StringEqual(ctx->file.name, "version")) {

                /* Validate artifact version */
                ret = artifact_read_version(ctx);

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
            } else if (StringEqual(ctx->file.name, "manifest")) {

                /* Read manifest file */
                ret = artifact_read_manifest(ctx);

                /* Early integrity check for version file */
                if ((MENDER_DONE == ret) && (MENDER_OK != mender_artifact_check_integrity_and_remove_item(ctx, "version"))) {
                    mender_log_error("Integrity check failed for version file");
                    ret = MENDER_FAIL;
                }
#endif
            } else if (StringEqual(ctx->file.name, "header.tar/header-info")) {

                /* Read header-info file */
                ret = artifact_read_header_info(ctx, dl_data);

            } else if ((true == mender_utils_strbeginswith(ctx->file.name, "header.tar/headers"))
                       && (true == mender_utils_strendswith(ctx->file.name, "meta-data"))) {

                /* Read meta-data file */
                ret = artifact_read_meta_data(ctx);

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
            } else if (mender_utils_strbeginswith(ctx->file.name, "header.tar/headers") && mender_utils_strendswith(ctx->file.name, "type-info")) {

                /* Read type-info file */
                ret = artifact_read_type_info(ctx);
#endif
            } else if ((mender_utils_strbeginswith(ctx->file.name, "data")) && (strlen(ctx->file.name) > strlen("data/xxxx.tar"))) {
                /* Processing data. But the first "file" is data/0000.tar which
                   is not a real file, it's just the beginning of the tarball
                   for which we don't need to do anything here. Hence the
                   strlen() check above. */
                if (!data_mdata_cache.valid) {

                    /* Early integrity check for header.tar */
                    if (MENDER_OK != mender_artifact_check_integrity_and_remove_item(ctx, "header.tar")) {
                        mender_log_error("Integrity check failed for header.tar");
                        ret = MENDER_FAIL;
                    } else {
                        /* Populate the cache and do one-off things */
                        ret = artifact_read_data_prepare(ctx, dl_data, &data_mdata_cache);
                    }
                }

                if (MENDER_OK == ret) {
                    assert(data_mdata_cache.valid);
                    /* Read data */
                    ret = artifact_read_data(ctx, dl_data, &data_mdata_cache);
                }
            } else if (false == mender_utils_strendswith(ctx->file.name, ".tar")) {

                /* Drop data, file is not relevant */
                ret = artifact_drop_file(ctx);
            } else {

                /* Nothing to do */
                ret = MENDER_DONE;
            }

            /* Check if file have been parsed and treatment done */
            if (MENDER_DONE == ret) {

                /* Remove the previous file name */
                char *substring = mender_utils_strrstr(ctx->file.name, ".tar");
                if (NULL != substring) {
                    *(substring + strlen(".tar")) = '\0';
                } else {
                    FREE_AND_NULL(ctx->file.name);
                }
                ctx->file.size  = 0;
                ctx->file.index = 0;

                /* Update the stream state machine */
                ctx->stream_state = MENDER_ARTIFACT_STREAM_STATE_PARSING_HEADER;
            }
        }
    } while (MENDER_DONE == ret);

    return ret;
}

void
mender_artifact_compact_ctx(mender_artifact_ctx_t *ctx) {
    if (NULL == ctx) {
        return;
    }
    FREE_AND_NULL(ctx->input.data);
    ctx->input.length = 0;
    ctx->input.size   = 0;
    FREE_AND_NULL(ctx->file.name);
}

void
mender_artifact_release_ctx(mender_artifact_ctx_t *ctx) {

    /* Release memory */
    if (NULL != ctx) {
        mender_free(ctx->input.data);
        if (NULL != ctx->payloads.values) {
            for (size_t index = 0; index < ctx->payloads.size; index++) {
                mender_free(ctx->payloads.values[index].type);
                cJSON_Delete(ctx->payloads.values[index].meta_data);

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
                mender_utils_key_value_list_free(ctx->payloads.values[index].provides);
                mender_utils_key_value_list_free(ctx->payloads.values[index].depends);
                for (size_t i = 0; i < ctx->payloads.values[index].clears_provides_size; i++) {
                    mender_free(ctx->payloads.values[index].clears_provides[i]);
                }
                mender_free(ctx->payloads.values[index].clears_provides);
#endif
            }
            mender_free(ctx->payloads.values);
        }
        mender_free(ctx->file.name);
#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
        mender_utils_key_value_list_free(ctx->artifact_info.provides);
        mender_utils_key_value_list_free(ctx->artifact_info.depends);
        mender_artifact_checksum_t *next;
        for (mender_artifact_checksum_t *checksum = ctx->artifact_info.checksums; NULL != checksum; checksum = next) {
            mender_free(checksum->filename);
            mender_sha256_finish(checksum->context, NULL);
            next = checksum->next;
            mender_free(checksum);
        }
        ctx->artifact_info.checksums = NULL;
#endif
        if (artifact_ctx == ctx) {
            artifact_ctx = NULL;
        }

        mender_free(ctx);
    }
}

static mender_err_t
artifact_parse_tar_header(mender_artifact_ctx_t *ctx) {
    assert(NULL != ctx);

    char *tmp;
    bool  in_header_tar;

    /* Check if enough data are received (at least one block) */
    if ((NULL == ctx->input.data) || (ctx->input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
        return MENDER_OK;
    }

    /* Cast block to TAR header structure */
    mender_artifact_tar_header_t *tar_header = (mender_artifact_tar_header_t *)ctx->input.data;

    /* Check if file name is provided, else the end of the current TAR file is reached */
    if ('\0' == tar_header->name[0]) {

        /* Check if enough data are received (at least 2 blocks) */
        if (ctx->input.length < 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE) {
            return MENDER_OK;
        }

        in_header_tar = (NULL != ctx->file.name) && StringEqual(ctx->file.name, "header.tar");

        /* Remove the TAR file name */
        if (NULL != ctx->file.name) {
            char *substring = mender_utils_strrstr(ctx->file.name, ".tar");
            if (NULL != substring) {
                *substring = '\0';
                substring  = mender_utils_strrstr(ctx->file.name, ".tar");
                if (NULL != substring) {
                    *(substring + strlen(".tar")) = '\0';
                } else {
                    FREE_AND_NULL(ctx->file.name);
                }
            } else {
                FREE_AND_NULL(ctx->file.name);
            }
        }

        /* Shift data in the buffer */
        /* header.tar has a checksum entry in the manifest as a whole so we need
           to include its empty blocks into checksum calculation */
        if (in_header_tar) {
            if (MENDER_OK
                != artifact_shift_and_checksum_data(ctx, 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE, "header.tar", 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
                mender_log_error("Unable to shift and checksum input data");
                return MENDER_FAIL;
            }
        } else {
            if (MENDER_OK != artifact_shift_data(ctx, 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
                mender_log_error("Unable to shift input data");
                return MENDER_FAIL;
            }
        }

        return MENDER_DONE;
    }

    /* Check magic */
    if (strncmp(tar_header->magic, "ustar", strlen("ustar"))) {
        /* Invalid magic */
        mender_log_error("Invalid magic");
        return MENDER_FAIL;
    }

    /* Compute the new file name */
    if (NULL != ctx->file.name) {
        size_t str_length = strlen(ctx->file.name) + strlen("/") + strlen(tar_header->name) + 1;
        if (NULL == (tmp = (char *)mender_malloc(str_length))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
        snprintf(tmp, str_length, "%s/%s", ctx->file.name, tar_header->name);
        mender_free(ctx->file.name);
    } else {
        if (NULL == (tmp = mender_utils_strdup(tar_header->name))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
    }
    ctx->file.name = tmp;

    /* Retrieve file size */
    assert(sizeof(size_t) >= sizeof(unsigned long));
    char *end_ptr;
    errno = 0; /* to distinguish between success/failure */

    ctx->file.size = strtoul(tar_header->size, &end_ptr, 8);
    if ((end_ptr == tar_header->size) /* no conversion */
        || (0 != errno)) {            /* out of range (for unsigned long) */
        mender_log_error("Unable to retrieve file size");
        return MENDER_FAIL;
    }

    ctx->file.index = 0;

    /* Shift data in the buffer */
    /* header.tar has a checksum entry in the manifest as a whole so we need
       to include its TAR header blocks into checksum calculation */
    in_header_tar = mender_utils_strbeginswith(ctx->file.name, "header.tar/");
    if (in_header_tar) {
        if (MENDER_OK != artifact_shift_and_checksum_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE, "header.tar", MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
            mender_log_error("Unable to shift and checksum input data");
            return MENDER_FAIL;
        }
    } else {
        if (MENDER_OK != artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
            mender_log_error("Unable to shift input data");
            return MENDER_FAIL;
        }
    }

    /* Update the stream state machine */
    ctx->stream_state = MENDER_ARTIFACT_STREAM_STATE_PARSING_DATA;

    return MENDER_DONE;
}

static mender_err_t
artifact_read_version(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    cJSON       *object = NULL;
    mender_err_t ret    = MENDER_DONE;

    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        return MENDER_OK;
    }

    /* Check version file */
    if (NULL == (object = cJSON_ParseWithLength(ctx->input.data, ctx->file.size))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    cJSON *json_format = cJSON_GetObjectItemCaseSensitive(object, "format");
    if (true == cJSON_IsString(json_format)) {
        if (!StringEqual(cJSON_GetStringValue(json_format), MENDER_ARTIFACT_SUPPORTED_FORMAT)) {
            mender_log_error("Invalid version format");
            ret = MENDER_FAIL;
            goto END;
        }
    } else {
        mender_log_error("Invalid version file");
        ret = MENDER_FAIL;
        goto END;
    }
    cJSON *json_version = cJSON_GetObjectItemCaseSensitive(object, "version");
    if (true == cJSON_IsNumber(json_version)) {
        if (MENDER_ARTIFACT_SUPPORTED_VERSION != (int)cJSON_GetNumberValue(json_version)) {
            mender_log_error("Invalid version value");
            ret = MENDER_FAIL;
            goto END;
        }
    } else {
        mender_log_error("Invalid version file");
        ret = MENDER_FAIL;
        goto END;
    }
    mender_log_debug("Artifact has valid version");

    /* Shift data in the buffer */
    if (MENDER_OK != artifact_shift_and_checksum_data(ctx, artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE), "version", ctx->file.size)) {
        mender_log_error("Unable to shift and checksum input data");
        ret = MENDER_FAIL;
        goto END;
    }

END:

    /* Release memory */
    cJSON_Delete(object);

    return ret;
}

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
mender_err_t
mender_artifact_get_device_type(mender_artifact_ctx_t *ctx, const char **device_type) {

    assert(NULL != ctx);
    assert(NULL != device_type);

    mender_key_value_list_t *item = ctx->artifact_info.depends;
    while (NULL != item) {
        if (NULL != item->key) {
            if (StringEqual(MENDER_ARTIFACT_DEVICE_TYPE_KEY, item->key)) {
                *device_type = item->value;
                return MENDER_OK;
            }
        }
        item = item->next;
    }
    return MENDER_FAIL;
}

static mender_err_t
artifact_read_manifest(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);

    /* Check if all data has been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        return MENDER_OK;
    }

    /*  The expected format matches the output of sha256sum: sum and the name of the file separated by two spaces
        1d0b820130ae028ce8a79b7e217fe505a765ac394718e795d454941487c53d32  data/0000/update.ext4
        4d480539cdb23a4aee6330ff80673a5af92b7793eb1c57c4694532f96383b619  header.tar.gz
        52c76ab66947278a897c2a6df8b4d77badfa343fec7ba3b2983c2ecbbb041a35  version
    */

    /* Read data line by line */
    char *line = ctx->input.data;
    char *end  = line + ctx->input.length;
    while (line < end) {
        char *next = strchr(line, '\n');
        if (NULL == next) {
            break;
        }
        *next = '\0';

        /* Process line */
        char *separator = strstr(line, "  ");
        if (NULL == separator) {
            mender_log_error("Invalid manifest file");
            return MENDER_FAIL;
        }
        *separator = '\0';

        const char *checksum_str = line;
        const char *filename     = separator + 2;

        /* We do not support compressed artifacts */
        if (mender_utils_strbeginswith(filename, "header.tar") && is_compressed(filename)) {
            mender_log_error("Artifact compression is not supported");
            return MENDER_FAIL;
        }

        /* Useful when debugging artifact integrity check failures */
        mender_log_debug("%s  %s", checksum_str, filename);

        /* Make sure digest is of expected length (two hex per byte) */
        if ((MENDER_DIGEST_BUFFER_SIZE * 2) != strlen(checksum_str)) {
            mender_log_error("Bad checksum '%s' in manifest for file '%s'", checksum_str, filename);
            return MENDER_FAIL;
        }

        /* Get checksum entry for the file (creates one if not found) */
        mender_artifact_checksum_t *checksum;
        if (NULL == (checksum = artifact_checksum_get_or_create(ctx, filename))) {
            /* Error already logged */
            return MENDER_FAIL;
        }

        /* Populate with manifest checksum */
        if (!mender_utils_hexdump_to_bytes(checksum_str, checksum->manifest, MENDER_DIGEST_BUFFER_SIZE)) {
            mender_log_error("Bad checksum '%s' in manifest for file '%s'", checksum_str, filename);
            return MENDER_FAIL;
        }

        ///* Move to the next line */
        line = next + 1;
    }

    /* Shift data in the buffer */
    if (MENDER_OK != artifact_shift_data(ctx, artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        mender_log_error("Unable to shift input data");
        return MENDER_FAIL;
    }

    return MENDER_DONE;
}

static mender_err_t
artifact_parse_provides_depends(cJSON *json_provides_depends, mender_key_value_list_t **provides_depends) {

    assert(NULL != json_provides_depends);
    assert(NULL != provides_depends);

    /* Create linked-list from json object */
    /* The elements can either be a string or an array of strings */
    cJSON *json_element = NULL;
    cJSON_ArrayForEach(json_element, json_provides_depends) {
        if (cJSON_IsString(json_element)) {
            if (MENDER_OK != mender_utils_key_value_list_create_node(json_element->string, json_element->valuestring, provides_depends)) {
                mender_log_error("Unable to create linked list node for string element");
                goto ERROR;
            }
        } else if (cJSON_IsArray(json_element)) {
            cJSON *json_element_value = NULL;
            cJSON_ArrayForEach(json_element_value, json_element) {
                if (MENDER_OK != mender_utils_key_value_list_create_node(json_element->string, json_element_value->valuestring, provides_depends)) {
                    mender_log_error("Unable to create linked list node for array element");
                    goto ERROR;
                }
            }
        } else {
            mender_log_error("Invalid header-info file element type");
            goto ERROR;
        }
    }

    return MENDER_OK;

ERROR:
    /* Free linked list in case of error */
    mender_utils_key_value_list_free(*provides_depends);
    return MENDER_FAIL;
}
#endif

static mender_err_t
artifact_read_header_info(mender_artifact_ctx_t *ctx, mender_artifact_download_data_t *dl_data) {

    assert(NULL != ctx);
    cJSON       *object = NULL;
    mender_err_t ret    = MENDER_DONE;
    size_t       rounded_file_size;

    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < (rounded_file_size = artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)))) {
        return MENDER_OK;
    }

    /* Read header-info */
    if (NULL == (object = cJSON_ParseWithLength(ctx->input.data, ctx->file.size))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    cJSON *json_payloads = cJSON_GetObjectItemCaseSensitive(object, "payloads");
    if (true == cJSON_IsArray(json_payloads)) {
        ctx->payloads.size = cJSON_GetArraySize(json_payloads);
        if (NULL == (ctx->payloads.values = (mender_artifact_payload_t *)mender_calloc(ctx->payloads.size, sizeof(mender_artifact_payload_t)))) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }
        size_t index        = 0;
        cJSON *json_payload = NULL;
        cJSON_ArrayForEach(json_payload, json_payloads) {
            if (true == cJSON_IsObject(json_payload)) {
                cJSON *json_payload_type = cJSON_GetObjectItemCaseSensitive(json_payload, "type");
                if (cJSON_IsString(json_payload_type)) {
                    if (NULL == (ctx->payloads.values[index].type = mender_utils_strdup(cJSON_GetStringValue(json_payload_type)))) {
                        mender_log_error("Unable to allocate memory");
                        ret = MENDER_FAIL;
                        goto END;
                    }
                    const char *payload_type = ctx->payloads.values[index].type;
                    /* Choose update module */
                    dl_data->update_module = mender_update_module_get(payload_type);
                    if (NULL == dl_data->update_module) {
                        /* Content is not supported by the mender-mcu-client */
                        mender_log_error("Unable to handle artifact type '%s'", payload_type);
                        ret = MENDER_FAIL;
                        goto END;
                    }
                    /* Add the payload type to deployment data  */
                    if (MENDER_OK != mender_deployment_data_add_payload_type(dl_data->deployment, payload_type)) {
                        /* Error already logged */
                        ret = MENDER_FAIL;
                        goto END;
                    }
                } else {
                    mender_log_error("Invalid header-info file");
                    ret = MENDER_FAIL;
                    goto END;
                }
            } else {
                mender_log_error("Invalid header-info file");
                ret = MENDER_FAIL;
                goto END;
            }
            index++;
        }

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
        cJSON *json_provides = cJSON_GetObjectItemCaseSensitive(object, "artifact_provides");
        if (cJSON_IsObject(json_provides)) {
            if (MENDER_FAIL == artifact_parse_provides_depends(json_provides, &(ctx->artifact_info.provides))) {
                mender_log_error("Unable to parse artifact_provides");
                ret = MENDER_FAIL;
                goto END;
            }
        }

        cJSON *json_depends = cJSON_GetObjectItemCaseSensitive(object, "artifact_depends");
        if (cJSON_IsObject(json_depends)) {
            if (MENDER_FAIL == artifact_parse_provides_depends(json_depends, &(ctx->artifact_info.depends))) {
                mender_log_error("Unable to parse artifact_depends");
                ret = MENDER_FAIL;
                goto END;
            }
        }
#endif

    } else {
        mender_log_error("Invalid header-info file");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Shift data in the buffer */
    /* header.tar has a checksum entry in the manifest as a whole */
    if (MENDER_OK != artifact_shift_and_checksum_data(ctx, rounded_file_size, "header.tar", rounded_file_size)) {
        mender_log_error("Unable to shift and checksum input data");
        ret = MENDER_FAIL;
        goto END;
    }

END:

    /* Release memory */
    cJSON_Delete(object);

    return ret;
}

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
static mender_err_t
artifact_read_type_info(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    cJSON       *object = NULL;
    mender_err_t ret    = MENDER_DONE;
    size_t       index  = 0;
    size_t       rounded_file_size;

    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < (rounded_file_size = artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)))) {
        return MENDER_OK;
    }

    /* Read type-info */
    if (NULL == (object = cJSON_ParseWithLength(ctx->input.data, ctx->file.size))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Check if payload index is valid */
    if (NULL == ctx->payloads.values[index].type) {
        mender_log_error("Invalid artifact format; no payload found for index %d", index);
        ret = MENDER_FAIL;
        goto END;
    }

    cJSON *json_provides = cJSON_GetObjectItemCaseSensitive(object, "artifact_provides");
    if (cJSON_IsObject(json_provides)) {
        if (MENDER_FAIL == artifact_parse_provides_depends(json_provides, &(ctx->payloads.values[index].provides))) {
            mender_log_error("Unable to parse artifact_provides");
            ret = MENDER_FAIL;
            goto END;
        }
    }

    cJSON *json_depends = cJSON_GetObjectItemCaseSensitive(object, "artifact_depends");
    if (cJSON_IsObject(json_depends)) {
        if (MENDER_FAIL == artifact_parse_provides_depends(json_depends, &(ctx->payloads.values[index].depends))) {
            mender_log_error("Unable to parse artifact_depends");
            ret = MENDER_FAIL;
            goto END;
        }
    }

    cJSON *json_clears_provides = cJSON_GetObjectItemCaseSensitive(object, "clears_artifact_provides");
    if (cJSON_IsArray(json_clears_provides)) {
        ctx->payloads.values[index].clears_provides_size = cJSON_GetArraySize(json_clears_provides);
        ctx->payloads.values[index].clears_provides      = (char **)mender_calloc(ctx->payloads.values[index].clears_provides_size, sizeof(char *));
        if (NULL == ctx->payloads.values[index].clears_provides) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }

        size_t i                            = 0;
        cJSON *json_clears_provides_element = NULL;

        cJSON_ArrayForEach(json_clears_provides_element, json_clears_provides) {
            if (cJSON_IsString(json_clears_provides_element)) {
                char *clears_provides = mender_utils_strdup(json_clears_provides_element->valuestring);
                if (NULL == clears_provides) {
                    mender_log_error("Unable to allocate memory");
                    ret = MENDER_FAIL;
                    goto END;
                }
                ctx->payloads.values[index].clears_provides[i] = clears_provides;
                i++;
            } else {
                mender_log_error("Invalid header-info file");
                ret = MENDER_FAIL;
                goto END;
            }
        }
    }

    /* Shift data in the buffer */
    /* header.tar has a checksum entry in the manifest as a whole */
    if (MENDER_OK != artifact_shift_and_checksum_data(ctx, rounded_file_size, "header.tar", rounded_file_size)) {
        mender_log_error("Unable to shift and checksum input data");
        ret = MENDER_FAIL;
        goto END;
    }

END:

    /* Release memory */
    cJSON_Delete(object);

    return ret;
}
#endif

static mender_err_t
artifact_read_meta_data(mender_artifact_ctx_t *ctx) {
    assert(NULL != ctx);
    size_t rounded_file_size;

    /* Retrieve payload index. We expect "header.tar/headers/%u/meta-data" where
     * %u is the index. Yes sscanf(3) would be nice, but we've experienced
     * unexplained segmentation faults on some hardware when using it. */
    const char *const prefix = "header.tar/headers/";
    if (!mender_utils_strbeginswith(ctx->file.name, prefix)) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }

    assert(sizeof(size_t) >= sizeof(unsigned long));
    const char *start_ptr = ctx->file.name + strlen(prefix);
    char       *end_ptr;
    errno = 0; /* to distinguish between success/failure */

    const size_t index = strtoul(start_ptr, &end_ptr, 10);
    if ((end_ptr == start_ptr)              /* no conversion */
        || (0 != errno)                     /* out of range (for unsigned long) */
        || (index >= ctx->payloads.size)) { /* index out of bounds */
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }

    assert(NULL != end_ptr);
    assert(StringEqualN(end_ptr, "/meta-data", 10)); /* just one last sanity check */

    /* Check size of the meta-data */
    if (0 == ctx->file.size) {
        /* Nothing to do */
        return MENDER_DONE;
    }

    /* Check if all data have been received */
    rounded_file_size = artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE);
    if ((NULL == ctx->input.data) || (ctx->input.length < rounded_file_size)) {
        return MENDER_OK;
    }

    /* Read meta-data */
    if (NULL == (ctx->payloads.values[index].meta_data = cJSON_ParseWithLength(ctx->input.data, ctx->file.size))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Shift data in the buffer */
    /* header.tar has a checksum entry in the manifest as a whole */
    if (MENDER_OK != artifact_shift_and_checksum_data(ctx, rounded_file_size, "header.tar", rounded_file_size)) {
        mender_log_error("Unable to shift and checksum input data");
        return MENDER_FAIL;
    }

    return MENDER_DONE;
}

/**
 * @brief Callback function to be invoked to perform the treatment of the data from the artifact
 * @param deployment_id Deployment ID
 * @param type Type from header-info payloads
 * @param artifact_name Artifact name
 * @param meta_data Meta-data from header tarball
 * @param filename Artifact filename
 * @param size Artifact file size
 * @param data Artifact data
 * @param index Artifact data index
 * @param length Artifact data length
 * @param dl_data Download data for the artifact
 * @return MENDER_OK if the function succeeds, error code if an error occurred
 */
static mender_err_t
process_artifact_data_callback(const char                      *deployment_id,
                               const char                      *type,
                               const char                      *artifact_name,
                               const cJSON                     *meta_data,
                               const char                      *filename,
                               size_t                           size,
                               void                            *data,
                               size_t                           index,
                               size_t                           length,
                               mender_artifact_download_data_t *dl_data) {

    assert(NULL != type);
    mender_err_t ret = MENDER_FAIL;

#if CONFIG_MENDER_LOG_LEVEL >= MENDER_LOG_LEVEL_INF
    if (size > 0) {
        static size_t download_progress = 0;
        /* New update */
        if (0 == index) {
            download_progress = 0;
        }

        /* Update every 10% */
        if (((index * 10) / size) > download_progress) {
            download_progress = (index * 10) / size;
            mender_log_info("Downloading '%s' %zu0%%... [%zu/%zu]", type, download_progress, index, size);
        }
    }
#endif

    /* Invoke update module download callback */
    struct mender_update_download_state_data_s download_state_data
        = { deployment_id, artifact_name, type, meta_data, filename, size, data, index, length, false };
    mender_update_state_data_t state_data = { .download_state_data = &download_state_data };
    if (MENDER_OK != (ret = dl_data->update_module->callbacks[MENDER_UPDATE_STATE_DOWNLOAD](MENDER_UPDATE_STATE_DOWNLOAD, state_data))) {
        mender_log_error("An error occurred while processing data of the artifact '%s' of type '%s'", artifact_name, type);
        return ret;
    }

    return MENDER_OK;
}

static mender_err_t
artifact_read_data_prepare(mender_artifact_ctx_t *ctx, mender_artifact_download_data_t *dl_data, struct data_mdata_cache *mdata_cache) {
    /* First, retrieve payload index. We expect "data/%u.tar" where %u is the
     * index. Yes sscanf(3) would be nice, but we've experienced unexplained
     * segmentation faults on some hardware when using it. */
    const char *const prefix = "data/";
    if (!mender_utils_strbeginswith(ctx->file.name, prefix)) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }

    size_t file_name_length = strlen(ctx->file.name);
    /* We check the length to make sure we only check for compression on the
     * payload itself - not the files inside the payload */
    if ((strlen("data/xxxx.tar.xx") == file_name_length) || (strlen("data/xxxx.tar.xxx") == file_name_length)) {
        /*
        * We allow compressed files _inside_ a payload:
        *   'data/0000.tar/compressed.tar.gz'
        * But not a compressed payload:
        *   'data/0000.tar[.gz|.xz|.zst]'
        **/
        if (is_compressed(ctx->file.name)) {
            mender_log_error("Artifact compression is not supported");
            return MENDER_FAIL;
        }
    }

    assert(sizeof(size_t) >= sizeof(unsigned long));
    const char *start_ptr = ctx->file.name + strlen(prefix);
    char       *end_ptr;
    errno = 0; /* to distinguish between success/failure */

    const size_t index = strtoul(start_ptr, &end_ptr, 10);
    if ((end_ptr == start_ptr)              /* no conversion */
        || (0 != errno)                     /* out of range (for unsigned long) */
        || (index >= ctx->payloads.size)) { /* index out of bounds */
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }

    assert(NULL != end_ptr);
    assert(StringEqualN(end_ptr, ".tar", 4)); /* just one last sanity check */

    const char *payload_type = ctx->payloads.values[index].type;

    /* Retrieve ID and artifact name */
    if (MENDER_OK != mender_deployment_data_get_id(dl_data->deployment, &(mdata_cache->deployment_id))) {
        mender_log_error("Unable to get ID from the deployment data");
        return MENDER_FAIL;
    }
    if (MENDER_OK != mender_deployment_data_get_artifact_name(dl_data->deployment, &(mdata_cache->artifact_name))) {
        mender_log_error("Unable to get artifact name from the deployment data");
        return MENDER_FAIL;
    }

    mdata_cache->payload_type = payload_type;
    mdata_cache->meta_data    = ctx->payloads.values[index].meta_data;
    mdata_cache->filename     = strstr(ctx->file.name, ".tar") + strlen(".tar") + 1;

    /* The filename will be something like
     * 'data/0000.tar/zephyr.signed.bin'. But the manifest will hold
     * 'data/0000/zephyr.signed.bin'. Hence, we need to remove the
     * '.tar' extension from the string.
     */
    if (NULL == (mdata_cache->checksum_fname = mender_utils_strdup(ctx->file.name))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    bool done = false;
    for (char *ch = strstr(mdata_cache->checksum_fname, ".tar"); (NULL != ch) && !done; ch++) {
        /* Don't worry! The call to strlen() on a static string should
         * be optimized out by the compiler */
        done = (*ch = ch[strlen(".tar")]) == '\0';
    }

    mdata_cache->valid = true;
    return MENDER_OK;
}

static mender_err_t
artifact_read_data(mender_artifact_ctx_t *ctx, mender_artifact_download_data_t *dl_data, struct data_mdata_cache *mdata_cache) {

    assert(NULL != ctx);
    mender_err_t ret;

    /* Check size of the data */
    if (0 == artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
        /* Nothing to do */
        return MENDER_DONE;
    }

    /* Parse data until the end of the file has been reached */
    do {

        /* Check if enough data are received (at least one block) */
        if ((NULL == ctx->input.data) || (ctx->input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
            return MENDER_OK;
        }

        /* Compute length */
        size_t length
            = ((ctx->file.size - ctx->file.index) > MENDER_ARTIFACT_STREAM_BLOCK_SIZE) ? MENDER_ARTIFACT_STREAM_BLOCK_SIZE : (ctx->file.size - ctx->file.index);

        /* Invoke the download artifact callback */
        ret = process_artifact_data_callback(mdata_cache->deployment_id,
                                             mdata_cache->payload_type,
                                             mdata_cache->artifact_name,
                                             mdata_cache->meta_data,
                                             mdata_cache->filename,
                                             ctx->file.size,
                                             ctx->input.data,
                                             ctx->file.index,
                                             length,
                                             dl_data);
        if (MENDER_OK != ret) {
            mender_log_error("An error occurred");
            return ret;
        }

        /* Update index */
        ctx->file.index += MENDER_ARTIFACT_STREAM_BLOCK_SIZE;

        /* Shift data in the buffer */
        if (MENDER_OK != (ret = artifact_shift_and_checksum_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE, mdata_cache->checksum_fname, length))) {
            mender_log_error("Unable to shift and checksum input data");
            return ret;
        }

    } while (ctx->file.index < ctx->file.size);

    return MENDER_DONE;
}

static mender_err_t
artifact_drop_file(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    mender_err_t ret;

    /* Check size of the data */
    if (0 == artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
        /* Nothing to do */
        return MENDER_DONE;
    }

    /* Parse data until the end of the file has been reached */
    do {

        /* Check if enough data are received (at least one block) */
        if ((NULL == ctx->input.data) || (ctx->input.length < MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
            return MENDER_OK;
        }

        /* Update index */
        ctx->file.index += MENDER_ARTIFACT_STREAM_BLOCK_SIZE;

        /* Shift data in the buffer */
        if (MENDER_OK != (ret = artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
            mender_log_error("Unable to shift input data");
            return ret;
        }

    } while (ctx->file.index < ctx->file.size);

    return MENDER_DONE;
}

static mender_err_t
artifact_shift_and_checksum_data(mender_artifact_ctx_t *ctx, size_t length, const char *checksum_key, size_t checksum_len) {
    assert(NULL != ctx);
    assert(ctx->input.length >= length);
    assert(checksum_len <= length);

    if (0 == length) {
        return MENDER_OK;
    }

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
    if ((NULL != checksum_key) && (0 != checksum_len)) {
        mender_artifact_checksum_t *checksum;
        /* Get checksum entry (create one if needed) */
        if (NULL == (checksum = artifact_checksum_get_or_create(ctx, checksum_key))) {
            /* Error already logged */
            return MENDER_FAIL;
        }

        if (MENDER_OK != mender_sha256_update(checksum->context, ctx->input.data, checksum_len)) {
            mender_log_error("Failed to update update checksum");
            return MENDER_FAIL;
        }
    }
#else
    /* Only to make the arguments "used" in this case. */
    (void)checksum_key;
    (void)checksum_len;
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

    return artifact_shift_data(ctx, length);
}

static mender_err_t
artifact_shift_data(mender_artifact_ctx_t *ctx, size_t length) {

    assert(NULL != ctx);

    /* Shift data */
    if (length > 0) {
        if (ctx->input.length > length) {
            memmove(ctx->input.data, (void *)(((uint8_t *)ctx->input.data) + length), ctx->input.length - length);
            ctx->input.length -= length;
            /* Here we could shrink the ctx->input.data buffer, but most likely, we would need to
               grow it again when we receive another batch of data so there's little point in doing
               so. */
        } else {
            ctx->input.length = 0;
        }
    }

    return MENDER_OK;
}

static size_t
artifact_round_up(size_t length, size_t incr) {
    return length + (incr - length % incr) % incr;
}
