/**
 * @file      mender-artifact.c
 * @brief     Mender artifact parser
 *
 * MIT License
 *
 * Copyright (c) 2022-2023 joelguittet and mender-mcu-client contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "mender-artifact.h"
#include "mender-log.h"

/**
 * @brief TAR block size
 */
#define MENDER_ARTIFACT_STREAM_BLOCK_SIZE (512)

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

/**
 * @brief Supported artifact format and version
 */
#define MENDER_ARTIFACT_SUPPORTED_FORMAT  "mender"
#define MENDER_ARTIFACT_SUPPORTED_VERSION (3)

/**
 * @brief Parse header of TAR file
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_parse_tar_header(mender_artifact_ctx_t *ctx);

/**
 * @brief Read version file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and version verified, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_read_version(mender_artifact_ctx_t *ctx);

/**
 * @brief Read header-info file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_read_header_info(mender_artifact_ctx_t *ctx);

#ifdef MENDER_FULL_PARSE_ARTIFACT
/**
 * @brief Read manifest file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and checksums retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_read_manifest(mender_artifact_ctx_t *ctx);

/**
 * @brief Read type-info file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_read_type_info(mender_artifact_ctx_t *ctx);

/**
 * @brief Parse provides/depends from JSON object
 * @param json_provides_depends JSON object to parse
 * @param provides_depends Pointer to the list of provides or depends
 * @return MENDER_SUCCESS if the function succeeds, MENDER_FAIL otherwise
 */
static mender_err_t mender_artifact_parse_provides_depends(cJSON *json_provides_depends, mender_artifact_provides_depends_t **provides_depends);

/**
 * @brief Convert string to mender_artifact_provides_depends_type_t
 * @param type String to convert
 * @return Type
 */
static mender_artifact_provides_depends_type_t convertStringToType(const char *type);

/**
 * @brief Clear provides/depends list
 * @param provides_depends List to clear
 */
static void mander_artifact_clear_provides_depends(mender_artifact_provides_depends_t *provides_depends);
#endif

/**
 * @brief Read meta-data file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_read_meta_data(mender_artifact_ctx_t *ctx);

/**
 * @brief Read data file of the artifact
 * @param ctx Artifact context
 * @param callback Callback function to be invoked to perform the treatment of the data from the artifact
 * @return MENDER_DONE if the data have been parsed and payloads retrieved, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_read_data(mender_artifact_ctx_t *ctx, mender_err_t (*callback)(char *, cJSON *, char *, size_t, void *, size_t, size_t));

/**
 * @brief Drop content of the current file of the artifact
 * @param ctx Artifact context
 * @return MENDER_DONE if the data have been parsed and dropped, MENDER_OK if there is not enough data to parse, error code if an error occurred
 */
static mender_err_t mender_artifact_drop_file(mender_artifact_ctx_t *ctx);

/**
 * @brief Shift data after parsing
 * @param ctx Artifact context
 * @param length Length of data to shift
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
static mender_err_t mender_artifact_shift_data(mender_artifact_ctx_t *ctx, size_t length);

/**
 * @brief Compute length rounded up to increment (usually the block size)
 * @param length Length
 * @param incr Increment
 * @return Rounded length
 */
static size_t mender_artifact_round_up(size_t length, size_t incr);

mender_artifact_ctx_t *
mender_artifact_create_ctx(void) {

    mender_artifact_ctx_t *ctx;

    /* Create new context */
    if (NULL == (ctx = (mender_artifact_ctx_t *)malloc(sizeof(mender_artifact_ctx_t)))) {
        return NULL;
    }
    memset(ctx, 0, sizeof(mender_artifact_ctx_t));

    return ctx;
}

mender_err_t
mender_artifact_process_data(mender_artifact_ctx_t *ctx,
                             void                  *input_data,
                             size_t                 input_length,
                             mender_err_t (*callback)(char *, cJSON *, char *, size_t, void *, size_t, size_t)) {

    assert(NULL != ctx);
    assert(NULL != callback);
    mender_err_t ret = MENDER_OK;
    void        *tmp;

    /* Copy data to the end of the internal buffer */
    if ((NULL != input_data) && (0 != input_length)) {
        if (NULL == (tmp = realloc(ctx->input.data, ctx->input.length + input_length))) {
            /* Unable to allocate memory */
            return MENDER_FAIL;
        }
        ctx->input.data = tmp;
        memcpy((void *)(((uint8_t *)ctx->input.data) + ctx->input.length), input_data, input_length);
        ctx->input.length += input_length;
    }

    /* Parse data */
    do {

        /* Treatment depending of the stream state */
        if (MENDER_ARTIFACT_STREAM_STATE_PARSING_HEADER == ctx->stream_state) {

            /* Parse TAR header */
            ret = mender_artifact_parse_tar_header(ctx);

        } else if (MENDER_ARTIFACT_STREAM_STATE_PARSING_DATA == ctx->stream_state) {

            /* Treatment depending of the file name */
            if (!strcmp(ctx->file.name, "version")) {

                /* Validate artifact version */
                ret = mender_artifact_read_version(ctx);
#ifdef MENDER_FULL_PARSE_ARTIFACT
            }
            else if (!strcmp(ctx->file.name, "manifest")) {

                /* Read artifact manifest */
                ret = mender_artifact_read_manifest(ctx);

            } else if (!strcmp(ctx->file.name, "manifest-augument")) {

                /* Validate artifact manifest-augument */
                ret = mender_artifact_read_manifest(ctx);
#endif
            }
            else if (!strcmp(ctx->file.name, "header.tar/header-info")) {

                /* Read header-info file */
                ret = mender_artifact_read_header_info(ctx);
#ifdef MENDER_FULL_PARSE_ARTIFACT
            }
            else if ((true == mender_utils_strbeginwith(ctx->file.name, "header.tar/headers"))
                       && (true == mender_utils_strendwith(ctx->file.name, "type-info"))) {

                /* Read type-info file */
                ret = mender_artifact_read_type_info(ctx);
#endif
            }
            else if ((true == mender_utils_strbeginwith(ctx->file.name, "header.tar/headers"))
                       && (true == mender_utils_strendwith(ctx->file.name, "meta-data"))) {

                /* Read meta-data file */
                ret = mender_artifact_read_meta_data(ctx);

            } else if (true == mender_utils_strbeginwith(ctx->file.name, "data")) {

                /* Read data */
                ret = mender_artifact_read_data(ctx, callback);

            } else if (false == mender_utils_strendwith(ctx->file.name, ".tar")) {

                /* Drop data, file is not relevant */
                ret = mender_artifact_drop_file(ctx);

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
                    free(ctx->file.name);
                    ctx->file.name = NULL;
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

#ifdef MENDER_FULL_PARSE_ARTIFACT
static void
mander_artifact_clear_provides_depends(mender_artifact_provides_depends_t *provides_depends) {
    mender_artifact_provides_depends_t *item = provides_depends;
    while (NULL != item) {
        mender_artifact_provides_depends_t *next = item->next;
        free(item);
        item = next;
    }
}
#endif

void
mender_artifact_release_ctx(mender_artifact_ctx_t *ctx) {

    /* Release memory */
    if (NULL != ctx) {
        if (NULL != ctx->input.data) {
            free(ctx->input.data);
        }
        if (NULL != ctx->payloads.values) {
            for (size_t index = 0; index < ctx->payloads.size; index++) {
                if (NULL != ctx->payloads.values[index].type) {
                    free(ctx->payloads.values[index].type);
                }
                if (NULL != ctx->payloads.values[index].meta_data) {
                    cJSON_Delete(ctx->payloads.values[index].meta_data);
                }

#ifdef MENDER_FULL_PARSE_ARTIFACT
                if (NULL != ctx->payloads.values[index].provides) {
                    mender_artifact_clear_provides_depends(ctx->payloads.values[index].provides);
                }
                if (NULL != ctx->payloads.values[index].depends) {
                    mender_artifact_clear_provides_depends(ctx->payloads.values[index].depends);
                }
                if (NULL != ctx->payloads.values[index].clears_provides) {
                    for (size_t i = 0; i < ctx->payloads.values[index].clears_provides_size; i++) {
                        free(ctx->payloads.values[index].clears_provides[i]);
                    }
                    free(ctx->payloads.values[index].clears_provides);
                }
#endif

            }
            free(ctx->payloads.values);
        }
        if (NULL != ctx->file.name) {
            free(ctx->file.name);
        }
#ifdef MENDER_FULL_PARSE_ARTIFACT
        if (NULL != ctx->artifact_info.provides) {
            mender_artifact_clear_provides_depends(ctx->artifact_info.provides);
        }
        if (NULL != ctx->artifact_info.depends) {
            mender_artifact_clear_provides_depends(ctx->artifact_info.depends);
        }
        if (NULL != ctx->artifact_info.manifest) {
            mender_artifact_checksum_t *item = ctx->artifact_info.manifest;
            while (NULL != item) {
                mender_artifact_checksum_t *next = item->next;
                free(item->checksum);
                free(item->file_name);
                free(item);
                item = next;
            }
        }
#endif
        free(ctx);
    }
}

static mender_err_t
mender_artifact_parse_tar_header(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    char *tmp;

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

        /* Remove the TAR file name */
        if (NULL != ctx->file.name) {
            char *substring = mender_utils_strrstr(ctx->file.name, ".tar");
            if (NULL != substring) {
                *substring = '\0';
                substring  = mender_utils_strrstr(ctx->file.name, ".tar");
                if (NULL != substring) {
                    *(substring + strlen(".tar")) = '\0';
                } else {
                    free(ctx->file.name);
                    ctx->file.name = NULL;
                }
            } else {
                free(ctx->file.name);
                ctx->file.name = NULL;
            }
        }

        /* Shift data in the buffer */
        if (MENDER_OK != mender_artifact_shift_data(ctx, 2 * MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
            mender_log_error("Unable to shift input data");
            return MENDER_FAIL;
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
        if (NULL == (tmp = (char *)malloc(str_length))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
        snprintf(tmp, str_length, "%s/%s", ctx->file.name, tar_header->name);
        free(ctx->file.name);
    } else {
        if (NULL == (tmp = strdup(tar_header->name))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
    }
    ctx->file.name = tmp;

    /* Retrieve file size */
    sscanf(tar_header->size, "%o", (unsigned int *)&(ctx->file.size));
    ctx->file.index = 0;

    /* Shift data in the buffer */
    if (MENDER_OK != mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
        mender_log_error("Unable to shift input data");
        return MENDER_FAIL;
    }

    /* Update the stream state machine */
    ctx->stream_state = MENDER_ARTIFACT_STREAM_STATE_PARSING_DATA;

    return MENDER_DONE;
}

static mender_err_t
mender_artifact_read_version(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    cJSON       *object = NULL;
    mender_err_t ret    = MENDER_FAIL;

    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        return MENDER_OK;
    }

    /* Check version file */
    if (NULL == (object = cJSON_ParseWithLength(ctx->input.data, ctx->file.size))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    cJSON *json_format = cJSON_GetObjectItemCaseSensitive(object, "format");
    if (true == cJSON_IsString(json_format)) {
        if (strcmp(cJSON_GetStringValue(json_format), MENDER_ARTIFACT_SUPPORTED_FORMAT)) {
            mender_log_error("Invalid version format");
            goto END;
        }
    } else {
        mender_log_error("Invalid version file");
        goto END;
    }
    cJSON *json_version = cJSON_GetObjectItemCaseSensitive(object, "version");
    if (true == cJSON_IsNumber(json_version)) {
        if (MENDER_ARTIFACT_SUPPORTED_VERSION != (int)cJSON_GetNumberValue(json_version)) {
            mender_log_error("Invalid version value");
            goto END;
        }
    } else {
        mender_log_error("Invalid version file");
        goto END;
    }
    mender_log_info("Artifact has valid version");

    /* Shift data in the buffer */
    if (MENDER_OK != mender_artifact_shift_data(ctx, mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        mender_log_error("Unable to shift input data");
        goto END;
    }

    ret = MENDER_DONE;

END:

    /* Release memory */
    if (NULL != object) {
        cJSON_Delete(object);
    }

    return ret;
}

#ifdef MENDER_FULL_PARSE_ARTIFACT
static mender_err_t
mender_artifact_read_manifest(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        return MENDER_OK;
    }

    /* Format matches the output of sha256sum tool which is the sum and the name of the file separated by the two spaces

        1d0b820130ae028ce8a79b7e217fe505a765ac394718e795d454941487c53d32  data/0000/update.ext4
        4d480539cdb23a4aee6330ff80673a5af92b7793eb1c57c4694532f96383b619  header.tar.gz
        52c76ab66947278a897c2a6df8b4d77badfa343fec7ba3b2983c2ecbbb041a35  version
    */

    /* Read data line by line */
    char *line = ctx->input.data;
    char *end  = ctx->input.data + ctx->input.length;
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

        /* Add checksum to the list */
        mender_artifact_checksum_t *checksum = (mender_artifact_checksum_t *)malloc(sizeof(mender_artifact_checksum_t));
        if (NULL == checksum) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }
        *separator = '\0';

        /* Allocate memory and check if allocation was succesfull */
        checksum->checksum  = strdup(line);
        checksum->file_name = strdup(separator + 2);
        if ((NULL == checksum->checksum) || (NULL == checksum->file_name)) {
            mender_log_error("Unable to allocate memory");
            free(checksum->checksum);
            free(checksum->file_name);
            free(checksum);
            return MENDER_FAIL;
        }
        checksum->next = ctx->artifact_info.manifest;
        ctx->artifact_info.manifest = checksum;

        /* Move to the next line */
        line = next + 1;
    }

    /* Shift data in the buffer */
    if (MENDER_OK != mender_artifact_shift_data(ctx, mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        mender_log_error("Unable to shift input data");
        return MENDER_FAIL;
    }

}

static mender_artifact_provides_depends_type_t
convertStringToType(const char *type) {
    if (0 == strcmp(type, "artifact_name")) {
        return MENDER_PROVIDES_DEPENDS_ARTIFACT_NAME;
    } else if (0 == strcmp(type, "artifact_group")) {
        return MENDER_PROVIDES_DEPENDS_ARTIFACT_GROUP;
    } else if (0 == strcmp(type, "device_type")) {
        return MENDER_PROVIDES_DEPENDS_ARTIFACT_DEVICE_TYPE;
    } else {
        return MENDER_PROVIDES_DEPENDS_ARTIFACT_UNKNOWN;
    }
}

static mender_err_t
mender_artifact_parse_provides_depends(cJSON *json_provides_depends, mender_artifact_provides_depends_t **provides_depends) {
    assert(NULL != json_provides_depends);
    assert(NULL != provides_depends);

    if (true == cJSON_IsObject(json_provides_depends)) {
        if (NULL == (*provides_depends = (mender_artifact_provides_depends_t *)calloc(1, sizeof(mender_artifact_provides_depends_t)))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }

        /* Store all the elements as key value pairs; elements can be strings or arrays of strings */
        cJSON *json_element = NULL;
        cJSON_ArrayForEach(json_element, json_provides_depends) {
            if (true == cJSON_IsString(json_element)) {
                mender_artifact_provides_depends_t *item = (mender_artifact_provides_depends_t *)malloc(sizeof(mender_artifact_provides_depends_t));
                if (NULL == item) {
                    mender_log_error("Unable to allocate memory");
                    return MENDER_FAIL;
                }
                item->type = convertStringToType(cJSON_GetStringValue(json_element));
                if (MENDER_PROVIDES_DEPENDS_ARTIFACT_UNKNOWN == item->type) {
                    mender_log_error("Unsupported provides/depends type");
                }
                if (NULL == strdup(item->value = cJSON_GetStringValue(json_element)) {
                    mender_log_error("Unable to allocate memory");
                    return MENDER_FAIL;
                }
                item->next  = (*provides_depends);
                (*provides_depends) = item;
            } else if (true == cJSON_IsArray(json_element)) {
                cJSON *json_array_element = NULL;
                cJSON_ArrayForEach(json_array_element, json_element) {
                    mender_artifact_provides_depends_t *item = (mender_artifact_provides_depends_t *)malloc(sizeof(mender_artifact_provides_depends_t));
                    if (NULL == item) {
                        mender_log_error("Unable to allocate memory");
                        return MENDER_FAIL;
                    }
                    item->type  = convertStringToType(cJSON_GetStringValue(json_element));
                    if (MENDER_PROVIDES_DEPENDS_ARTIFACT_UNKNOWN == item->type) {
                        mender_log_error("Unsupported provides/depends type");
                    }
                    if (NULL == (item->value = strdup(cJSON_GetStringValue(json_array_element)))) {
                        mender_log_error("Unable to allocate memory");
                        return MENDER_FAIL;
                    }
                    item->next  = (*provides_depends);
                    (*provides_depends) = item;
                }
            } else {
                mender_log_error("Invalid header-info file artifact_provides/depends");
                return MENDER_FAIL;
            }
        }
    } else {
        mender_log_error("Invalid header-info file");
        return MENDER_FAIL;
    }
    return MENDER_OK;
}
#endif

static mender_err_t
mender_artifact_read_header_info(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    cJSON       *object = NULL;
    mender_err_t ret    = MENDER_DONE;

    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
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
        if (NULL == (ctx->payloads.values = (mender_artifact_payload_t *)calloc(ctx->payloads.size, sizeof(mender_artifact_payload_t)))) {
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
                    if (NULL == (ctx->payloads.values[index].type = strdup(cJSON_GetStringValue(json_payload_type)))) {
                        mender_log_error("Unable to allocate memory");
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

#ifdef MENDER_FULL_PARSE_ARTIFACT
        /* Optionally we can have provides and depends in the header-info file

            "artifact_provides": {
            "artifact_name": "release-2",
            "artifact_group": "fix"
            },
            "artifact_depends": {
                "artifact_name": [
                "release-1"
                ],
                "device_type": [
                    "vexpress-qemu",
                    "beaglebone"
                ]
            }
        */

        cJSON *json_provides = cJSON_GetObjectItemCaseSensitive(object, "artifact_provides");
        if (true == cJSON_IsObject(json_provides)) {
            if (MENDER_FAIL == mender_artifact_parse_provides_depends(json_provides, &(ctx->artifact_info.provides))) {
                mender_log_error("Unable to parse artifact_provides");
                ret = MENDER_FAIL;
                goto END;
            }
        }

        cJSON *json_depends = cJSON_GetObjectItemCaseSensitive(object, "artifact_depends");
        if (true == cJSON_IsObject(json_depends)) {
            if (MENDER_FAIL == mender_artifact_parse_provides_depends(json_depends, &(ctx->artifact_info.depends))) {
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
    if (MENDER_OK != mender_artifact_shift_data(ctx, mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        mender_log_error("Unable to shift input data");
        ret = MENDER_FAIL;
        goto END;
    }

END:

    /* Release memory */
    if (NULL != object) {
        cJSON_Delete(object);
    }

    return ret;
}

#ifdef MENDER_FULL_PARSE_ARTIFACT
static mender_err_t
mender_artifact_read_type_info(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    cJSON       *object = NULL;
    mender_err_t ret    = MENDER_DONE;
    size_t index = 0;

    /* Retrieve payload index and check if we have enough payloads allocated */
    if (1 != sscanf(ctx->file.name, "header.tar/headers/%u/type-info", (unsigned int *)&index)) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }
    if (index >= ctx->payloads.size) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }

    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        return MENDER_OK;
    }

    /* Read type-info */
    if (NULL == (object = cJSON_ParseWithLength(ctx->input.data, ctx->file.size))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    cJSON *json_type = cJSON_GetObjectItemCaseSensitive(object, "type");

    /* First check if we have payload aleardy initialized */
    if (NULL == ctx->payloads.values[index]) {
        mender_log_error("Invalid artifact format; no payload found for %d index", index);
        return MENDER_FAIL;
    }

    cJSON *json_provides = cJSON_GetObjectItemCaseSensitive(object, "artifact_provides");
    if (true == cJSON_IsObject(json_provides)) {
        if (MENDER_FAIL == mender_artifact_parse_provides_depends(json_provides, &(ctx->payloads.values[index].provides))) {
            mender_log_error("Unable to parse artifact_provides");
            ret = MENDER_FAIL;
            goto END;
        }
    }

    cJSON *json_depends = cJSON_GetObjectItemCaseSensitive(object, "artifact_depends");
    if (true == cJSON_IsObject(json_depends)) {
        if (MENDER_FAIL == mender_artifact_parse_provides_depends(json_depends, &(ctx->payloads.values[index].depends))) {
            mender_log_error("Unable to parse artifact_depends");
            ret = MENDER_FAIL;
            goto END;
        }
    }

    cJSON *json_clears_provides = cJSON_GetObjectItemCaseSensitive(object, "clears_artifact_provides");
    if (true == cJSON_IsArray(json_clears_provides)) {
        ctx->payloads.values[index].clears_provides_size = cJSON_GetArraySize(json_clears_provides);
        ctx->payloads.values[index].clears_provides = (char **)calloc(cctx->payloads.values[index].clears_provides_sizee, sizeof(char *));
        if (NULL == ctx->payloads.values[index].clears_provides) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }

        int i = 0;
        cJSON *json_clears_provides_element = NULL;

        cJSON_ArrayForEach(json_clears_provides_element, json_clears_provides) {
            if (true == cJSON_IsString(json_clears_provides_element)) {
                char *clears_provides = strdup(cJSON_GetStringValue(json_clears_provides_element));
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
    if (MENDER_OK != mender_artifact_shift_data(ctx, mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        mender_log_error("Unable to shift input data");
        ret = MENDER_FAIL;
        goto END;
    }

END:

    /* Release memory */
    if (NULL != object) {
        cJSON_Delete(object);
    }

    return ret;
}
#endif

static mender_err_t
mender_artifact_read_meta_data(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    size_t index = 0;

    /* Retrieve payload index */
    if (1 != sscanf(ctx->file.name, "header.tar/headers/%u/meta-data", (unsigned int *)&index)) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }
    if (index >= ctx->payloads.size) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }

    /* Check size of the meta-data */
    if (0 == mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
        /* Nothing to do; metadata file is empty */
        return MENDER_DONE;
    }

    /* Check if all data have been received */
    if ((NULL == ctx->input.data) || (ctx->input.length < mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        return MENDER_OK;
    }

    /* Read meta-data */
    if (NULL == (ctx->payloads.values[index].meta_data = cJSON_ParseWithLength(ctx->input.data, ctx->file.size))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Shift data in the buffer */
    if (MENDER_OK != mender_artifact_shift_data(ctx, mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
        mender_log_error("Unable to shift input data");
        return MENDER_FAIL;
    }

    return MENDER_DONE;
}

static mender_err_t
mender_artifact_read_data(mender_artifact_ctx_t *ctx, mender_err_t (*callback)(char *, cJSON *, char *, size_t, void *, size_t, size_t)) {

    assert(NULL != ctx);
    assert(NULL != callback);
    size_t       index = 0;
    mender_err_t ret;

    /* Retrieve payload index */
    if (1 != sscanf(ctx->file.name, "data/%u.tar", (unsigned int *)&index)) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }
    if (index >= ctx->payloads.size) {
        mender_log_error("Invalid artifact format");
        return MENDER_FAIL;
    }

    /* Check if a file name is provided (we don't check the extension because we don't know it) */
    if (strlen("data/xxxx.tar") == strlen(ctx->file.name)) {

        /* Beginning of the data file */
        if (MENDER_OK != (ret = callback(ctx->payloads.values[index].type, ctx->payloads.values[index].meta_data, NULL, 0, NULL, 0, 0))) {
            mender_log_error("An error occurred");
            return ret;
        }

        return MENDER_DONE;
    }

    /* Check size of the data */
    if (0 == mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
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

        /* Invoke callback */
        if (MENDER_OK
            != (ret = callback(ctx->payloads.values[index].type,
                               ctx->payloads.values[index].meta_data,
                               strstr(ctx->file.name, ".tar") + strlen(".tar") + 1,
                               ctx->file.size,
                               ctx->input.data,
                               ctx->file.index,
                               length))) {
            mender_log_error("An error occurred");
            return ret;
        }

        /* Update index */
        ctx->file.index += MENDER_ARTIFACT_STREAM_BLOCK_SIZE;

        /* Shift data in the buffer */
        if (MENDER_OK != (ret = mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
            mender_log_error("Unable to shift input data");
            return ret;
        }

    } while (ctx->file.index < ctx->file.size);

    return MENDER_DONE;
}

static mender_err_t
mender_artifact_drop_file(mender_artifact_ctx_t *ctx) {

    assert(NULL != ctx);
    mender_err_t ret;

    /* Check size of the data */
    if (0 == mender_artifact_round_up(ctx->file.size, MENDER_ARTIFACT_STREAM_BLOCK_SIZE)) {
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
        if (MENDER_OK != (ret = mender_artifact_shift_data(ctx, MENDER_ARTIFACT_STREAM_BLOCK_SIZE))) {
            mender_log_error("Unable to shift input data");
            return ret;
        }

    } while (ctx->file.index < ctx->file.size);

    return MENDER_DONE;
}

static mender_err_t
mender_artifact_shift_data(mender_artifact_ctx_t *ctx, size_t length) {

    assert(NULL != ctx);
    char *tmp;

    /* Shift data */
    if (length > 0) {
        if (ctx->input.length > length) {
            memcpy(ctx->input.data, (void *)(((uint8_t *)ctx->input.data) + length), ctx->input.length - length);
            if (NULL == (tmp = realloc(ctx->input.data, ctx->input.length - length))) {
                mender_log_error("Unable to allocate memory");
                return MENDER_FAIL;
            }
            ctx->input.data = tmp;
            ctx->input.length -= length;
        } else {
            free(ctx->input.data);
            ctx->input.data   = NULL;
            ctx->input.length = 0;
        }
    }

    return MENDER_OK;
}

static size_t
mender_artifact_round_up(size_t length, size_t incr) {
    return length + (incr - length % incr) % incr;
}
