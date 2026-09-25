/**
 * @file      storage.c
 * @brief     Mender storage interface for the ESP-IDF platform
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

#include <nvs_flash.h>

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include <esp_partition.h>
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

#include "log.h"
#include "storage.h"
#include "utils.h"

/* In case a custom partition label was specified, use it, otherwise default to
   "mender" */
#ifdef CONFIG_MENDER_STORAGE_PARTITION_LABEL
#define MENDER_STORAGE_PARTITION_LABEL CONFIG_MENDER_STORAGE_PARTITION_LABEL
#else
#define MENDER_STORAGE_PARTITION_LABEL "mender"
#endif /* CONFIG_MENDER_STORAGE_PARTITION_LABEL */

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
/* In case a custom partition label was specified, use it, otherwise default to
   "mender_logs". This must be a dedicated "data" partition of at least two
   erase sectors, not shared with NVS/FATFS/anything else. */
#ifdef CONFIG_MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL
#define MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL CONFIG_MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL
#else
#define MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL "mender_logs"
#endif /* CONFIG_MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL */

/**
 * @brief On-flash layout of the deployment logs storage area
 *
 * The partition is split into fixed-size erase sectors, used as a ring
 * buffer:
 *
 *   +--------------------+--------------------+-----+--------------------+
 *   | sector 0           | sector 1           | ... | sector N-1         |
 *   +--------------------+--------------------+-----+--------------------+
 *
 * Each sector starts with a depl_logs_sector_header_t identifying it as
 * in-use and carrying a sequence number. Sequence numbers are used to
 * determine, even across resets, which sector holds the oldest ("head") and
 * newest ("tail", i.e. currently being appended to) data.
 *
 * The rest of the sector is filled, front to back, with length-prefixed,
 * CRC-protected entries (depl_logs_entry_header_t followed by the message
 * bytes), written once and never rewritten. When the active (tail) sector
 * fills up, the next sector in line is erased and takes over as the tail;
 * if that happens to be the current head sector, the ring has wrapped and
 * the sector after it becomes the new (oldest) head, i.e. its data is
 * dropped.
 *
 * Every entry is written with a single esp_partition_write() call and
 * validated (length range + CRC8 over the actual bytes read back) before
 * being trusted, so a write torn by a reset/power-loss is always detected
 * and simply treated as "no more data here" rather than being read back as
 * corrupt content.
 */

/* 0xFF is reserved to always mean "erased/unwritten" so it can never be
   mistaken for a valid entry length. */
#define DEPL_LOGS_MAX_MSG_LEN 254

#define DEPL_LOGS_SECTOR_MAGIC ((uint32_t)0x4D444C31) /* "MDL1" */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t seq;
} depl_logs_sector_header_t;

typedef struct __attribute__((packed)) {
    uint8_t len;
    uint8_t crc8;
} depl_logs_entry_header_t;

/* Entries are padded to a 4-byte boundary; purely defensive (unencrypted
   partition writes have no alignment requirement) to keep entries clear of
   any potential driver-specific write-granularity quirks. */
#define DEPL_LOGS_ENTRY_ALIGN             4
#define DEPL_LOGS_ALIGN_UP(x)             (((x) + (DEPL_LOGS_ENTRY_ALIGN - 1)) & ~(size_t)(DEPL_LOGS_ENTRY_ALIGN - 1))
#define DEPL_LOGS_ENTRY_SIZE(payload_len) DEPL_LOGS_ALIGN_UP(sizeof(depl_logs_entry_header_t) + (payload_len))

/**
 * @brief The deployment logs partition
 */
static const esp_partition_t *depl_logs_part = NULL;

/**
 * @brief Number of erase sectors in #depl_logs_part
 */
static size_t depl_logs_sector_count = 0;

/**
 * @brief Index of the oldest sector (first one read back by a walk)
 */
static size_t depl_logs_head_sector = 0;

/**
 * @brief Index of the active sector (the one currently being appended to)
 */
static size_t depl_logs_tail_sector = 0;

/**
 * @brief Next free offset within #depl_logs_tail_sector
 */
static size_t depl_logs_next_offset = 0;

/**
 * @brief Sequence number to assign to the next freshly erased sector
 */
static uint16_t depl_logs_next_seq = 0;

static inline uint8_t
depl_logs_crc8(const uint8_t *data, size_t len) {
    uint8_t crc = 0xFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
        }
    }
    return crc;
}

static inline size_t
depl_logs_sector_offset(size_t sector_idx) {
    return sector_idx * depl_logs_part->erase_size;
}

static mender_err_t
depl_logs_prepare_sector(size_t sector_idx, uint16_t seq) {
    if (ESP_OK != esp_partition_erase_range(depl_logs_part, depl_logs_sector_offset(sector_idx), depl_logs_part->erase_size)) {
        mender_log_error("Failed to erase deployment logs sector %zu", sector_idx);
        return MENDER_FAIL;
    }
    depl_logs_sector_header_t header = { .magic = DEPL_LOGS_SECTOR_MAGIC, .seq = seq };
    if (ESP_OK != esp_partition_write(depl_logs_part, depl_logs_sector_offset(sector_idx), &header, sizeof(header))) {
        mender_log_error("Failed to write deployment logs sector %zu header", sector_idx);
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

/**
 * @brief Read entry header
 * @return MENDER_OK if reading succeeded, MENDER_FAIL otherwise
 */
static mender_err_t
depl_logs_read_entry_header(size_t sector_idx, size_t offset, depl_logs_entry_header_t *header) {
    if (ESP_OK != esp_partition_read(depl_logs_part, depl_logs_sector_offset(sector_idx) + offset, header, sizeof(*header))) {
        mender_log_error("Failed to read deployment log entry header");
        return MENDER_FAIL;
    }
    return MENDER_OK;
}

/**
 * @brief Validate and optionally read back the entry at #offset within sector #sector_idx
 * @param sector_idx   Sector to read from
 * @param offset       Offset relative to the start of the sector
 * @param msg          If non-NULL, the entry payload is copied here as a NUL-terminated string
 * @param msg_buf_size Size of #msg, only used if #msg is non-NULL
 * @param entry_size   On success, set to the total (aligned) size occupied by the entry
 * @return MENDER_OK if a valid entry was found, MENDER_NOT_FOUND if #offset is unwritten or
 *         holds a torn/corrupt entry (both cases mean "no usable data here"), MENDER_FAIL on a
 *         flash access error
 */
static mender_err_t
depl_logs_read_entry(size_t sector_idx, size_t offset, char *msg, size_t msg_buf_size, size_t *entry_size) {
    depl_logs_entry_header_t header;
    if (MENDER_OK != depl_logs_read_entry_header(sector_idx, offset, &header)) {
        /* error already logged */
        return MENDER_FAIL;
    }

    /* 0xFF means unwritten (erased) */
    if (0xFF == header.len) {
        return MENDER_NOT_FOUND;
    }

    assert(header.len <= DEPL_LOGS_MAX_MSG_LEN);
    char payload[DEPL_LOGS_MAX_MSG_LEN];
    if (ESP_OK != esp_partition_read(depl_logs_part, depl_logs_sector_offset(sector_idx) + offset + sizeof(header), payload, header.len)) {
        mender_log_error("Failed to read deployment log entry payload");
        return MENDER_FAIL;
    }
    if (depl_logs_crc8((const uint8_t *)payload, header.len) != header.crc8) {
        /* Only expected as a result of a write torn by a reset/power-loss:
           treat it the same as "no more data here". */
        mender_log_debug("Corrupt deployment log entry at sector %zu, offset %zu, ignoring", sector_idx, offset);
        return MENDER_NOT_FOUND;
    }

    if (NULL != msg) {
        size_t copy_len = header.len;
        bool   trim     = (msg_buf_size - 1) < (size_t)header.len;
        if (trim) {
            mender_log_warning("Trimming a long deployment log entry");
            copy_len = msg_buf_size - 1;
        }
        memcpy(msg, payload, copy_len);
        msg[copy_len] = '\0';
        if (trim) {
            for (size_t i = copy_len - 3; i < copy_len; i++) {
                msg[i] = '.';
            }
        }
    }
    if (NULL != entry_size) {
        *entry_size = DEPL_LOGS_ENTRY_SIZE(header.len);
    }
    return MENDER_OK;
}

/**
 * @brief Find the first free (unwritten) offset within a sector
 */
static mender_err_t
depl_logs_find_next_offset(size_t sector_idx, size_t *offset) {
    depl_logs_entry_header_t header;

    *offset = sizeof(depl_logs_sector_header_t);
    while (*offset + sizeof(depl_logs_entry_header_t) <= depl_logs_part->erase_size) {
        mender_err_t ret = depl_logs_read_entry_header(sector_idx, *offset, &header);
        if (MENDER_OK != ret) {
            return ret;
        } else if (0xFF == header.len) {
            /* 0xFF is an erased/unwritten byte, we never store 255-long messages */
            return MENDER_OK;
        }
        *offset += DEPL_LOGS_ENTRY_SIZE(header.len);
    }
    return MENDER_OK;
}

static mender_err_t
depl_logs_storage_init(void) {
    esp_err_t err
        = esp_partition_find_first_err(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL, &depl_logs_part);
    if (ESP_OK != err) {
        mender_log_error("Failed to find deployment logs partition '" MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL "': %s", esp_err_to_name(err));
        return MENDER_FAIL;
    }

    depl_logs_sector_count = depl_logs_part->size / depl_logs_part->erase_size;
    if (depl_logs_sector_count < 2) {
        mender_log_error("Deployment logs partition '" MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL "' needs at least 2 erase sectors");
        return MENDER_FAIL;
    }

    /* Scan all sectors for a valid header to find the head (lowest sequence
       number) and tail (highest sequence number) sectors. */
    bool     any_valid = false;
    uint16_t min_seq = 0, max_seq = 0;
    size_t   min_idx = 0, max_idx = 0;
    for (size_t i = 0; i < depl_logs_sector_count; i++) {
        depl_logs_sector_header_t header;
        if (ESP_OK != esp_partition_read(depl_logs_part, depl_logs_sector_offset(i), &header, sizeof(header))) {
            mender_log_error("Failed to read deployment logs sector %zu header", i);
            return MENDER_FAIL;
        }
        if (DEPL_LOGS_SECTOR_MAGIC != header.magic) {
            continue;
        }
        if (!any_valid || (header.seq < min_seq)) {
            min_seq = header.seq;
            min_idx = i;
        }
        if (!any_valid || (header.seq > max_seq)) {
            max_seq = header.seq;
            max_idx = i;
        }
        any_valid = true;
    }

    if (!any_valid) {
        /* Blank or corrupt partition: start fresh from sector 0. */
        if (MENDER_OK != depl_logs_prepare_sector(0, 0)) {
            return MENDER_FAIL;
        }
        depl_logs_head_sector = 0;
        depl_logs_tail_sector = 0;
        depl_logs_next_seq    = 1;
        depl_logs_next_offset = sizeof(depl_logs_sector_header_t);
    } else {
        if (MENDER_OK == depl_logs_find_next_offset(depl_logs_tail_sector, &depl_logs_next_offset)) {
            depl_logs_head_sector = min_idx;
            depl_logs_tail_sector = max_idx;
            depl_logs_next_seq    = max_seq + 1;
        } else {
            /* This should not happen, but if it does, the best thing to do is
               to try to start from scratch so that future logs can be captured
               (and published). */
            mender_log_error("Failed to identify the end of existing deployment logs");
            if (MENDER_OK != depl_logs_prepare_sector(0, 0)) {
                return MENDER_FAIL;
            }
            depl_logs_head_sector = 0;
            depl_logs_tail_sector = 0;
            depl_logs_next_seq    = 1;
            depl_logs_next_offset = sizeof(depl_logs_sector_header_t);
        }
    }

    mender_log_debug("Initialized deployment logs storage on '" MENDER_STORAGE_DEPLOYMENT_LOGS_PARTITION_LABEL "': %zu sectors of %" PRIu32
                     " bytes, head=%zu tail=%zu",
                     depl_logs_sector_count,
                     depl_logs_part->erase_size,
                     depl_logs_head_sector,
                     depl_logs_tail_sector);

    return MENDER_OK;
}
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

/**
 * @brief NVS keys
 * @note According to the ESP-IDF documentation the NVS keys are limited to 15 characters:
 *       https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_flash.html#keys-and-values
 */
/*                                         "###MAX-LENGTH##" */
#define MENDER_STORAGE_NVS_PRIVATE_KEY     "private_key"
#define MENDER_STORAGE_NVS_PUBLIC_KEY      "public_key"
#define MENDER_STORAGE_NVS_DEPLOYMENT_DATA "deployment-data"
#define MENDER_STORAGE_NVS_PROVIDES        "provides"
#define MENDER_STORAGE_NVS_ARTIFACT_NAME   "artifact-name"

/**
 * @brief Cached Artifact name
 */
static char *cached_artifact_name = NULL;

/**
 * @brief NVS storage handle
 */
static nvs_handle_t mender_storage_nvs_handle;

mender_err_t
mender_storage_init(void) {
    if (StringEqual(MENDER_STORAGE_PARTITION_LABEL, "nvs")) {
        /* The default partition (using label "nvs") specified, simply
           initialize and open this default and use the "mender" namespace */
        if (ESP_OK != nvs_flash_init()) {
            mender_log_error("Failed to initialize default NVS storage");
            return MENDER_FAIL;
        }
        if (ESP_OK != nvs_open("mender", NVS_READWRITE, &mender_storage_nvs_handle)) {
            mender_log_error("Failed to open default NVS storage");
            return MENDER_FAIL;
        }
    } else {
        const esp_partition_t *part;
        /* TODO: do nvs_flash_init() with partition label instead? */
        esp_err_t err = esp_partition_find_first_err(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, MENDER_STORAGE_PARTITION_LABEL, &part);
        if (ESP_ERR_NOT_FOUND == err) {
            mender_log_error("Failed to find an NVS data partition with label '" MENDER_STORAGE_PARTITION_LABEL "'");
            return MENDER_FAIL;
        } else if (ESP_OK != err) {
            mender_log_error("Failure when looking up NVS data partition for Mender data: %s", esp_err_to_name(err));
            return MENDER_FAIL;
        }
        if (ESP_OK != nvs_flash_init_partition_ptr(part)) {
            mender_log_error("Failed to initialize NVS data partition");
            return MENDER_FAIL;
        }
        if (ESP_OK != nvs_open_from_partition(MENDER_STORAGE_PARTITION_LABEL, "mender", NVS_READWRITE, &mender_storage_nvs_handle)) {
            mender_log_error("Failed to open NVS data partition");
            return MENDER_FAIL;
        }
    }

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
    if (MENDER_OK != depl_logs_storage_init()) {
        return MENDER_FAIL;
    }
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

    return MENDER_OK;
}

#ifdef CONFIG_MENDER_DEPLOYMENT_LOGS
mender_err_t
mender_storage_deployment_log_append(const char *msg, size_t msg_size) {
    assert(NULL != depl_logs_part);

    /* msg_size counts the terminating '\0', mirroring the other platform backends. */
    const size_t payload_len = MIN(msg_size, (size_t)DEPL_LOGS_MAX_MSG_LEN + 1) - 1;
    const size_t entry_size  = DEPL_LOGS_ENTRY_SIZE(payload_len);

    if (depl_logs_next_offset + entry_size > depl_logs_part->erase_size) {
        /* No more room in the active sector: roll over to the next one. */
        size_t new_tail = (depl_logs_tail_sector + 1) % depl_logs_sector_count;
        if (MENDER_OK != depl_logs_prepare_sector(new_tail, depl_logs_next_seq++)) {
            return MENDER_FAIL;
        }
        if (new_tail == depl_logs_head_sector) {
            /* We just erased the oldest sector: the ring has wrapped and the
               sector after it becomes the new (oldest) head. */
            depl_logs_head_sector = (new_tail + 1) % depl_logs_sector_count;
        }
        depl_logs_tail_sector = new_tail;
        depl_logs_next_offset = sizeof(depl_logs_sector_header_t);
    }

    uint8_t                   buf[sizeof(depl_logs_entry_header_t) + DEPL_LOGS_MAX_MSG_LEN];
    depl_logs_entry_header_t *header = (depl_logs_entry_header_t *)buf;
    memcpy(buf + sizeof(*header), msg, payload_len);
    header->len  = (uint8_t)payload_len;
    header->crc8 = depl_logs_crc8(buf + sizeof(*header), payload_len);

    if (ESP_OK
        != esp_partition_write(depl_logs_part, depl_logs_sector_offset(depl_logs_tail_sector) + depl_logs_next_offset, buf, sizeof(*header) + payload_len)) {
        mender_log_error("Failed to write deployment log entry");
        return MENDER_FAIL;
    }

    depl_logs_next_offset += entry_size;
    return MENDER_OK;
}

mender_err_t
mender_storage_deployment_log_walk(MenderDeploymentLogVisitor visitor_fn, void *ctx) {
    assert(NULL != depl_logs_part);

    char   msg[DEPL_LOGS_MAX_MSG_LEN + 1];
    size_t sector_idx = depl_logs_head_sector;
    bool   done       = false;
    while (!done) {
        /* Walk over all entries in the sector. */
        size_t offset = sizeof(depl_logs_sector_header_t);
        while (offset + sizeof(depl_logs_entry_header_t) <= depl_logs_part->erase_size) {
            size_t       entry_size;
            mender_err_t ret = depl_logs_read_entry(sector_idx, offset, msg, sizeof(msg), &entry_size);
            if (MENDER_FAIL == ret) {
                return MENDER_FAIL;
            }
            if (MENDER_NOT_FOUND == ret) {
                /* No more valid entries in this sector. */
                break;
            }
            visitor_fn(msg, ctx);
            offset += entry_size;
        }

        /* Done if the last sector was just processed (could have been the first
           one as well, of course!). */
        done       = (sector_idx == depl_logs_tail_sector);
        sector_idx = (sector_idx + 1) % depl_logs_sector_count;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_deployment_log_clear(void) {
    assert(NULL != depl_logs_part);

    if (MENDER_OK != depl_logs_prepare_sector(0, 0)) {
        return MENDER_FAIL;
    }
    if (depl_logs_sector_count > 1) {
        if (ESP_OK != esp_partition_erase_range(depl_logs_part, depl_logs_sector_offset(1), (depl_logs_sector_count - 1) * depl_logs_part->erase_size)) {
            mender_log_error("Failed to erase deployment logs partition");
            return MENDER_FAIL;
        }
    }

    depl_logs_head_sector = 0;
    depl_logs_tail_sector = 0;
    depl_logs_next_seq    = 1;
    depl_logs_next_offset = sizeof(depl_logs_sector_header_t);

    return MENDER_OK;
}
#endif /* CONFIG_MENDER_DEPLOYMENT_LOGS */

mender_err_t
mender_storage_set_authentication_keys(unsigned char *private_key, size_t private_key_length, unsigned char *public_key, size_t public_key_length) {
    assert(NULL != private_key);
    assert(NULL != public_key);

    if ((ESP_OK != nvs_set_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, private_key, private_key_length))
        || (ESP_OK != nvs_set_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, public_key, public_key_length))) {
        mender_log_error("Failed to write authentication keys");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write authentication keys");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_get_authentication_keys(unsigned char **private_key, size_t *private_key_length, unsigned char **public_key, size_t *public_key_length) {
    assert(NULL != private_key);
    assert(NULL != private_key_length);
    assert(NULL != public_key);
    assert(NULL != public_key_length);

    /* Retrieve length of the keys */
    nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, NULL, private_key_length);
    nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, NULL, public_key_length);
    if ((0 == *private_key_length) || (0 == *public_key_length)) {
        mender_log_info("Authentication keys not available in NVS");
        return MENDER_NOT_FOUND;
    }

    /* Allocate memory for the keys */
    if (NULL == (*private_key = mender_malloc(*private_key_length))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }
    if (NULL == (*public_key = mender_malloc(*public_key_length))) {
        mender_log_error("Unable to allocate memory");
        FREE_AND_NULL(*private_key);
        return MENDER_FAIL;
    }

    /* Read the keys */
    if ((ESP_OK != nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY, *private_key, private_key_length))
        || (ESP_OK != nvs_get_blob(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY, *public_key, public_key_length))) {
        mender_log_error("Failed to read authentication keys from NVS");
        FREE_AND_NULL(*private_key);
        FREE_AND_NULL(*public_key);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_authentication_keys(void) {
    if ((ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PRIVATE_KEY))
        || (ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PUBLIC_KEY))) {
        mender_log_error("Failed to erase authentication keys from NVS");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to erase authentication keys from NVS");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_set_deployment_data(char *deployment_data) {
    assert(NULL != deployment_data);

    if (ESP_OK != nvs_set_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, deployment_data)) {
        mender_log_error("Failed to write deployment data to NVS");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write (commit) deployment data to NVS");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_get_deployment_data(char **deployment_data) {
    assert(NULL != deployment_data);

    /* Retrieve length of the deployment data */
    size_t deployment_data_length = 0;
    nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, NULL, &deployment_data_length);
    if (0 == deployment_data_length) {
        mender_log_info("No deployment data found");
        return MENDER_NOT_FOUND;
    }

    /* Allocate memory for the deployment data */
    if (NULL == (*deployment_data = mender_malloc(deployment_data_length + 1))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Read the deployment data */
    if (ESP_OK != nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA, *deployment_data, &deployment_data_length)) {
        mender_log_error("Failed to read deployment data");
        FREE_AND_NULL(*deployment_data);
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_deployment_data(void) {
    if (ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_DEPLOYMENT_DATA)) {
        mender_log_error("Failed to delete deployment data");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

#ifdef CONFIG_MENDER_FULL_PARSE_ARTIFACT
#ifdef CONFIG_MENDER_PROVIDES_DEPENDS
mender_err_t
mender_storage_set_provides(mender_key_value_list_t *provides) {
    assert(NULL != provides);

    char *provides_str = NULL;
    if (MENDER_OK != mender_utils_key_value_list_to_string(provides, &provides_str)) {
        return MENDER_FAIL;
    }

    if (ESP_OK != nvs_set_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, provides_str)) {
        mender_log_error("Failed to write provides to NVS");
        mender_free(provides_str);
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write (commit) provides to NVS");
        mender_free(provides_str);
        return MENDER_FAIL;
    }

    mender_free(provides_str);
    return MENDER_OK;
}

mender_err_t
mender_storage_get_provides(mender_key_value_list_t **provides) {
    assert(NULL != provides);
    assert(NULL == *provides); /* otherwise we prepend to a bad list going nowhere */

    size_t provides_str_length = 0;
    char  *provides_str        = NULL;
    nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, NULL, &provides_str_length);
    if (0 == provides_str_length) {
        mender_log_info("No provides found");
        return MENDER_NOT_FOUND;
    }

    /* Allocate memory for the provides */
    if (NULL == (provides_str = mender_malloc(provides_str_length + 1))) {
        mender_log_error("Unable to allocate memory");
        return MENDER_FAIL;
    }

    /* Read the provides */
    if (ESP_OK != nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES, provides_str, &provides_str_length)) {
        mender_log_error("Failed to read provides");
        mender_free(provides_str);
        return MENDER_FAIL;
    }

    /* Convert str to key-value list */
    if (MENDER_OK != mender_utils_string_to_key_value_list(provides_str, provides)) {
        /* Error already logged */
        mender_free(provides_str);
        return MENDER_FAIL;
    }
    mender_free(provides_str);

    return MENDER_OK;
}

mender_err_t
mender_storage_delete_provides(void) {
    if (ESP_OK != nvs_erase_key(mender_storage_nvs_handle, MENDER_STORAGE_NVS_PROVIDES)) {
        mender_log_error("Failed to delete provides");
        return MENDER_FAIL;
    }

    return MENDER_OK;
}

#endif /* CONFIG_MENDER_PROVIDES_DEPENDS */
#endif /* CONFIG_MENDER_FULL_PARSE_ARTIFACT */

mender_err_t
mender_storage_set_artifact_name(const char *artifact_name) {
    assert(NULL != artifact_name);

    if (ESP_OK != nvs_set_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTIFACT_NAME, artifact_name)) {
        mender_log_error("Failed to write artifact name to NVS");
        return MENDER_FAIL;
    }
    if (ESP_OK != nvs_commit(mender_storage_nvs_handle)) {
        mender_log_error("Failed to write (commit) artifact name to NVS");
        return MENDER_FAIL;
    }

    FREE_AND_NULL(cached_artifact_name);
    return MENDER_OK;
}

mender_err_t
mender_storage_get_artifact_name(const char **artifact_name) {
    assert(NULL != artifact_name);

    if (NULL != cached_artifact_name) {
        *artifact_name = cached_artifact_name;
        return MENDER_OK;
    }

    /* Retrieve length of the artifact name */
    size_t artifact_name_length = 0;
    nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTIFACT_NAME, NULL, &artifact_name_length);
    if (0 == artifact_name_length) {
        mender_log_info("No artifact name found");
        const char *artifact_name_literal;
        /* Get the Artifact Name from the build, if set */
#ifdef CONFIG_MENDER_ARTIFACT_NAME
        if (strlen(CONFIG_MENDER_ARTIFACT_NAME) > 0) {
            artifact_name_literal = CONFIG_MENDER_ARTIFACT_NAME;
        } else {
            artifact_name_literal = "unknown";
        }
#else
        artifact_name_literal = "unknown";
#endif
        if (NULL == (*artifact_name = mender_utils_strdup(artifact_name_literal))) {
            mender_log_error("Unable to allocate memory");
            return MENDER_FAIL;
        }

        cached_artifact_name = (char *)*artifact_name;
        return MENDER_OK;
    }

    /* Allocate memory for the artifact name */
    char *nvs_artifact_name;
    if (NULL == (nvs_artifact_name = mender_malloc(artifact_name_length + 1))) {
        mender_log_error("Unable to allocate memory");
        *artifact_name = NULL;
        return MENDER_FAIL;
    }

    /* Read the artifact name */
    if (ESP_OK != nvs_get_str(mender_storage_nvs_handle, MENDER_STORAGE_NVS_ARTIFACT_NAME, nvs_artifact_name, &artifact_name_length)) {
        mender_log_error("Failed to read artifact name");
        mender_free(nvs_artifact_name);
        *artifact_name = NULL;
        return MENDER_FAIL;
    }

    *artifact_name       = (char *)nvs_artifact_name;
    cached_artifact_name = nvs_artifact_name;

    return MENDER_OK;
}

mender_err_t
mender_storage_exit(void) {
    FREE_AND_NULL(cached_artifact_name);

    /* Close the NVS storage */
    nvs_close(mender_storage_nvs_handle);

    return MENDER_OK;
}
