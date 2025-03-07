/**
 * @file      utils.h
 * @brief     Mender utility functions (private API)
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

#ifndef __MENDER_UTILS_PRIV_H__
#define __MENDER_UTILS_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mender/utils.h>

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif /* !MAX */

/**
 * @brief Macro for releasing a resource followed by setting it to NULL.
 */
#define DESTROY_AND_NULL(destructor, resource) \
    destructor(resource);                      \
    resource = NULL

/**
 * @brief Macro for releasing a resource with mender_free() followed by setting it to NULL.
 */
#define FREE_AND_NULL(resource) DESTROY_AND_NULL(mender_free, resource)

/**
 * @brief Macro for checking if string is NULL or empty
 */
#define IS_NULL_OR_EMPTY(str) ((NULL == str) || (str[0] == '\0'))

/**
 * @brief Macro for comparing two strings
 * @return true if the strings are equal, false otherwise
 */
#define StringEqual(str1, str2) (0 == strcmp(str1, str2))

/**
 * @brief Macro for comparing two strings up to N bytes
 * @return true if the strings are equal, false otherwise
 */
#define StringEqualN(str1, str2, n) (0 == strncmp(str1, str2, n))

/**
 * @brief Linked-list
 */
typedef struct mender_key_value_list_t {
    char                           *key;
    char                           *value;
    struct mender_key_value_list_t *next;
} mender_key_value_list_t;

/**
 * @brief Function used to print HTTP status as string
 * @param status HTTP status code
 * @return HTTP status as string, NULL if it is not found
 */
const char *mender_utils_http_status_to_string(int status);

/**
 * @brief Function used to locate last substring in string
 * @param haystack String to look for a substring
 * @param needle Substring to look for
 * @return Pointer to the beginning of the substring, NULL is the substring is not found
 */
char *mender_utils_strrstr(const char *haystack, const char *needle);

/**
 * @brief Function used to check if string begins with wanted substring
 * @param s1 String to be checked
 * @param s2 Substring to look for at the beginning of the string
 * @return true if the string begins with wanted substring, false otherwise
 */
bool mender_utils_strbeginswith(const char *s1, const char *s2);

/**
 * @brief Function used to check if string ends with wanted substring
 * @param s1 String to be checked
 * @param s2 Substring to look for at the end of the string
 * @return true if the string ends with wanted substring, false otherwise
 */
bool mender_utils_strendswith(const char *s1, const char *s2);

/**
 * @brief Convert a hexdump of bytes into the respective bytes
 * @param hexdump String containing the hexdumped bytes
 * @param bytes   An array to store the bytes in
 * @param n_bytes The number of the bytes to convert (i.e. the size of #bytes and half the
 *                length of #hexdump).
 * @return %true if the conversion was successful, false otherwise
 */
bool mender_utils_hexdump_to_bytes(const char *hexdump, unsigned char *bytes, size_t n_bytes);

/**
 * @brief Function used to format identity to JSON object
 * @param  identity Identity
 * @param object JSON object
 * @return MENDER_OK if the function succeeds, error code otherwise
 */
mender_err_t mender_utils_identity_to_json(const mender_identity_t *identity, cJSON **object);

/**
 * @brief Delete the given keystore
 */
void mender_utils_keystore_delete(mender_keystore_t *keystore, uint8_t keystore_len);

/**
 * @brief Free linked list list
 * @param provides_depends List to clear
 */
mender_err_t mender_utils_key_value_list_free(mender_key_value_list_t *list);

/**
 * @brief Create a new key-value node
 */
mender_err_t mender_utils_key_value_list_create_node(const char *type, const char *value, mender_key_value_list_t **list);

/**
 * @brief Append linked list - appends list2 to list1 and sets list2 to NULL
 */
mender_err_t mender_utils_key_value_list_append(mender_key_value_list_t **list1, mender_key_value_list_t **list2);

/**
 * @brief Convert linked list to string
 */
mender_err_t mender_utils_key_value_list_to_string(mender_key_value_list_t *list, char **key_value_str);

/**
 * @brief Convert string to linked list
 */
mender_err_t mender_utils_string_to_key_value_list(const char *key_value_str, mender_key_value_list_t **list);

/**
 * @brief Append items from list2 that are not in list1
 */
mender_err_t mender_utils_key_value_list_append_unique(mender_key_value_list_t **list1, mender_key_value_list_t **list2);

/**
 * @brief Delete a node from a linked list
 */
mender_err_t mender_utils_key_value_list_delete_node(mender_key_value_list_t **list, const char *key);

/**
 * @brief Compare `string` with `wild_card_string`
 * @return true if matches, else false
 */
mender_err_t mender_utils_compare_wildcard(const char *str, const char *wildcard_str, bool *match);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MENDER_UTILS_PRIV_H__ */
