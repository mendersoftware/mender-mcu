# @file      CMakeLists.txt
# @brief     mender-mcu-client static library CMakeLists file
#
# Copyright joelguittet and mender-mcu-client contributors
# Copyright Northern.tech AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.16.3)

# Library project
project(mender-mcu-client LANGUAGES C)

# Compiler options
if (CONFIG_MENDER_ALL_WARNINGS_AS_ERRORS)
    add_compile_options(-Wall -Wextra -Werror -Wpointer-arith)
endif()

# Creation of the library
add_library(mender-mcu-client STATIC)

# Library options
if (NOT CONFIG_MENDER_SERVER_HOST)
    message(STATUS "Using default server host")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_SERVER_HOST}' server host")
endif()
if (NOT CONFIG_MENDER_SERVER_TENANT_TOKEN)
    message(STATUS "Using default server tenant token")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_SERVER_TENANT_TOKEN}' server tenant token")
endif()
if (NOT CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL)
    message(STATUS "Using default authentication poll interval")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL}' authentication poll interval")
endif()
if (NOT CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL)
    message(STATUS "Using default update poll interval")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL}' update poll interval")
endif()
option(CONFIG_MENDER_CLIENT_INVENTORY "Mender client Inventory" ON)
if (CONFIG_MENDER_CLIENT_INVENTORY)
    message(STATUS "Using mender-inventory")
    if (NOT CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL)
        message(STATUS "Using default inventory refresh interval")
    else()
        message(STATUS "Using custom '${CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL}' inventory refresh interval")
    endif()
  endif()
option(CONFIG_MENDER_ZEPHYR_IMAGE_UPDATE_MODULE "The defautl Mender zephyr-image update module" ON)
if (CONFIG_MENDER_ZEPHYR_IMAGE_UPDATE_MODULE)
  message(STATUS "Using the default zephyr-image update module")
endif()
if (NOT CONFIG_MENDER_LOG_LEVEL)
    message(STATUS "Using default log level")
elseif (CONFIG_MENDER_LOG_LEVEL STREQUAL "off")
    message(STATUS "Using log level 'off'")
    set(CONFIG_MENDER_LOG_LEVEL MENDER_LOG_LEVEL_OFF)
elseif (CONFIG_MENDER_LOG_LEVEL STREQUAL "error")
    message(STATUS "Using log level 'error'")
    set(CONFIG_MENDER_LOG_LEVEL MENDER_LOG_LEVEL_ERR)
elseif (CONFIG_MENDER_LOG_LEVEL STREQUAL "warning")
    message(STATUS "Using log level 'warning'")
    set(CONFIG_MENDER_LOG_LEVEL MENDER_LOG_LEVEL_WRN)
elseif (CONFIG_MENDER_LOG_LEVEL STREQUAL "info")
    message(STATUS "Using log level 'info'")
    set(CONFIG_MENDER_LOG_LEVEL MENDER_LOG_LEVEL_INF)
elseif (CONFIG_MENDER_LOG_LEVEL STREQUAL "verbose")
    message(STATUS "Using log level 'verbose'")
    set(CONFIG_MENDER_LOG_LEVEL MENDER_LOG_LEVEL_VRB)
elseif (CONFIG_MENDER_LOG_LEVEL STREQUAL "debug")
    message(STATUS "Using log level 'debug'")
    set(CONFIG_MENDER_LOG_LEVEL MENDER_LOG_LEVEL_DBG)
else()
    message(FATAL_ERROR "Invalid log level '${CONFIG_MENDER_LOG_LEVEL}'")
endif()
if (NOT CONFIG_MENDER_PLATFORM_FLASH_TYPE)
    message(STATUS "Using default 'generic/weak' platform flash implementation")
    set(CONFIG_MENDER_PLATFORM_FLASH_TYPE "generic/weak")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_PLATFORM_FLASH_TYPE}' platform flash implementation")
endif()
if (NOT CONFIG_MENDER_PLATFORM_LOG_TYPE)
    message(STATUS "Using default 'generic/weak' platform log implementation")
    set(CONFIG_MENDER_PLATFORM_LOG_TYPE "generic/weak")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_PLATFORM_LOG_TYPE}' platform log implementation")
endif()
if (NOT CONFIG_MENDER_PLATFORM_NET_TYPE)
    message(STATUS "Using default 'generic/weak' platform network implementation")
    set(CONFIG_MENDER_PLATFORM_NET_TYPE "generic/weak")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_PLATFORM_NET_TYPE}' platform network implementation")
endif()
if (NOT CONFIG_MENDER_PLATFORM_SCHEDULER_TYPE)
    message(STATUS "Using default 'generic/weak' platform scheduler implementation")
    set(CONFIG_MENDER_PLATFORM_SCHEDULER_TYPE "generic/weak")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_PLATFORM_SCHEDULER_TYPE}' platform scheduler implementation")
endif()
if (NOT CONFIG_MENDER_PLATFORM_STORAGE_TYPE)
    message(STATUS "Using default 'generic/weak' platform storage implementation")
    set(CONFIG_MENDER_PLATFORM_STORAGE_TYPE "generic/weak")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_PLATFORM_STORAGE_TYPE}' platform storage implementation")
endif()
if (NOT CONFIG_MENDER_PLATFORM_TLS_TYPE)
    message(STATUS "Using default 'generic/weak' platform TLS implementation")
    set(CONFIG_MENDER_PLATFORM_TLS_TYPE "generic/weak")
else()
    message(STATUS "Using custom '${CONFIG_MENDER_PLATFORM_TLS_TYPE}' platform TLS implementation")
endif()

option(MENDER_MBEDTLS_ERROR_STR "Enable mbedtls error strings" OFF)

# Definitions
if (CONFIG_MENDER_SERVER_HOST)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_SERVER_HOST=\"${CONFIG_MENDER_SERVER_HOST}\")
endif()
if (CONFIG_MENDER_SERVER_TENANT_TOKEN)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_SERVER_TENANT_TOKEN=\"${CONFIG_MENDER_SERVER_TENANT_TOKEN}\")
endif()
if (CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL=${CONFIG_MENDER_CLIENT_AUTHENTICATION_POLL_INTERVAL})
endif()
if (CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL=${CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL})
endif()
if (CONFIG_MENDER_CLIENT_INVENTORY)
    target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_CLIENT_INVENTORY)
    if (CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL)
        target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL=${CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL})
    endif()
endif()
if (CONFIG_MENDER_ZEPHYR_IMAGE_UPDATE_MODULE)
  target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_ZEPHYR_IMAGE_UPDATE_MODULE)
endif()
if (CONFIG_MENDER_LOG_LEVEL)
    target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_LOG_LEVEL=${CONFIG_MENDER_LOG_LEVEL})
endif()
if (CONFIG_MENDER_FULL_PARSE_ARTIFACT)
    target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_FULL_PARSE_ARTIFACT)
endif()
if (CONFIG_MENDER_PROVIDES_DEPENDS)
    target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_PROVIDES_DEPENDS)
endif()

# List of sources
file(GLOB SOURCES_TEMP
    "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-api.c"
    "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-artifact.c"
    "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-client.c"
    "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-utils.c"
    "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-zephyr-image-update-module.c"
    "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-deployment-data.c"
    "${CMAKE_CURRENT_LIST_DIR}/platform/flash/${CONFIG_MENDER_PLATFORM_FLASH_TYPE}/src/mender-flash.c"
    "${CMAKE_CURRENT_LIST_DIR}/platform/log/${CONFIG_MENDER_PLATFORM_LOG_TYPE}/src/mender-log.c"
    "${CMAKE_CURRENT_LIST_DIR}/platform/net/${CONFIG_MENDER_PLATFORM_NET_TYPE}/src/mender-http.c"
    "${CMAKE_CURRENT_LIST_DIR}/platform/scheduler/${CONFIG_MENDER_PLATFORM_SCHEDULER_TYPE}/src/mender-scheduler.c"
    "${CMAKE_CURRENT_LIST_DIR}/platform/storage/${CONFIG_MENDER_PLATFORM_STORAGE_TYPE}/src/mender-storage.c"
    "${CMAKE_CURRENT_LIST_DIR}/platform/tls/${CONFIG_MENDER_PLATFORM_TLS_TYPE}/src/mender-tls.c"
)
if (CONFIG_MENDER_CLIENT_INVENTORY)
    list(APPEND SOURCES_TEMP
        "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-inventory.c"
    )
endif()
if (CONFIG_MENDER_ZEPHYR_IMAGE_UPDATE_MODULE)
    list(APPEND SOURCES_TEMP
        "${CMAKE_CURRENT_LIST_DIR}/core/src/mender-zephyr-image-update-module.c"
    )
endif()
if (CONFIG_MENDER_PLATFORM_NET_TYPE STREQUAL "zephyr")
    list(APPEND SOURCES_TEMP
        "${CMAKE_CURRENT_LIST_DIR}/platform/net/${CONFIG_MENDER_PLATFORM_NET_TYPE}/src/mender-net.c"
    )
endif()
target_sources(mender-mcu-client PRIVATE ${SOURCES_TEMP})

# Add include directories
target_include_directories(mender-mcu-client PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include")
if (CONFIG_MENDER_PLATFORM_NET_TYPE STREQUAL "zephyr")
    target_include_directories(mender-mcu-client PRIVATE "${CMAKE_CURRENT_LIST_DIR}/platform/net/${CONFIG_MENDER_PLATFORM_NET_TYPE}/include")
endif()

# cJSON location/options
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  pkg_check_modules(cjson libcjson)
  if (cjson_FOUND)
    target_compile_options(mender-mcu-client PRIVATE ${cjson_CFLAGS})
  endif()
endif()

# mbedtls error strings
if (CONFIG_MENDER_PLATFORM_TLS_TYPE STREQUAL "mbedtls")
  if (MENDER_MBEDTLS_ERROR_STR)
    target_compile_definitions(mender-mcu-client PRIVATE MBEDTLS_ERROR_C)
  endif()
endif()

# Define version
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/VERSION" MENDER_CLIENT_VERSION)
add_definitions("-DMENDER_CLIENT_VERSION=\"${MENDER_CLIENT_VERSION}\"")
