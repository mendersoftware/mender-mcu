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

# Include helpers to define default cache and MENDER_MCU_ variables
include(../../cmake/CMake_posix_defaults.txt)
include(../../cmake/mender_mcu_sources.txt)

# Compiler options
if (CONFIG_MENDER_ALL_WARNINGS_AS_ERRORS)
    add_compile_options(-Wall -Wextra -Werror -Wpointer-arith)
endif()

# Creation of the library
add_library(mender-mcu-client STATIC)
target_sources(mender-mcu-client PRIVATE ${MENDER_MCU_SOURCES})
target_include_directories(mender-mcu-client PUBLIC ${MENDER_MCU_INCLUDE})

option(COVERAGE "Turn coverage instrumentation on (Default: OFF)" OFF)
if($CACHE{COVERAGE})
  target_compile_options(mender-mcu-client PRIVATE --coverage)
endif()

# POSIX definitions, mimicking what KConfig defines for Zephyr OS builds
if (CONFIG_MENDER_SERVER_HOST)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_SERVER_HOST=\"${CONFIG_MENDER_SERVER_HOST}\")
endif()
if (CONFIG_MENDER_SERVER_TENANT_TOKEN)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_SERVER_TENANT_TOKEN=\"${CONFIG_MENDER_SERVER_TENANT_TOKEN}\")
endif()
if (CONFIG_MENDER_DEVICE_TYPE)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_DEVICE_TYPE=\"${CONFIG_MENDER_DEVICE_TYPE}\")
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
if (CONFIG_MENDER_COMMIT_REQUIRE_AUTH)
    target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_COMMIT_REQUIRE_AUTH)
endif()
if (CONFIG_MENDER_ERRORS_THRESHOLD_NET)
    target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_ERRORS_THRESHOLD_NET=${CONFIG_MENDER_ERRORS_THRESHOLD_NET})
endif()
if (CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT)
    target_compile_definitions(mender-mcu-client PUBLIC CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT=${CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT})
endif()

find_package(PkgConfig REQUIRED)

# Depencency: cJSON. Rely on the system provided package
pkg_check_modules(cjson REQUIRED libcjson)
target_compile_options(mender-mcu-client PUBLIC ${cjson_CFLAGS})
target_link_libraries(mender-mcu-client PRIVATE cjson)

# Depencency: Mbed TLS. Fetch the project from upstream
# This is because the popular Linux distributions (Fedora, Ubuntu) are stuck in 2.x version
# due to an breaking API change in 3.x. As Zephyr project uses 3.x, we want to avoid poluting
# the code with many ifdefs for the two major versions
include(FetchContent)
FetchContent_Declare(
  MbedTLS
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
  GIT_TAG        v3.6.2
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  FIND_PACKAGE_ARGS NAMES MbedTLS
)

# We don't want to build MbedTLS tests and utilities. The only working way to do
# so seems to be to preset the variables/options MbedTLS uses for this before we
# "include" it. Unfortunately, they are not not prefixed and don't have very
# specific names. See
# https://github.com/Mbed-TLS/mbedtls/issues/2824#issuecomment-2457546685 for
# details.
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
message(STATUS "Fetching MbedTLS...")
FetchContent_MakeAvailable(MbedTLS)
unset(ENABLE_TESTING CACHE)
unset(ENABLE_PROGRAMS CACHE)

find_package(MbedTLS REQUIRED)
target_link_libraries(mender-mcu-client PRIVATE MbedTLS::mbedtls)

# mbedtls error strings
option(MENDER_MBEDTLS_ERROR_STR "Enable mbedtls error strings" OFF)
if (CONFIG_MENDER_PLATFORM_TLS_TYPE STREQUAL "mbedtls")
  if (MENDER_MBEDTLS_ERROR_STR)
    target_compile_definitions(mender-mcu-client PRIVATE MBEDTLS_ERROR_C)
  endif()
endif()

# Define version
file(STRINGS ${MENDER_MCU_VERSION_FILE} MENDER_CLIENT_VERSION)
add_definitions("-DMENDER_CLIENT_VERSION=\"${MENDER_CLIENT_VERSION}\"")
