# @file      CMakeLists.txt
# @brief     mender-mcu-client zephyr module CMakeLists file
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

if(CONFIG_MENDER_MCU_CLIENT)
    # Include helper to define MENDER_MCU_ variables
    include(../../cmake/mender_mcu_sources.txt)

    zephyr_library()
    zephyr_library_sources(${MENDER_MCU_SOURCES})
    zephyr_library_include_directories(${MENDER_PRIV_INCLUDE})
    zephyr_include_directories(${MENDER_MCU_INCLUDE})

    file (STRINGS ${MENDER_MCU_VERSION_FILE} MENDER_CLIENT_VERSION)
    zephyr_library_compile_definitions(-DMENDER_CLIENT_VERSION=\"${MENDER_CLIENT_VERSION}\")
    zephyr_library_compile_definitions(-D_POSIX_C_SOURCE=200809L)  # Required for strdup and strtok_r support
    zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)

    if(CONFIG_MENDER_ARTIFACT_GENERATE)
        include(${CMAKE_CURRENT_LIST_DIR}/mender-artifact.cmake)
    endif()

endif()
