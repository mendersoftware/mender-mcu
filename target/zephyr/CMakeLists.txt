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

    # Define version
    include("${MENDER_MCU_ROOT}/cmake/git_helper.cmake")
    git_describe(${MENDER_MCU_ROOT} BUILD_VERSION_NAME)
    zephyr_library_compile_definitions(-DMENDER_CLIENT_VERSION=\"${BUILD_VERSION_NAME}\")

    zephyr_library_compile_definitions(-D_POSIX_C_SOURCE=200809L)  # Required for strdup and strtok_r support
    zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)

    if (CONFIG_MENDER_STORAGE_PARTITION_STORAGE_PARTITION)
      message(STATUS "Using storage_partition for Mender non-volatile data")
    elseif (CONFIG_MENDER_STORAGE_PARTITION_MENDER_PARTITION)
      message(STATUS "Using mender_partition for Mender non-volatile data")
    else()
      message(STATUS "Using a custom partition for Mender non-volatile data")
    endif()

    if(CONFIG_MENDER_ARTIFACT_GENERATE)
        include(${CMAKE_CURRENT_LIST_DIR}/mender-artifact.cmake)
    endif()

endif()

# Install the dormant certificates
if (CONFIG_MENDER_SERVER_DORMANT_CERTIFICATES)
    set(DORMANT_CERTIFICATE_A_LINK "https://docs.mender.io/releases/certs/isrgrootx1.der")
    set(DORMANT_CERTIFICATE_A_SHA256 96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6)
    set(DORMANT_CERTIFICATE_A "${CMAKE_CURRENT_BINARY_DIR}/dormant.cer")
    file(DOWNLOAD ${DORMANT_CERTIFICATE_A_LINK} ${DORMANT_CERTIFICATE_A} EXPECTED_HASH SHA256=${DORMANT_CERTIFICATE_A_SHA256})

    generate_inc_file_for_target(app
        ${DORMANT_CERTIFICATE_A}
        "${ZEPHYR_BINARY_DIR}/include/generated/dormant_a.cer.inc"
    )

    set(DORMANT_CERTIFICATE_B_LINK "https://docs.mender.io/releases/certs/isrg-root-x2.der")
    set(DORMANT_CERTIFICATE_B_SHA256 69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470)
    set(DORMANT_CERTIFICATE_B "${CMAKE_CURRENT_BINARY_DIR}/dormant_b.cer")
    file(DOWNLOAD ${DORMANT_CERTIFICATE_B_LINK} ${DORMANT_CERTIFICATE_B} EXPECTED_HASH SHA256=${DORMANT_CERTIFICATE_B_SHA256})

    generate_inc_file_for_target(app
        ${DORMANT_CERTIFICATE_B}
        "${ZEPHYR_BINARY_DIR}/include/generated/dormant_b.cer.inc"
    )
endif()
