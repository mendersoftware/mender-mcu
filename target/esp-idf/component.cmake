# @file      component.cmake
# @brief     mender-mcu ESP-IDF component file
#
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

# Set project root
get_filename_component(MENDER_MCU_ROOT ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)

set(CONFIG_MENDER_PLATFORM_LOG_TYPE "esp-idf")
set(CONFIG_MENDER_PLATFORM_SCHEDULER_TYPE "freertos")

include(${MENDER_MCU_ROOT}/cmake/mender_mcu_sources.txt)

idf_component_register(
    SRCS ${MENDER_MCU_SOURCES}
    INCLUDE_DIRS ${MENDER_MCU_INCLUDE}
    PRIV_INCLUDE_DIRS ${MENDER_PRIV_INCLUDE}
    # menuconfig entries; the values land as the CONFIG_MENDER_* CMake
    # variables consumed by the definitions below.
    KCONFIG ${MENDER_MCU_ROOT}/target/esp-idf/Kconfig
)

# The FreeRTOS platform sources use vanilla FreeRTOS includes (e.g. <FreeRTOS.h>),
# while ESP-IDF namespaces them under freertos/. Add the kernel header directory
# to the include path so the vanilla includes resolve.
idf_component_get_property(freertos_dir freertos COMPONENT_DIR)
target_include_directories(${COMPONENT_LIB} PRIVATE ${freertos_dir}/FreeRTOS-Kernel/include/freertos)

include(${MENDER_MCU_ROOT}/cmake/CMake_defaults.txt)
if(CONFIG_MENDER_LOG_LEVEL)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CONFIG_MENDER_LOG_LEVEL=${CONFIG_MENDER_LOG_LEVEL})
endif()
if(CONFIG_MENDER_CLIENT_INVENTORY_DISABLE)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CONFIG_MENDER_CLIENT_INVENTORY_DISABLE)
endif()
if(CONFIG_MENDER_FULL_PARSE_ARTIFACT)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CONFIG_MENDER_FULL_PARSE_ARTIFACT)
endif()
if(CONFIG_MENDER_PROVIDES_DEPENDS)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CONFIG_MENDER_PROVIDES_DEPENDS)
endif()
if(CONFIG_MENDER_COMMIT_REQUIRE_AUTH)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CONFIG_MENDER_COMMIT_REQUIRE_AUTH)
endif()
if(CONFIG_MENDER_ERRORS_THRESHOLD_NET)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CONFIG_MENDER_ERRORS_THRESHOLD_NET=${CONFIG_MENDER_ERRORS_THRESHOLD_NET})
endif()
if(CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT=${CONFIG_MENDER_ERRORS_THRESHOLD_REBOOT})
endif()
if(CONFIG_MENDER_SERVER_HOST)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_SERVER_HOST=\"${CONFIG_MENDER_SERVER_HOST}\")
endif()
if(CONFIG_MENDER_SERVER_TENANT_TOKEN)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_SERVER_TENANT_TOKEN=\"${CONFIG_MENDER_SERVER_TENANT_TOKEN}\")
endif()
if(CONFIG_MENDER_DEVICE_TIER)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_DEVICE_TIER=\"${CONFIG_MENDER_DEVICE_TIER}\")
endif()
# default the device type to the chip, like the Zephyr Kconfig defaults to BOARD
if(NOT CONFIG_MENDER_DEVICE_TYPE)
    set(CONFIG_MENDER_DEVICE_TYPE ${IDF_TARGET})
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_DEVICE_TYPE=\"${CONFIG_MENDER_DEVICE_TYPE}\")
if(CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL=${CONFIG_MENDER_CLIENT_UPDATE_POLL_INTERVAL})
endif()
if(CONFIG_MENDER_RETRY_ERROR_BACKOFF)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_RETRY_ERROR_BACKOFF=${CONFIG_MENDER_RETRY_ERROR_BACKOFF})
endif()
if(CONFIG_MENDER_RETRY_ERROR_MAX_BACKOFF)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_RETRY_ERROR_MAX_BACKOFF=${CONFIG_MENDER_RETRY_ERROR_MAX_BACKOFF})
endif()
if(CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL=${CONFIG_MENDER_CLIENT_INVENTORY_REFRESH_INTERVAL})
endif()
if(CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE=${CONFIG_MENDER_SCHEDULER_WORK_QUEUE_STACK_SIZE})
endif()
if(CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY=${CONFIG_MENDER_SCHEDULER_WORK_QUEUE_PRIORITY})
endif()
if(CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH=${CONFIG_MENDER_SCHEDULER_WORK_QUEUE_LENGTH})
endif()

# TODO: figure out how to dynamically get the version.
# The component manager only fetches the staged files, so no git information is available
target_compile_definitions(${COMPONENT_LIB} PUBLIC MENDER_CLIENT_VERSION="esp-idf-demo")
