# @file      CMakeLists.txt
# @brief     Test application CMakeLists file
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

# CMake configurations
set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "Configs" FORCE)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define PROJECT_BASE_NAME
set(PROJECT_BASE_NAME mender-mcu-client)
message("Configuring for ${PROJECT_BASE_NAME} - Build type is ${CMAKE_BUILD_TYPE}")

# Define project
project(${PROJECT_BASE_NAME} LANGUAGES C ASM)

# Declare the executable first, so that we can add flags and sources later on
set(EXECUTABLE_NAME ${PROJECT_BASE_NAME}.elf)
message("Executable name: ${EXECUTABLE_NAME}")
add_executable(${EXECUTABLE_NAME})

# Define compile options
if (CMAKE_BUILD_TYPE MATCHES "Debug")
    target_compile_options(${EXECUTABLE_NAME} PRIVATE -O1 -g)
    target_compile_definitions(${EXECUTABLE_NAME} PRIVATE DEBUG)
else()
    target_compile_options(${EXECUTABLE_NAME} PRIVATE -Os)
endif()

# Add sources
file(GLOB_RECURSE SOURCES_TEMP "${CMAKE_CURRENT_LIST_DIR}/*.c")
target_sources(${EXECUTABLE_NAME} PRIVATE ${SOURCES_TEMP})

# Include mender-mcu-client library
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../target/posix" build)

# Add definitions to configure the client
if(CONFIG_MENDER_PLATFORM_NET_TYPE MATCHES "zephyr")
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_NET_CA_CERTIFICATE_TAG=1)
endif()
if(CONFIG_MENDER_PLATFORM_STORAGE_TYPE MATCHES "zephyr/nvs")
    target_compile_definitions(mender-mcu-client PRIVATE CONFIG_MENDER_STORAGE_NVS_SECTOR_COUNT=4)
endif()

# Link the mender-mcu-client library
if(CONFIG_MENDER_PLATFORM_NET_TYPE MATCHES "generic/curl")
    target_link_libraries(mender-mcu-client PRIVATE curl)
endif()
if(CONFIG_MENDER_PLATFORM_SCHEDULER_TYPE MATCHES "posix")
    target_link_libraries(mender-mcu-client PRIVATE rt)
endif()

# Link the executable with the mender-mcu-client library
target_link_libraries(${EXECUTABLE_NAME} mender-mcu-client pthread)
