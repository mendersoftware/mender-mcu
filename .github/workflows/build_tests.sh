#!/bin/bash
# @file      build_tests.sh
# @brief     Build all tests
#
# Copyright joelguittet and mender-mcu-client contributors
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

set -e

cd tests
mkdir -p build
cd build

# Build weak use case
cmake .. -G "Unix Makefiles" -DCONFIG_MENDER_PLATFORM_FLASH_TYPE="generic/weak" -DCONFIG_MENDER_PLATFORM_LOG_TYPE="generic/weak" -DCONFIG_MENDER_PLATFORM_NET_TYPE="generic/weak" -DCONFIG_MENDER_PLATFORM_SCHEDULER_TYPE="generic/weak" -DCONFIG_MENDER_PLATFORM_STORAGE_TYPE="generic/weak" -DCONFIG_MENDER_PLATFORM_TLS_TYPE="generic/weak" -DCONFIG_MENDER_CLIENT_INVENTORY=ON
make -j$(nproc)

# Build Posix use case
cmake .. -G "Unix Makefiles" -DCONFIG_MENDER_PLATFORM_FLASH_TYPE="posix" -DCONFIG_MENDER_PLATFORM_LOG_TYPE="posix" -DCONFIG_MENDER_PLATFORM_NET_TYPE="generic/curl" -DCONFIG_MENDER_PLATFORM_SCHEDULER_TYPE="posix" -DCONFIG_MENDER_PLATFORM_STORAGE_TYPE="posix" -DCONFIG_MENDER_PLATFORM_TLS_TYPE="generic/mbedtls" -DCONFIG_MENDER_CLIENT_INVENTORY=ON
make -j$(nproc)
