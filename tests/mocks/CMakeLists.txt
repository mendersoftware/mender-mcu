# @file      CMakeLists.txt
# @brief     Mocks CMakeLists file
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

# Include all mocks
include("${CMAKE_CURRENT_LIST_DIR}/cjson/CMakeLists.txt")
if(CONFIG_MENDER_PLATFORM_TLS_TYPE MATCHES "generic/mbedtls")
    include("${CMAKE_CURRENT_LIST_DIR}/mbedtls/CMakeLists.txt")
endif()
