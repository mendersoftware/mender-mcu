# @file      asan.cmake
# @brief     Address Sanitizer options
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

include(${CMAKE_CURRENT_LIST_DIR}/helper.cmake)

if (CMAKE_BUILD_TYPE STREQUAL "ASan")
  sanitizer_add_compiler_and_linker_flags(ASAN
    "-fsanitize=address -fno-omit-frame-pointer -fsanitize-address-use-after-scope"
    "-fsanitize=address")
endif()
