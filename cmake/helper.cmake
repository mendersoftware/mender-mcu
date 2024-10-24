# @file      helper.cmake
# @brief     Helper for sanitaziers
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

function (sanitizer_add_compiler_and_linker_flags CONFIG SANITIZER_BUILD_FLAGS SANITIZER_SHARED_LINKER_FLAGS)

  message (STATUS "Adding the compiler flags flags: ${SANITIZER_BUILD_FLAGS}")
  message (STATUS "Adding the linker flags: ${SANITIZER_SHARED_LINKER_FLAGS}")

  set(CMAKE_C_FLAGS_${CONFIG}
    "${CMAKE_C_FLAGS_DEBUG} ${SANITIZER_BUILD_FLAGS}" CACHE STRING
    "Flags used by the C compiler for ${CONFIG} build type or configuration." FORCE)

  set(CMAKE_CXX_FLAGS_${CONFIG}
    "${CMAKE_CXX_FLAGS_DEBUG} ${SANITIZER_BUILD_FLAGS}" CACHE STRING
    "Flags used by the C++ compiler for ${CONFIG} build type or configuration." FORCE)

  set(CMAKE_EXE_LINKER_FLAGS_${CONFIG}
    "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} ${SANITIZER_BUILD_FLAGS}" CACHE STRING
    "Linker flags to be used to create executables for ${CONFIG} build type." FORCE)

  set(CMAKE_SHARED_LINKER_FLAGS_${CONFIG}
    "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} ${SANITIZER_SHARED_LINKER_FLAGS}" CACHE STRING
    "Linker lags to be used to create shared libraries for ${CONFIG} build type." FORCE)

endfunction ()
