# @file      CMakeLists.txt
# @brief     Unit Tests for Mender MCU platform independent code
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

cmake_minimum_required(VERSION 3.16.3)
project(mender-mcu-tests-unit)

# Include sanitizers options for CMAKE_BUILD_TYPE
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/asan.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/threadsan.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/undefsan.cmake")

# Include mender-mcu-client library, forcing warnings and errors
set(CONFIG_MENDER_ALL_WARNINGS_AS_ERRORS ON CACHE BOOL "All warnings as errors" FORCE)
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../target/posix" build)

# And add the same flags for the test targets too
add_compile_options(-Wall -Wextra -Werror -Wpointer-arith)

# Silence C/C++ compat warning for structs and unions
add_compile_options(-Wno-extern-c-compat)

enable_testing()

option(COVERAGE "Turn coverage instrumentation on (Default: OFF)" OFF)
if($CACHE{COVERAGE})
  set(CMAKE_CXX_FLAGS "--coverage $CACHE{CMAKE_CXX_FLAGS}")
endif()

set(GTEST_VERSION 1.12.1)

option(MENDER_DOWNLOAD_GTEST "Download google test if it is not found (Default: ON)" ON)

if (MENDER_DOWNLOAD_GTEST)

  ### BEGIN taken from https://google.github.io/googletest/quickstart-cmake.html
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/release-${GTEST_VERSION}.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )

  # For Windows: Prevent overriding the parent project's compiler/linker settings
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  ### END

  set(BUILD_GMOCK ON)
  set(INSTALL_GTEST OFF)
  FetchContent_MakeAvailable(googletest)

else()
  find_package(GTest REQUIRED)
endif()

if($CACHE{COVERAGE})
  add_custom_target(coverage_enabled COMMAND true)
else()
  add_custom_target(coverage_enabled
    COMMAND echo 'Please run `cmake -D COVERAGE=ON .` first!'
    COMMAND false
  )
endif()

set(MENDER_COVERAGE_EXCLUDE_FLAGS
  --exclude '/usr/*'
  --exclude '*/_deps/*'
  --exclude '*_test.*'
)
# Following the recipe from lcov man page, genearte
# an initial report and then the tests one, so that the
# source files with 0% coverage are also reported. See:
# https://linux.die.net/man/1/lcov
add_custom_target(coverage
  COMMAND lcov --add-tracefile initial.info --add-tracefile tests.info --output-file coverage.lcov
  DEPENDS coverage-tests coverage-initial
)
add_custom_target(coverage-initial
  COMMAND lcov --capture --quiet --directory .
               --initial
               --output-file initial.info
               ${MENDER_COVERAGE_EXCLUDE_FLAGS}
  DEPENDS coverage_enabled tests
)
add_custom_target(coverage-tests
  COMMAND lcov --capture --quiet --directory .
               --output-file tests.info
               ${MENDER_COVERAGE_EXCLUDE_FLAGS}
  DEPENDS coverage_enabled check
)

# CMake is not clever enough to build the tests before running them so we use
# the 'check' target below that does both.
add_custom_target(check
  COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
  DEPENDS tests
)
add_custom_target(tests
  # This target itself does nothing, but all tests are added as dependencies for it.
  COMMAND true
)

include(GoogleTest)
set(MENDER_TEST_FLAGS EXTRA_ARGS --gtest_output=xml:${CMAKE_SOURCE_DIR}/reports/)

add_library(main_test STATIC EXCLUDE_FROM_ALL main_test.cpp)
target_link_libraries(main_test PUBLIC gtest)
target_compile_options(main_test PRIVATE ${PLATFORM_SPECIFIC_COMPILE_OPTIONS})
add_dependencies(tests main_test)

# test for core source files
add_executable(core_test EXCLUDE_FROM_ALL core/mender-utils_test.cpp)
target_link_libraries(core_test PUBLIC
  mender-mcu-client
  gtest
  main_test
)
gtest_discover_tests(core_test
  ${MENDER_TEST_FLAGS}
  NO_PRETTY_VALUES
)
add_dependencies(tests core_test)
