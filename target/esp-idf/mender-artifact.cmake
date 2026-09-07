# @file      mender-artifact.cmake
# @brief     ESP-IDF -specific CMake code to generate Mender Artifacts
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

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/mender-artifact.cmake)

function(run_mender_artifact)
  set(base_cmd ${ARGV})
  # Input file
  if(CONFIG_MENDER_ARTIFACT_PAYLOAD_FILE STREQUAL "")
    set(mender_artifact_payload "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.bin")
  else()
    set(mender_artifact_payload ${CONFIG_MENDER_ARTIFACT_PAYLOAD_FILE})
  endif()
  # Output file
  if(CONFIG_MENDER_ARTIFACT_OUTPUT_FILE STREQUAL "")
    set(mender_artifact_output "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.mender")
  else()
    set(mender_artifact_output ${CONFIG_MENDER_ARTIFACT_OUTPUT_FILE})
  endif()
  set(MENDER_ARTIFACT_CMD_ALL ${base_cmd} --file ${mender_artifact_payload} --output-path ${mender_artifact_output})

  # Execute a command right after the main app binary is successfully linked
  add_custom_command(TARGET app POST_BUILD
    COMMAND ${MENDER_ARTIFACT_CMD_ALL}
    COMMENT "Generating Mender Artifact..."
  )
endfunction()

# We need to defer the Artifact creation to the the source directory scope,
# i.e. to the main app/project build because that's where the main binary
# is built.
# On top of that, ${mender_artifact_cmd} is a directory/function-local variable,
# but cmake_language(DEFER) only re-evaluates variable references in its
# arguments at the time the deferred call runs (in the scope of
# CMAKE_SOURCE_DIR), not when it is scheduled. Wrapping in EVAL CODE with a
# bracket argument forces immediate substitution so the value survives.
cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY \"${CMAKE_SOURCE_DIR}\" CALL run_mender_artifact [[${mender_artifact_cmd}]])")

