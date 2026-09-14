# @file      mender-artifact.cmake
# @brief     Zephyr-specific CMake code to generate Mender Artifacts
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

# Input file
if(CONFIG_MENDER_ARTIFACT_PAYLOAD_FILE STREQUAL "")
    set(mender_artifact_payload ${ZEPHYR_BINARY_DIR}/${KERNEL_NAME}.signed.bin)
else()
    set(mender_artifact_payload ${CONFIG_MENDER_ARTIFACT_PAYLOAD_FILE})
endif()
set(mender_artifact_cmd ${mender_artifact_cmd} --file ${mender_artifact_payload})
# Output file
if(CONFIG_MENDER_ARTIFACT_OUTPUT_FILE STREQUAL "")
    set(mender_artifact_output ${ZEPHYR_BINARY_DIR}/${KERNEL_NAME}.mender)
else()
    set(mender_artifact_output ${CONFIG_MENDER_ARTIFACT_OUTPUT_FILE})
endif()
set(mender_artifact_cmd ${mender_artifact_cmd} --output-path ${mender_artifact_output})

#### Design note ###
#
# Ideally, we would have used the existing hook from Zephyr project to trigger the
# Mender Artifact build as a "Build Event"
# (https://cmake.org/cmake/help/latest/command/add_custom_command.html#build-events)
# through extra_post_build_commands with something like:
#
# set_property(
#     GLOBAL APPEND PROPERTY extra_post_build_commands COMMAND ${mender_artifact_cmd}
# )
# set_property(
#     GLOBAL APPEND PROPERTY extra_post_build_byproducts ${mender_artifact_output}
# )
#
# However, the Mender Artifact post build command would depend on the signed
# kernel, which is in itself generated through a post build command
# (https://github.com/zephyrproject-rtos/zephyr/blob/v4.0.0/cmake/mcuboot.cmake#L149)
# and there is no way to "sort" the command or declare interdependencies between
# them.
#
# So here is the workaround: as a post build command just remove the Artifact,
# so that we clear any stale Artifact every time that we build a new kernel. And
# then as custom target that runs always, we check and generate the Artifact
# opportunistically.
# 
##################

set_property(
    GLOBAL APPEND PROPERTY
    extra_post_build_commands
    COMMAND
    rm -f ${mender_artifact_output}
)

add_custom_target(
    mender-artifact ALL
    COMMAND
    test -f ${mender_artifact_output} ||
    echo "Generating Mender Artifact ${CONFIG_MENDER_ARTIFACT_NAME} for devices ${CONFIG_MENDER_DEVICE_TYPES_COMPATIBLE} from ${mender_artifact_payload}" &&
    ${mender_artifact_cmd} 
    DEPENDS
    ${mender_artifact_payload}
    BYPRODUCTS
    ${mender_artifact_output}
)
