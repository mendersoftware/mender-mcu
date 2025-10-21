# @file      mender-artifact.cmake
# @brief     CMake code to generate the Mender Artifact
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

# Check for the tool and the Artifact Name. The rest of the parameters have defaults
find_program(mender_artifact_found mender-artifact)
if(NOT mender_artifact_found)
    message(FATAL_ERROR "mender-artifact not found in PATH. Visit https://docs.mender.io/downloads#mender-artifact to download the tool or disable Artifact generation with MENDER_ARTIFACT_GENERATE")
endif()

# Fail if version mender-artifact version doesn't have the Artifact size functionality
if (CONFIG_MENDER_ARTIFACT_SIZE_LIMITS)
    execute_process(COMMAND mender-artifact write module-image --help OUTPUT_VARIABLE HELP_OUTPUT OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(FIND "${HELP_OUTPUT}" "--warn-artifact-size" FOUND_ARTIFACT_SIZE)
    if (FOUND_ARTIFACT_SIZE LESS 0)
        message(FATAL_ERROR "Setting Artifact size limits require mender-artifact >= 4.2.0")
    endif()
endif()

# Print a warning on empty Artifact name
if(CONFIG_MENDER_ARTIFACT_NAME STREQUAL "")
    message(WARNING "MENDER_ARTIFACT_NAME cannot be empty; Artifact generation will fail. Set the variable in your build or alternatively disable the feature with CONFIG_MENDER_ARTIFACT_GENERATE=n")
endif()

# Assemble the mender-artifact arguments
set(mender_artifact_cmd mender-artifact write module-image)
# No compression
set(mender_artifact_cmd ${mender_artifact_cmd} --compression none)
# Artifact name
set(mender_artifact_cmd ${mender_artifact_cmd} --artifact-name '${CONFIG_MENDER_ARTIFACT_NAME}')
# Update Module
set(mender_artifact_cmd ${mender_artifact_cmd} --type ${CONFIG_MENDER_ARTIFACT_TYPE})
# Device type
string(REPLACE " " ";" device_type_list ${CONFIG_MENDER_DEVICE_TYPES_COMPATIBLE})
foreach(device_type ${device_type_list})
    set(mender_artifact_cmd ${mender_artifact_cmd} --device-type ${device_type})
endforeach()
# Artifact provides
if(NOT CONFIG_MENDER_ARTIFACT_PROVIDES STREQUAL "")
    string(REPLACE " " ";" provides_list ${CONFIG_MENDER_ARTIFACT_PROVIDES})
    foreach(provides ${provides_list})
        set(mender_artifact_cmd ${mender_artifact_cmd} --provides ${provides})
    endforeach()
endif()
# Artifact depends
if(NOT CONFIG_MENDER_ARTIFACT_DEPENDS STREQUAL "")
    string(REPLACE " " ";" depends_list ${CONFIG_MENDER_ARTIFACT_DEPENDS})
    foreach(depends ${depends_list})
        set(mender_artifact_cmd ${mender_artifact_cmd} --depends ${depends})
    endforeach()
endif()
# Prefix for the default provides
set(mender_artifact_cmd ${mender_artifact_cmd} --software-filesystem ${CONFIG_MENDER_ARTIFACT_SOFTWARE_FILESYSTEM})
set(mender_artifact_cmd ${mender_artifact_cmd} --software-name ${CONFIG_MENDER_ARTIFACT_SOFTWARE_NAME})
# Set fail/warn limits on Artifact size
if (CONFIG_MENDER_ARTIFACT_WARN_SIZE)
    set(mender_artifact_cmd ${mender_artifact_cmd} --warn-artifact-size ${CONFIG_MENDER_ARTIFACT_WARN_SIZE})
endif()
if (CONFIG_MENDER_ARTIFACT_MAX_SIZE)
    set(mender_artifact_cmd ${mender_artifact_cmd} --max-artifact-size ${CONFIG_MENDER_ARTIFACT_MAX_SIZE})
endif()
# Extra arguments
if(NOT CONFIG_MENDER_ARTIFACT_EXTRA_ARGS STREQUAL "")
    separate_arguments(extra_args UNIX_COMMAND ${CONFIG_MENDER_ARTIFACT_EXTRA_ARGS})
    set(mender_artifact_cmd ${mender_artifact_cmd} ${extra_args})
endif()
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
