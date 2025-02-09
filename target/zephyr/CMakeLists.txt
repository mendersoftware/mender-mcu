# @file      CMakeLists.txt
# @brief     mender-mcu-client zephyr module CMakeLists file
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

if(CONFIG_MENDER_MCU_CLIENT)
    # Include helper to define MENDER_MCU_ variables
    include(../../cmake/mender_mcu_sources.txt)

    zephyr_library()
    zephyr_library_sources(${MENDER_MCU_SOURCES})
    zephyr_include_directories(${MENDER_MCU_INCLUDE})
    zephyr_include_directories("${MENDER_MCU_ROOT}/platform/net/zephyr/include")

    file (STRINGS ${MENDER_MCU_VERSION_FILE} MENDER_CLIENT_VERSION)
    zephyr_library_compile_definitions(-DMENDER_CLIENT_VERSION=\"${MENDER_CLIENT_VERSION}\")
    zephyr_library_compile_definitions(-D_POSIX_C_SOURCE=200809L)  # Required for strdup and strtok_r support
    zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)

    # TODO: get the property instead
    # get_target_property(out runners_yaml_props_target bin_file)"
    # get_target_property(out runners_yaml_props_target hex_file)"
    # ...

    set(output_signed ${ZEPHYR_BINARY_DIR}/${KERNEL_NAME}.signed.bin)
    set(mender_artifact ${ZEPHYR_BINARY_DIR}/${KERNEL_NAME}.mender)

    # Assemble the mender-artifact arguments
    set(mender_artifact_args write module-image)
    # No compression
    set(mender_artifact_args ${mender_artifact_args} --compression none)
    # Update Module
    # TODO: take it from Kconfig
    set(mender_artifact_args ${mender_artifact_args} --type zephyr-image)
    # Device Type
    set(mender_artifact_args ${mender_artifact_args} --device-type ${CONFIG_MENDER_DEVICE_TYPE})
    # Artifact Name
    # TODO: take it from Kconfig
    set(mender_artifact_args ${mender_artifact_args} --artifact-name lluis-update)

    set_property(
        GLOBAL APPEND PROPERTY
        extra_post_build_commands
        COMMAND
        # mender-artifact ${mender_artifact_args} --file ${output_signed} --output-path ${mender_artifact}
        rm -f ${mender_artifact}
    )

    # set_property(
    #     GLOBAL APPEND PROPERTY
    #     extra_post_build_byproducts
    #     ${mender_artifact}
    # )

    add_custom_target(
        mender-artifact ALL
        COMMAND
        test -f ${mender_artifact} ||
        echo "Generating Mender Artifact from ${output_signed} for board ${BOARD}" &&
        mender-artifact ${mender_artifact_args} --file ${output_signed} --output-path ${mender_artifact}
        DEPENDS
        ${output_signed}
        BYPRODUCTS
        ${mender_artifact}
    )

    # add_custom_command(
    #     TARGET zephyr_final
    #     POST_BUILD
    #     COMMAND mender-artifact ${mender_artifact_args} --file ${output_signed} --output-path ${mender_artifact}
    #     BYPRODUCTS
    #     ${mender_artifact}
    # )

    # add_custom_command(
    #     OUTPUT ${mender_artifact}
    #     DEPENDS zephyr_final
    #     COMMAND mender-artifact ${mender_artifact_args} --file ${output_signed} --output-path ${mender_artifact}
    # )

    # add_custom_target (
    #     something
    #     COMMAND mender-artifact ${mender_artifact_args} --file ${output_signed} --output-path ${mender_artifact}
    #     DEPENDS ${output_signed}
    #     BYPRODUCTS
    #     ${mender_artifact}
    #     COMMENT "dummy Generating Mender Artifact from ${output_signed} for board ${BOARD}"
    #  )

endif()
