include_directories(${CMAKE_CURRENT_LIST_DIR}/../../include)
set(MCU_LIBRARIES "mender-mcu-client;pthread;cjson;mbedtls;mbedx509;mbedcrypto")

# Add tests by adding the target name to this list
# Example:
# list(APPEND TEST_TARGETS mender_test_target)
list(APPEND TEST_TARGETS mender_test_client)

foreach(TEST_TARGET IN LISTS TEST_TARGETS)
    add_cmocka_test(
        ${TEST_TARGET}
        SOURCES ${TEST_TARGET}.c
        LINK_LIBRARIES ${CMOCKA_LIBRARIES} ${MCU_LIBRARIES})

        target_link_libraries(${TEST_TARGET} PRIVATE cmocka-static)
endforeach()
