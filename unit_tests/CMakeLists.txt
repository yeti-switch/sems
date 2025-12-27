find_package(GTest REQUIRED)

add_subdirectory(tests)

set(SEMS_UT sems-tester)

include_directories(${BOTAN_BUNDLED_INCLUDE_DIRS}
                    ${SPANDSP_BUNDLED_INCLUDE_DIRS}
                    ${CONFUSE_BUNDLED_INCLUDE_DIRS}
                    ${SRTP_BUNDLED_INCLUDE_DIRS}
                    ${CMAKE_SOURCE_DIR}/unit_tests)

file(GLOB tester_SRCS "*.c*")

add_executable(${SEMS_UT}
    ${tester_SRCS})
set_property(TARGET ${SEMS_UT} PROPERTY ENABLE_EXPORTS ON)
target_link_libraries(${SEMS_UT} libsems event ev GTest::gtest GTest::gtest_main)

install(TARGETS ${SEMS_UT} RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/bin)

if (BUILD_TESTING)
    set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)
    gtest_discover_tests(${SEMS_UT}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        TEST_FILTER "-*.DISABLED_*:FaxTest.*:RTPStream.SingleStreams:ZRTPTest.SingleTest:TransportTest.WebSocket"
    )

    file(MAKE_DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/rsr
        ${CMAKE_CURRENT_BINARY_DIR}/logs
    )
    set(CMAKE_CTEST_ARGUMENTS "--timeout 15" "--repeat after-timeout:3")
endif()

