find_package(GTest REQUIRED)

set(SEMS_UT sems-tester)

include_directories(${BOTAN_BUNDLED_INCLUDE_DIRS}
                    ${SPANDSP_BUNDLED_INCLUDE_DIRS}
                    ${CONFUSE_BUNDLED_INCLUDE_DIRS}
                    ${SRTP_BUNDLED_INCLUDE_DIRS}
                    ${CMAKE_SOURCE_DIR}/unit_tests)

file(GLOB tester_SRCS "*.c*")
file(GLOB tester_test_SRCS "tests/*.cpp")

add_executable(${SEMS_UT}
    ${tester_test_SRCS}
    ${tester_SRCS})
set_property(TARGET ${SEMS_UT} PROPERTY ENABLE_EXPORTS ON)
target_link_libraries(${SEMS_UT} libsems event ev GTest::gtest GTest::gtest_main)

install(TARGETS ${SEMS_UT} RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/bin)

gtest_discover_tests(${SEMS_UT}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    TEST_FILTER "-*.DISABLED_*:FaxTest.*:RTPStream.SingleStreams:ZRTPTest.SingleTest:TransportTest.WebSocket"
)

file(MAKE_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}/rsr
    ${CMAKE_CURRENT_BINARY_DIR}/logs
)
