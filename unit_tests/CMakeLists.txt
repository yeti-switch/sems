cmake_minimum_required(VERSION 3.0)

find_package(GTest REQUIRED)
include(GoogleTest)

set(SEMS_UT sems-tester)

include_directories(${BOTAN_BUNDLED_INCLUDE_DIRS}
                    ${SPANDSP_BUNDLED_INCLUDE_DIRS}
                    ${CONFUSE_BUNDLED_INCLUDE_DIRS}
                    ${SRTP_BUNDLED_INCLUDE_DIRS}
                    ${CMAKE_SOURCE_DIR}/unit_tests)

file(GLOB tester_SRCS "*.c*")
file(GLOB tester_test_SRCS "tests/*.cpp")

add_executable(${SEMS_UT} ${tester_test_SRCS} ${tester_SRCS})
target_link_libraries(${SEMS_UT} GTest::GTest GTest::Main event ev libsems)
install(TARGETS sems-tester RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/bin)

