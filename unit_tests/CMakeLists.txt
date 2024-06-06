cmake_minimum_required(VERSION 3.0)

find_package(GTest REQUIRED)
include(GoogleTest)

set(SEMS_UT sems-tester)
set(SEMS_UT_LDHELPER ldhelper)

add_library(${SEMS_UT_LDHELPER} SHARED ldhelper.c)
target_compile_definitions(${SEMS_UT_LDHELPER} PUBLIC _GNU_SOURCE)
target_link_libraries(${SEMS_UT_LDHELPER} dl)
install(TARGETS ${SEMS_UT_LDHELPER} RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/bin)

include_directories(${BOTAN_BUNDLED_INCLUDE_DIRS}
                    ${SPANDSP_BUNDLED_INCLUDE_DIRS}
                    ${CONFUSE_BUNDLED_INCLUDE_DIRS}
                    ${SRTP_BUNDLED_INCLUDE_DIRS}
                    ${CMAKE_SOURCE_DIR}/unit_tests)

file(GLOB tester_SRCS "*.cpp")
file(GLOB tester_test_SRCS "tests/*.cpp")

add_executable(${SEMS_UT} ${tester_test_SRCS} ${tester_SRCS})
target_link_libraries(${SEMS_UT} ${SEMS_UT_LDHELPER} GTest::GTest GTest::Main event ev libsems)
install(TARGETS sems-tester RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/bin)

