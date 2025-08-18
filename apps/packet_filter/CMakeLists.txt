add_subdirectory(bpf)

FILE(GLOB_RECURSE packet_filter_SRCS *.cpp)
list(FILTER packet_filter_SRCS EXCLUDE REGEX "unit_tests")
SET(sems_module_name packet_filter)
SET(sems_module_libs bpf)

IF(SEMS_USE_GTEST)
    file(GLOB packet_filter_UNIT_SRCS unit_tests/*.cpp)
ENDIF(SEMS_USE_GTEST)

SET(sems_module_dependency sems_packet_filter_bpf)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/bpf/include
                    ${CMAKE_CURRENT_BINARY_DIR}/bpf/build/skel)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)


