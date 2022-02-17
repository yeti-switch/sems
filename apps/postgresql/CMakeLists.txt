SET(sems_module_name postgresql)

file(GLOB postgresql_SRCS *.cpp)

IF(SEMS_USE_GTEST)
    file(GLOB postgresql_UNIT_SRCS unit_tests/*.cpp)
ENDIF(SEMS_USE_GTEST)

SET(postgresql_config_files "")
SET(postgresql_dist_files postgresql)

FIND_LIBRARY(PQ pq)
INCLUDE_DIRECTORIES(${PG_INCLUDE_DIR})
SET(sems_module_libs ${PQ})

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
