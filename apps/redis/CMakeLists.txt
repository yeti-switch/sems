file(GLOB_RECURSE redis_SRCS *.cpp)
list(FILTER redis_SRCS EXCLUDE REGEX "unit_tests")

if(SEMS_USE_GTEST)
    file(GLOB redis_UNIT_SRCS unit_tests/*.cpp)
    set(redis_UNIT_INSTALL TRUE)
endif(SEMS_USE_GTEST)

find_package(Hiredis REQUIRED)
if (HIREDIS_FOUND)
    SET(sems_module_libs ${HIREDIS_LIBRARIES})
endif()

set(sems_module_name redis)
include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)

