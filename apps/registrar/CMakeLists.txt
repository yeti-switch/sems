file(GLOB_RECURSE registrar_SRCS *.cpp)
list(FILTER registrar_SRCS EXCLUDE REGEX "unit_tests")

if(SEMS_USE_GTEST)
    file(GLOB registrar_UNIT_SRCS unit_tests/*.cpp)
endif(SEMS_USE_GTEST)

add_subdirectory(etc)

find_package(Hiredis REQUIRED)
if (HIREDIS_FOUND)
    SET(sems_module_libs ${HIREDIS_LIBRARIES})
endif()

set(sems_module_name registrar)
include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
