file(GLOB_RECURSE identity_validator_SRCS *.cpp)
list(FILTER identity_validator_SRCS EXCLUDE REGEX "unit_tests")

if(SEMS_USE_GTEST)
    file(GLOB identity_validator_UNIT_SRCS unit_tests/*.cpp)
endif(SEMS_USE_GTEST)

set(sems_module_name identity_validator)
include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)

