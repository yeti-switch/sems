set (uac_auth_SRCS
UACAuth.cpp
HashCalculation.cpp
)

IF(SEMS_USE_GTEST)
    file(GLOB uac_auth_UNIT_SRCS unit_tests/*.cpp)
ENDIF(SEMS_USE_GTEST)

SET(sems_module_name uac_auth)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)

