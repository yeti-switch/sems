SET(sems_module_name s3_client)

file(GLOB_RECURSE s3_client_SRCS *.cpp)
list(FILTER s3_client_SRCS EXCLUDE REGEX "unit_tests")

IF(SEMS_USE_GTEST)
    file(GLOB s3_client_UNIT_SRCS unit_tests/*.cpp)
ENDIF(SEMS_USE_GTEST)

SET(s3_client_config_files "")
SET(s3_client_dist_files s3_client)

SET(sems_module_libs ${CURL_BUNDLED_LIBS} S3_bundled)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)

