find_package(CURL REQUIRED)

set (mod_curl_SRCS ModCurl.cpp)

INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIRS})

SET(sems_dsm_module_name mod_curl)
SET(sems_dsm_module_libs ${CURL_LIBRARIES})
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/dsm.lib.rules.txt)

