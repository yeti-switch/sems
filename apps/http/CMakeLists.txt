SET(sems_module_name http_client)

file(GLOB_RECURSE http_client_SRCS *.cpp)

SET(http_client_config_files "")
SET(http_client_config_dist_files http_client)

#bundled curl
SET(sems_module_libs ${CURL_BUNDLED_LIBS})

#system curl
#FIND_PACKAGE(CURL)
#INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR})
#SET(sems_module_libs ${CURL_LIBRARIES})

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
