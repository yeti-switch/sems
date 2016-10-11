find_package(LibXml2 REQUIRED)

set(mod_xml_SRCS ModXml.cpp)

INCLUDE_DIRECTORIES(${LIBXML2_INCLUDE_DIR})


SET(sems_dsm_module_name mod_xml)
SET(sems_dsm_module_libs ${LIBXML2_LIBRARIES})
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/dsm.lib.rules.txt)

