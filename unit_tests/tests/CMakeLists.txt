SET(sems_module_name core_unit)
file(GLOB_RECURSE core_unit_SRCS *.cpp)
SET(sems_module_libs BOTAN_bundled)

SET(MODULE_VERSION "${SEMS_VERSION}")
ADD_DEFINITIONS(-DMOD_NAME="${sems_module_name}"  -DMODULE_VERSION="${MODULE_VERSION}")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})
ADD_DEFINITIONS("-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/=${sems_module_name}:")
ADD_LIBRARY(sems_${sems_module_name} MODULE ${${sems_module_name}_SRCS})
TARGET_LINK_LIBRARIES(sems_${sems_module_name} ${CMAKE_DL_LIBS} ${sems_module_libs})
SET_TARGET_PROPERTIES(sems_${sems_module_name} PROPERTIES OUTPUT_NAME ${sems_module_name})
SET_TARGET_PROPERTIES(sems_${sems_module_name} PROPERTIES PREFIX "")
