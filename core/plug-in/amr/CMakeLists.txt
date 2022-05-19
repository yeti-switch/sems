find_package(opencore-amr REQUIRED)

set(sems_module_name amr)
set(sems_module_libs ${OPENCORE-AMR_LIBRARIES})
set(amr_SRCS amr.cpp)

include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
