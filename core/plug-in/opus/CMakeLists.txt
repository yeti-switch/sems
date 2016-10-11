find_package(OPUS REQUIRED)

set (opus_SRCS
	opus.c
)

SET(sems_module_name opus)
SET(sems_module_libs ${OPUS_LIBRARIES})

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/doc.rules.txt)
