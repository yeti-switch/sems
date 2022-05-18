SET(g722_SRCS g722.cpp)

#module_cflags  = -ansi # -DNOFPU

SET(sems_module_name g722)
SET(sems_module_libs ${SPANDSP_BUNDLED_LIBS})
SET(g722_doc_files Readme.g722codec)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/doc.rules.txt)
