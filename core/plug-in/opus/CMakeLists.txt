find_package(OPUS REQUIRED)

set (opus_SRCS
	opus.cpp
)

SET(sems_module_name opus)

SET(sems_module_libs ${OPUS_LIBRARIES})
## ./configure --with-pic --disable-extra-programs --disable-doc --enable-static --enable-shared=no --prefix=/opt/opus && make && make install
#SET(sems_module_libs /opt/opus/lib/libopus.a)
#INCLUDE_DIRECTORIES(/opt/opus/include)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/doc.rules.txt)
