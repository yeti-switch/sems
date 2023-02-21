set (mp3_SRCS
mp3.cpp
)

#ifeq ($(WITH_MPG123DECODER), yes)
#	module_ldflags += -lmpg123
#	module_cflags += -DWITH_MPG123DECODER

ADD_DEFINITIONS(-DWITH_MPG123DECODER)

SET(sems_module_name mp3)
SET(sems_module_libs mp3lame mpg123)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
