set(sems_module_name bus_client)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LZO REQUIRED lzo2)

set(sems_module_libs ${LZO_LIBRARIES})

file(GLOB base_SRCS "*.cpp")
file(GLOB libsctp_SRCS
	libsctp/recvmsg.c
	libsctp/sendmsg.c
)
set(bus_client_SRCS ${base_SRCS} ${libsctp_SRCS})

set(bus_client_config_files "")
set(bus_client_config_dist_files bus_client)

include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
