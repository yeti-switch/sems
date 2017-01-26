set(bin sems-di-log-extract)

include_directories(..)

add_executable(${bin} extract.cpp)
set_target_properties(${bin} PROPERTIES LINK_FLAGS -static)

install(TARGETS ${bin} RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/sbin)

install(PROGRAMS sems-di-log-dump DESTINATION ${SEMS_EXEC_PREFIX}/sbin)
