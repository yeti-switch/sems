set(bin sems-di-log-extract)

include_directories(..)

add_executable(${bin} extract.cpp)
IF(USE_ADDRESS_SANITIZER)
    set_target_properties(${bin} PROPERTIES LINK_FLAGS -shared)
ELSE(USE_ADDRESS_SANITIZER)
    set_target_properties(${bin} PROPERTIES LINK_FLAGS -static)
ENDIF(USE_ADDRESS_SANITIZER)

install(TARGETS ${bin} RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/bin)

install(PROGRAMS sems-di-log-dump DESTINATION ${SEMS_EXEC_PREFIX}/bin)
