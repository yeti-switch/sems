IF(SEMS_USE_AMARG_STAT)
    set(USE_AMARG_STAT_DEFINITION "add_definitions(\"-DUSE_AMARG_STATISTIC\")")
ENDIF(SEMS_USE_AMARG_STAT)

CONFIGURE_FILE (${CMAKE_SOURCE_DIR}/core/cmake/module.rules.sample ${CMAKE_SOURCE_DIR}/core/cmake/module.rules.txt)

FILE(GLOB CMAKE_MAKE_HELPERS "*.cmake" "*.rules.txt")
INSTALL(FILES ${CMAKE_MAKE_HELPERS} DESTINATION /usr/share/cmake/sems)
