MESSAGE(STATUS "Enable building of the bundled Spandsp")

set (SPANDSP_DIR third/spandsp)
set (SPANDSP_SRC_DIR ${PROJECT_SOURCE_DIR}/${SPANDSP_DIR})
set (SPANDSP_BIN_DIR ${PROJECT_BINARY_DIR}/${SPANDSP_DIR})
set (SPANDSP_BUNDLED_PREFIX ${SPANDSP_BIN_DIR}/src/.libs)
set (SPANDSP_BUNDLED_LIB ${SPANDSP_BUNDLED_PREFIX}/libspandsp.a)
# set (SPANDSP_INCLUDE_HEADER ${SPANDSP_BIN_DIR}/src/spandsp.h)

set(SPANDSP_CONFIG_ARGS --enable-static --with-pic)

add_custom_target(libspandsp ALL DEPENDS ${SPANDSP_BUNDLED_LIB})

IF(NOT EXISTS ${SPANDSP_BIN_DIR}/configure_stdout)
    file(MAKE_DIRECTORY ${SPANDSP_BIN_DIR})
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy_directory ${SPANDSP_SRC_DIR} ${SPANDSP_BIN_DIR} WORKING_DIRECTORY ${SPANDSP_BIN_DIR})
    execute_process(COMMAND ./configure ${SPANDSP_CONFIG_ARGS} OUTPUT_FILE configure_stdout WORKING_DIRECTORY ${SPANDSP_BIN_DIR})
ENDIF(NOT EXISTS ${SPANDSP_BIN_DIR}/configure_stdout)

add_custom_command(OUTPUT ${SPANDSP_BUNDLED_LIB}
    COMMAND $(MAKE)
    WORKING_DIRECTORY ${SPANDSP_BIN_DIR})

add_library(SPANDSP_bundled STATIC IMPORTED)
set_property(TARGET SPANDSP_bundled PROPERTY IMPORTED_LOCATION ${SPANDSP_BUNDLED_LIB})
set(SPANDSP_BUNDLED_LIBS ${SPANDSP_BUNDLED_LIB} -ltiff -lm)
list(APPEND sems_dependency_targets SPANDSP_bundled)

set (SPANDSP_BUNDLED_INCLUDE_DIRS ${SPANDSP_BIN_DIR}/src)

install(FILES ${SPANDSP_BIN_DIR}/src/spandsp.h DESTINATION /usr/include/sems)
install(DIRECTORY ${SPANDSP_BIN_DIR}/src/spandsp DESTINATION /usr/include/sems
        FILES_MATCHING PATTERN "*.h")
