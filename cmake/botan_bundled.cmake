MESSAGE(STATUS "Enable building of the bundled libbotan")

set (BOTAN_DIR third/botan)
set (BOTAN_PATCH_FILE ${PROJECT_SOURCE_DIR}/third/botan_patch.diff)
set (BOTAN_SRC_DIR ${PROJECT_SOURCE_DIR}/${BOTAN_DIR})
set (BOTAN_BIN_DIR ${PROJECT_BINARY_DIR}/${BOTAN_DIR})
set (BOTAN_BUNDLED_LIB ${BOTAN_BIN_DIR}/libbotan-2.a)

set(BOTAN_CONFIG_ARGS --disable-shared-library --cxxflags=-fPIC --without-documentation)

add_custom_target(libbotan ALL DEPENDS ${BOTAN_BUNDLED_LIB})

#use execute_process instead of custom_command to generate headers before cmake install command invocation
IF(NOT EXISTS ${BOTAN_BIN_DIR}/configure_stdout)
    file(MAKE_DIRECTORY ${BOTAN_BIN_DIR})
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy_directory ${BOTAN_SRC_DIR} ${BOTAN_BIN_DIR})
    execute_process(COMMAND git --git-dir=${PROJECT_SOURCE_DIR}/.git/modules/${BOTAN_DIR} --work-tree=${BOTAN_BIN_DIR} apply ${BOTAN_PATCH_FILE} WORKING_DIRECTORY ${BOTAN_BIN_DIR})
    execute_process(COMMAND ./configure.py ${BOTAN_CONFIG_ARGS} OUTPUT_FILE configure_stdout WORKING_DIRECTORY ${BOTAN_BIN_DIR})
ENDIF(NOT EXISTS ${BOTAN_BIN_DIR}/configure_stdout)

add_custom_command(OUTPUT ${BOTAN_BUNDLED_LIB}
    PRE_BUILD
    COMMAND $(MAKE)
    WORKING_DIRECTORY ${BOTAN_BIN_DIR})

set(BOTAN_BUNDLED_INCLUDE_DIRS ${BOTAN_BIN_DIR}/build/include/)

add_library(BOTAN_bundled STATIC IMPORTED)
set_property(TARGET BOTAN_bundled PROPERTY IMPORTED_LOCATION ${BOTAN_BUNDLED_LIB})
set(BOTAN_BUNDLED_LIBS ${BOTAN_BUNDLED_LIB})
list(APPEND sems_dependency_targets libbotan)

file(GLOB BOTAN_INCLUDE_FILES "${BOTAN_BIN_DIR}/build/include/botan/*.h")
FOREACH(rel_file ${BOTAN_INCLUDE_FILES})
    get_filename_component(abs_file ${rel_file} REALPATH)
    install(FILES ${abs_file} DESTINATION /usr/include/sems/botan)
ENDFOREACH(rel_file ${BOTAN_INCLUDE_FILES})
