MESSAGE(STATUS "Enable building of the bundled libconfuse")

set (CONFUSE_DIR third/confuse)
set (CONFUSE_DEPENDENCY_TARGET libconfuse)
set (CONFUSE_SRC_DIR ${PROJECT_SOURCE_DIR}/${CONFUSE_DIR})
set (CONFUSE_BIN_DIR ${PROJECT_BINARY_DIR}/${CONFUSE_DIR})
set (CONFUSE_BUNDLED_LIB ${CONFUSE_BIN_DIR}/src/.libs/libconfuse.a)

set(CONFUSE_CONFIG_ARGS --enable-shared=no --enable-static=yes --with-pic=yes)

add_custom_target(libconfuse ALL DEPENDS ${CONFUSE_BUNDLED_LIB})

file(MAKE_DIRECTORY ${CONFUSE_BIN_DIR})
add_custom_command(OUTPUT ${CONFUSE_BUNDLED_LIB}
    PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CONFUSE_SRC_DIR} ${CONFUSE_BIN_DIR}
    COMMAND ./configure ${CONFUSE_CONFIG_ARGS}
    COMMAND $(MAKE)
    WORKING_DIRECTORY ${CONFUSE_BIN_DIR})

set(CONFUSE_BUNDLED_INCLUDE_DIRS ${CONFUSE_BIN_DIR}/src/)

add_library(CONFUSE_bundled STATIC IMPORTED)
set_property(TARGET CONFUSE_bundled PROPERTY IMPORTED_LOCATION ${CONFUSE_BUNDLED_LIB})
set(CONFUSE_BUNDLED_LIBS ${CONFUSE_BUNDLED_LIB})
list(APPEND sems_dependency_targets ${CONFUSE_DEPENDENCY_TARGET})

install(FILES ${CONFUSE_BIN_DIR}/src/confuse.h DESTINATION /usr/include/sems/)
