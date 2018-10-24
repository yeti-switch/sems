MESSAGE(STATUS "Enable building of the bundled libbotan")

set (BOTAN_DIR third/botan)
set (BOTAN_SRC_DIR ${PROJECT_SOURCE_DIR}/${BOTAN_DIR})
set (BOTAN_BIN_DIR ${PROJECT_BINARY_DIR}/${BOTAN_DIR})
set (BOTAN_BUNDLED_LIB ${BOTAN_BIN_DIR}/libbotan-2.a)

set(BOTAN_CONFIG_ARGS --disable-shared-library --cxxflags=-fPIC)

add_custom_target(libbotan ALL DEPENDS ${BOTAN_BUNDLED_LIB})

file(MAKE_DIRECTORY ${BOTAN_BIN_DIR})
add_custom_command(OUTPUT ${BOTAN_BUNDLED_LIB}
    PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${BOTAN_SRC_DIR} ${BOTAN_BIN_DIR}
    COMMAND ./configure.py ${BOTAN_CONFIG_ARGS}
    COMMAND $(MAKE)
    WORKING_DIRECTORY ${BOTAN_BIN_DIR})

set(BOTAN_BUNDLED_INCLUDE_DIRS ${BOTAN_BIN_DIR}/build/include/)

add_library(BOTAN_bundled STATIC IMPORTED)
set_property(TARGET BOTAN_bundled PROPERTY IMPORTED_LOCATION ${BOTAN_BUNDLED_LIB})
set(BOTAN_BUNDLED_LIBS ${BOTAN_BUNDLED_LIB})

install(DIRECTORY ${BOTAN_BIN_DIR}/build/include/botan DESTINATION /usr/include/sems/botan-2/botan)
