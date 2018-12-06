MESSAGE(STATUS "Enable building of the bundled libsrtp")

set (SRTP_DIR third/srtp)
set (SRTP_SRC_DIR ${PROJECT_SOURCE_DIR}/${SRTP_DIR})
set (SRTP_BIN_DIR ${PROJECT_BINARY_DIR}/${SRTP_DIR})
set (SRTP_BUNDLED_LIB ${SRTP_BIN_DIR}/libsrtp2.a)

set(SRTP_CONFIG_ARGS --disable-openssl --enable-debug-logging CPPFLAGS=-fPIC)

add_custom_target(libsrtp ALL DEPENDS ${SRTP_BUNDLED_LIB})

file(MAKE_DIRECTORY ${SRTP_BIN_DIR})
add_custom_command(OUTPUT ${SRTP_BUNDLED_LIB}
    PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${SRTP_SRC_DIR} ${SRTP_BIN_DIR}
    COMMAND ./configure ${SRTP_CONFIG_ARGS}
    COMMAND $(MAKE)
    WORKING_DIRECTORY ${SRTP_BIN_DIR})

set(SRTP_BUNDLED_INCLUDE_DIRS ${SRTP_BIN_DIR}/include/)

add_library(SRTP_bundled STATIC IMPORTED)
set_property(TARGET SRTP_bundled PROPERTY IMPORTED_LOCATION ${SRTP_BUNDLED_LIB})
set(SRTP_BUNDLED_LIBS ${SRTP_BUNDLED_LIB})

install(DIRECTORY ${SRTP_BIN_DIR}/include DESTINATION /usr/include/sems/srtp/)
