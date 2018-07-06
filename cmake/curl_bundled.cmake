MESSAGE(STATUS "Enable building of the bundled Curl")

set (CURL_DIR third/curl)
set (CURL_SRC_DIR ${PROJECT_SOURCE_DIR}/${CURL_DIR})
set (CURL_BIN_DIR ${PROJECT_BINARY_DIR}/${CURL_DIR})
set (CURL_BUNDLED_PREFIX ${CURL_BIN_DIR}/lib/.libs)
set (CURL_BUNDLED_LIB ${CURL_BUNDLED_PREFIX}/libcurl.a)

set(CURL_WITHOUT --without-libssh2 --without-librtmp --without-libpsl --without-libidn2)
set(CURL_ENABLE --enable-ares --enable-debug)
set(CURL_DISABLE0 --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-proxy --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-gopher)
set(CURL_DISABLE1 --disable-thread --disable-manual --disable-dependency-tracking --disable-cookies --disable-silent-rules --disable-symbol-hiding --disable-shared)
set(CURL_WITH --with-ssl --with-gssapi=/usr --with-lber-lib=lber --with-ca-path=/etc/ssl/certs)
set(CURL_OPTS --quiet)
set(CURL_CONFIG_ARGS ${CURL_WITHOUT} ${CURL_DISABLE0} ${CURL_DISABLE1} ${CURL_ENABLE} ${CURL_WITH} ${CURL_OPTS})

add_custom_target(libcurl ALL DEPENDS ${CURL_BUNDLED_LIB})

file(MAKE_DIRECTORY ${CURL_BIN_DIR})
add_custom_command(OUTPUT ${CURL_BUNDLED_LIB}
    PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CURL_SRC_DIR} ${CURL_BIN_DIR}
    COMMAND ./buildconf
    COMMAND ./configure ${CURL_CONFIG_ARGS}
    COMMAND $(MAKE)
    WORKING_DIRECTORY ${CURL_BIN_DIR})

set(CURL_BUNDLED_INCLUDE_DIR ${CURL_BIN_DIR}/include)

add_library(curl_bundled STATIC IMPORTED)
set_property(TARGET curl_bundled PROPERTY IMPORTED_LOCATION ${CURL_BUNDLED_LIB})
set(CURL_BUNDLED_LIBS -L/lib64 -lgssapi_krb5 ssl cares crypto z ${CURL_BUNDLED_LIB})
