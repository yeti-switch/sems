FIND_PACKAGE(Spandsp REQUIRED)
FIND_PACKAGE(Wslay REQUIRED)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/audio.rules.txt)

FILE (GLOB sems_SRCS "*.cpp" "sip/*.cpp" "resample/*.cpp" "*.c" "rtcp/*.cpp")

SET(SEMS_LIB libsems)

SET(aux_binaries decode_test utf8_test)

set (audio_files
beep.wav
default_en.wav
codecs_bench.wav
)

INCLUDE_DIRECTORIES (ampi)
INCLUDE_DIRECTORIES (amci)
INCLUDE_DIRECTORIES (${BOTAN_BUNDLED_INCLUDE_DIRS}
                     ${SRTP_BUNDLED_INCLUDE_DIRS}
                     ${CONFUSE_BUNDLED_INCLUDE_DIRS}
                     ${STUN_BUNDLED_INCLUDE_DIRS})

SET(common_LIBS stdc++ resolv mp3lame event event_pthreads)

SET(sems_LIB_SRCS ${sems_SRCS})
LIST(REMOVE_ITEM sems_LIB_SRCS sems.cpp)

ADD_LIBRARY(${SEMS_LIB} SHARED ${sems_LIB_SRCS})
SET_TARGET_PROPERTIES(${SEMS_LIB} PROPERTIES
	VERSION ${YETI_MAJOR_VERSION}.${YETI_MINOR_VERSION}.${YETI_PATCH_VERSION}
	SOVERSION ${YETI_MAJOR_VERSION})

ADD_EXECUTABLE(${SEMS_APP} sems.cpp)
FOREACH(aux_binary IN LISTS aux_binaries)
	ADD_EXECUTABLE (sems_${aux_binary} aux/${aux_binary}.cpp)
ENDFOREACH(aux_binary)

IF(NOT MAX_RTP_SESSIONS)
	SET(MAX_RTP_SESSIONS 2048)
ENDIF(NOT MAX_RTP_SESSIONS)

#ADD_DEFINITIONS(-DMAX_RTP_SESSIONS=${MAX_RTP_SESSIONS})
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMAX_RTP_SESSIONS=${MAX_RTP_SESSIONS}")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMAX_RTP_SESSIONS=${MAX_RTP_SESSIONS}")

IF(LIBSAMPLERATE_FOUND)
	LIST(APPEND common_LIBS samplerate)
ENDIF(LIBSAMPLERATE_FOUND)

IF(BZRTP_FOUND)
	LIST(APPEND common_LIBS bzrtp)
ENDIF(BZRTP_FOUND)

IF(WSLAY_FOUND)
	LIST(APPEND common_LIBS wslay)
ENDIF(WSLAY_FOUND)

TARGET_LINK_LIBRARIES(${SEMS_LIB} ${CMAKE_DL_LIBS} ${common_LIBS})
TARGET_LINK_LIBRARIES(${SEMS_LIB} ${BOTAN_BUNDLED_LIBS} ${CONFUSE_BUNDLED_LIBS} ${SRTP_BUNDLED_LIBS} ${STUN_BUNDLED_LIBS})
IF(SPANDSP_FOUND)
    TARGET_LINK_LIBRARIES(${SEMS_LIB} -Wl,--whole-archive ${SPANDSP_LIBRARIES} -Wl,--no-whole-archive)
ENDIF(SPANDSP_FOUND)

MESSAGE(STATUS "${SEMS_LIB} dependency: ${sems_dependency_targets}")
ADD_DEPENDENCIES(${SEMS_LIB} ${sems_dependency_targets})

TARGET_LINK_LIBRARIES(${SEMS_APP} ${SEMS_LIB})
FOREACH(aux_binary IN LISTS aux_binaries)
	TARGET_LINK_LIBRARIES(sems_${aux_binary} ${SEMS_LIB})
ENDFOREACH(aux_binary)

ADD_SUBDIRECTORY(plug-in)
ADD_SUBDIRECTORY(cmake)

# Create config-file from template
CONFIGURE_FILE (${CMAKE_SOURCE_DIR}/core/etc/app_mapping.conf.sample ${CMAKE_SOURCE_DIR}/core/etc/app_mapping.conf)

INSTALL(
	TARGETS ${SEMS_LIB} ${SEMS_APP}
	RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/sbin
	LIBRARY DESTINATION ${SEMS_EXEC_PREFIX}/${SEMS_LIBDIR}
)
FOREACH(aux_binary IN LISTS aux_binaries)
	INSTALL(TARGETS sems_${aux_binary} RUNTIME DESTINATION ${SEMS_EXEC_PREFIX}/sbin)
ENDFOREACH(aux_binary)

CONFIGURE_FILE(${SEMS_LIB}.pc.in ${SEMS_LIB}.pc)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${SEMS_LIB}.pc DESTINATION ${PKGCFG_DIR})

# Installation of config-files
INSTALL(FILES ./etc/app_mapping.conf DESTINATION ${SEMS_CFG_PREFIX}/etc/sems/etc/)
INSTALL(FILES ./etc/rtsp_client.conf.dist DESTINATION ${SEMS_CFG_PREFIX}/etc/sems/etc/)
IF(LIBZRTP_FOUND)
INSTALL(FILES ./etc/zrtp.conf DESTINATION ${SEMS_CFG_PREFIX}/etc/sems/etc/)
ENDIF(LIBZRTP_FOUND)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/doc.rules.txt)

SET(doc_dirs ../doc/figures)
SET(doc_files
	../doc/Applications.txt
	../doc/Howtostart_noproxy.txt
	../doc/Howtostart_simpleproxy.txt
	../doc/Howtostart_voicemail.txt
	../doc/CHANGELOG
	../doc/COPYING
	../doc/Tuning.txt
)

#SEMS_INSTALL_DOCS("${doc_files}" "${doc_dirs}")
SEMS_INSTALL_AUDIO("" "${audio_files}")

add_custom_target(install-dev
    install -d /usr/include/sems
    COMMAND install -v -D libsems.pc /usr/lib/pkgconfig/
    COMMAND install -v -D -t /usr/share/cmake/sems ${CMAKE_SOURCE_DIR}/core/cmake/*.txt ${CMAKE_SOURCE_DIR}/core/cmake/FindSEMS.cmake
    COMMAND install -v -D -t /usr/include/sems ${CMAKE_SOURCE_DIR}/core/*.cc ${CMAKE_SOURCE_DIR}/core/*.h ${CONFUSE_BIN_DIR}/src/confuse.h ${CMAKE_BINARY_DIR}/core/sems.h
    COMMAND install -v -D -t /usr/include/sems/rtcp ${CMAKE_SOURCE_DIR}/core/rtcp/*.h
    COMMAND install -v -D -t /usr/include/sems/ampi ${CMAKE_SOURCE_DIR}/core/ampi/*.h
    COMMAND install -v -D -t /usr/include/sems/amci ${CMAKE_SOURCE_DIR}/core/amci/*.h
    COMMAND install -v -D -t /usr/include/sems/rtp ${CMAKE_SOURCE_DIR}/core/rtp/*.h
    COMMAND install -v -D -t /usr/include/sems/compat ${CMAKE_SOURCE_DIR}/core/compat/*.c ${CMAKE_SOURCE_DIR}/core/compat/*.h
    COMMAND install -v -D -t /usr/include/sems/sip ${CMAKE_SOURCE_DIR}/core/sip/*.h
    COMMAND install -v -D -t /usr/include/sems/resample ${CMAKE_SOURCE_DIR}/core/resample/*.h
)
