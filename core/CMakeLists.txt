FIND_PACKAGE(Spandsp REQUIRED)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/audio.rules.txt)

FILE (GLOB sems_SRCS "*.cpp" "sip/*.cpp" "resample/*.cpp" "*.c")

SET(SEMS_LIB libsems)

SET(aux_binaries decode_test utf8_test)

set (audio_files
beep.wav
default_en.wav
codecs_bench.wav
)

INCLUDE_DIRECTORIES (ampi)
INCLUDE_DIRECTORIES (amci)

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

IF(LIBZRTP_FOUND)
	LIST(APPEND common_LIBS zrtp)
ENDIF(LIBZRTP_FOUND)

TARGET_LINK_LIBRARIES(${SEMS_LIB} ${CMAKE_DL_LIBS} ${common_LIBS})
IF(SPANDSP_FOUND)
    TARGET_LINK_LIBRARIES(${SEMS_LIB} -Wl,--whole-archive ${SPANDSP_LIBRARIES} -Wl,--no-whole-archive)
ENDIF(SPANDSP_FOUND)

TARGET_LINK_LIBRARIES(${SEMS_APP} ${SEMS_LIB})
FOREACH(aux_binary IN LISTS aux_binaries)
	TARGET_LINK_LIBRARIES(sems_${aux_binary} ${SEMS_LIB})
ENDFOREACH(aux_binary)

ADD_SUBDIRECTORY(plug-in)
ADD_SUBDIRECTORY(cmake)

# Create config-file from template
CONFIGURE_FILE (${CMAKE_SOURCE_DIR}/core/etc/app_mapping.conf.sample ${CMAKE_SOURCE_DIR}/core/etc/app_mapping.conf)
CONFIGURE_FILE (${CMAKE_SOURCE_DIR}/core/etc/sems.conf.cmake ${CMAKE_SOURCE_DIR}/core/etc/sems.conf.dist)

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
INSTALL(FILES ./etc/sems.conf.dist DESTINATION ${SEMS_CFG_PREFIX}/etc/sems/)
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
