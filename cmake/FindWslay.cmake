#.rst:
# FindWslay
# --------
#
# Find Wslay
#
# Find Wslay headers and libraries.
#
# ::
#
#   Wslay_LIBRARIES      - List of libraries when using Wslay.
#   Wslay_FOUND          - True if libwslay found.
#   Wslay_VERSION        - Version of found libwslay.
FIND_PATH(WSLAY_INCLUDE_DIR wslay/wslay.h)
FIND_LIBRARY(WSLAY_LIBRARIES NAMES wslay PATHS /usr/lib/x86_64-linux-gnu)

IF(WSLAY_INCLUDE_DIR AND WSLAY_LIBRARIES)
	SET(WSLAY_FOUND TRUE)
ELSE(WSLAY_INCLUDE_DIR AND WSLAY_LIBRARIES)
    SET(WSLAY_FOUND FALSE)
ENDIF(WSLAY_INCLUDE_DIR AND WSLAY_LIBRARIES)

IF(WSLAY_FOUND)
    MESSAGE(STATUS "Found wslay includes:	${WSLAY_INCLUDE_DIR}/wslay")
    MESSAGE(STATUS "Found wslay library: ${WSLAY_LIBRARIES}")
ELSE(WSLAY_FOUND)
	IF (Wslay_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could NOT find wslay development files")
	ENDIF (Wslay_FIND_REQUIRED)
ENDIF(WSLAY_FOUND)

