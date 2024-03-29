#apt install libvo-amrwbenc-dev libopencore-amrnb-dev libopencore-amrwb-dev

FIND_PATH(OPENCORE-AMRNB_INCLUDE_DIR interf_dec.h HINTS /usr/include/opencore-amrnb )
FIND_PATH(OPENCORE-AMRWB_INCLUDE_DIR dec_if.h HINTS /usr/include/opencore-amrwb )

FIND_LIBRARY(OPENCORE-AMRNB_LIBRARIES NAMES opencore-amrnb)
FIND_LIBRARY(OPENCORE-AMRWB_LIBRARIES NAMES opencore-amrwb)
FIND_LIBRARY(OPENCORE-VO-AMRW_LIBRARIES NAMES vo-amrwbenc)

LIST(APPEND OPENCORE-AMR_LIBRARIES ${OPENCORE-AMRNB_LIBRARIES})
LIST(APPEND OPENCORE-AMR_LIBRARIES ${OPENCORE-AMRWB_LIBRARIES})
LIST(APPEND OPENCORE-AMR_LIBRARIES ${OPENCORE-VO-AMRW_LIBRARIES})

IF(OPENCORE-AMRNB_INCLUDE_DIR AND OPENCORE-AMRWB_INCLUDE_DIR AND OPENCORE-AMR_LIBRARIES)
	SET(OPENCORE-AMR_FOUND TRUE)
ENDIF(OPENCORE-AMRNB_INCLUDE_DIR AND OPENCORE-AMRWB_INCLUDE_DIR AND OPENCORE-AMR_LIBRARIES)

IF(OPENCORE-AMR_FOUND)
	IF (NOT opencore-amr_FIND_QUIETLY)
		MESSAGE(STATUS "Found libopencore-amrnb includes:	${OPENCORE-AMRNB_INCLUDE_DIR}")
		MESSAGE(STATUS "Found libopencore-amrwb includes:	${OPENCORE-AMRWB_INCLUDE_DIR}")
		MESSAGE(STATUS "Found libopencore-amr library: ${OPENCORE-AMR_LIBRARIES}")
	ENDIF (NOT opencore-amr_FIND_QUIETLY)
ELSE(OPENCORE-AMR_FOUND)
	IF (opencore-amr_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could NOT find libopencore-amrnb development files")
	ENDIF (opencore-amr_FIND_REQUIRED)
ENDIF(OPENCORE-AMR_FOUND)

