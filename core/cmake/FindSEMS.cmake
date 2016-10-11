#.rst:
# FindSEMS
# --------
#
# Find libsems
#
# Find libsems headers and libraries.
#
# ::
#
#   SEMS_INCLUDE_DIRS   - libsems headers
#   SEMS_LIBRARIES      - List of libraries when using libsems
#   SEMS_FOUND          - True if libsems found.
#   SEMS_VERSION        - Version of found libyeticc.

find_package(PkgConfig REQUIRED)
pkg_check_modules(SEMS libsems)

# handle the QUIETLY and REQUIRED arguments and set SEMS_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
	SEMS
	REQUIRED_VARS SEMS_LIBRARIES
	VERSION_VAR SEMS_VERSION
)

IF (NOT SEMS_CFG_PREFIX)
        SET(SEMS_CFG_PREFIX "")
ENDIF (NOT SEMS_CFG_PREFIX)

IF (NOT SEMS_AUDIO_PREFIX)
        SET(SEMS_AUDIO_PREFIX "/usr/lib")
ENDIF (NOT SEMS_AUDIO_PREFIX)

IF (NOT SEMS_EXEC_PREFIX)
        SET(SEMS_EXEC_PREFIX "/usr")
ENDIF (NOT SEMS_EXEC_PREFIX)

IF (NOT SEMS_LIBDIR)
        SET(SEMS_LIBDIR "lib")
ENDIF (NOT SEMS_LIBDIR)

IF (NOT SEMS_DOC_PREFIX)
        SET(SEMS_DOC_PREFIX "/usr/share/doc")
ENDIF (NOT SEMS_DOC_PREFIX)

IF (NOT SEMS_CMAKE_DIR)
        SET(SEMS_CMAKE_DIR "/usr/share/cmake/sems")
ENDIF (NOT SEMS_CMAKE_DIR)

IF(NOT SEMS_FILENAME_DEF)
	#needs disabled variables escaping to use for compile definitions
	SET(SEMS_FILENAME_DEF "-D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
ENDIF(NOT SEMS_FILENAME_DEF)
