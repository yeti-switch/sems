#.rst:
# FindLIBOPUS
# --------
#
# ::
#
#   OPUS_INCLUDE_DIRS   - where to find opus.h
#   OPUS_LIBRARIES      - List of libraries when using libopus
#   OPUS_FOUND          - True if libyeticc found.
#   OPUS_VERSION	  - Version of found libopus.

find_package(PkgConfig REQUIRED)
pkg_check_modules(OPUS opus)

# handle the QUIETLY and REQUIRED arguments and set OPUS_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(OPUS
                                  REQUIRED_VARS OPUS_LIBRARIES
                                  VERSION_VAR OPUS_VERSION)

