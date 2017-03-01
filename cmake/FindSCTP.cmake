#.rst:
# FindSCTP
# --------
#
# Find libsctp
#
# Find libsctp headers and libraries.
#
# ::
#
#   SCTP_INCLUDE_DIRS   - where to find sctp.h
#   SCTP_LIBRARIES      - List of libraries when using libsctp.
#   SCTP_FOUND          - True if libSCTP found.
#   SCTP_VERSION        - Version of found libsctp.

find_package(PkgConfig REQUIRED)
pkg_check_modules(SCTP libsctp)

# handle the QUIETLY and REQUIRED arguments and set TASN_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SCTP
                                  REQUIRED_VARS SCTP_LIBRARIES
                                  VERSION_VAR SCTP_VERSION)

