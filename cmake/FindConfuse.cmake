#.rst:
# FindConfuse
# --------
#
# Find Confuse
#
# Find Confuse headers and libraries.
#
# ::
#
#   Confuse_LIBRARIES      - List of libraries when using Confuse.
#   Confuse_FOUND          - True if libconfuse found.
#   Confuse_VERSION        - Version of found libconfuse.

find_package(PkgConfig REQUIRED)
pkg_check_modules(Confuse libconfuse)

# handle the QUIETLY and REQUIRED arguments and set Confuse_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Confuse
                                  REQUIRED_VARS Confuse_LIBRARIES
				  VERSION_VAR Confuse_VERSION)

