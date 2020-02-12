#.rst:
# FindLIBCURL
# --------
#
# ::
#
#   CURL_INCLUDE_DIR   - where to find curl.h
#   CURL_LIBRARIES      - List of libraries when using libcurl
#   CURL_FOUND          - True if libyeticc found.
#   CURL_VERSION        - Version of found libcurl.

find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL libcurl)

# handle the QUIETLY and REQUIRED arguments and set OPUS_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CURL
                                  REQUIRED_VARS CURL_LIBRARIES
                                  VERSION_VAR CURL_VERSION)
