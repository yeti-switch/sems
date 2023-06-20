MESSAGE(STATUS "Enable building of the bundled s3")

set (S3_DIR third/s3)
set (S3_SRC_DIR ${PROJECT_SOURCE_DIR}/${S3_DIR})
set (S3_BIN_DIR ${PROJECT_BINARY_DIR}/${S3_DIR})
set (S3_BUNDLED_LIB ${S3_BIN_DIR}/build/libs3.a)
set (S3_INCLUDE_DIR ${S3_BIN_DIR}/include)

execute_process(COMMAND ${CMAKE_COMMAND} -E copy_directory ${S3_SRC_DIR}/inc ${S3_INCLUDE_DIR}/s3)
file(MAKE_DIRECTORY ${S3_BIN_DIR}/build)

find_package(LibXml2 REQUIRED)

file(GLOB_RECURSE s3_SRCS ${S3_SRC_DIR}/src/*.c)
list(REMOVE_ITEM s3_SRCS ${S3_SRC_DIR}/src/mingw_functions.c ${S3_SRC_DIR}/src/mingw_s3_functions.c)
add_library(s3 STATIC ${s3_SRCS})
target_compile_definitions(s3 PUBLIC LIBS3_VER_MAJOR="1" LIBS3_VER_MINOR="0")
target_include_directories(s3 PUBLIC ${S3_INCLUDE_DIR}/s3 ${LIBXML2_INCLUDE_DIR})
set_property(TARGET s3 PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(s3 ${LIBXML2_LIBRARIES})
set_target_properties(s3 PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${S3_BIN_DIR}/build")

install(DIRECTORY ${S3_INCLUDE_DIR} DESTINATION /usr/include/sems
        FILES_MATCHING PATTERN "*.h")
