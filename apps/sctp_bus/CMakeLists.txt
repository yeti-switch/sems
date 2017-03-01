find_package(Confuse REQUIRED)
find_package(SCTP REQUIRED)
find_package(Protobuf REQUIRED)

file(GLOB_RECURSE PB_DEFS proto/*.proto)
message(STATUS "Generate protocol buffers classes")
execute_process(
    COMMAND protoc -I ${CMAKE_CURRENT_SOURCE_DIR}/proto --cpp_out ${CMAKE_CURRENT_BINARY_DIR} ${PB_DEFS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    RESULT_VARIABLE PROTOC_RESULT
    ERROR_VARIABLE PROTOC_ERROR
	OUTPUT_VARIABLE PROTOC_OUTPUT)
if(PROTOC_RESULT)
    message(FATAL_ERROR "can't generate procotol buffers classes: ${PROTOC_ERROR}") 
endif(PROTOC_RESULT)

foreach(def ${PB_DEFS})
	get_filename_component(src ${def} NAME_WE)
	list(APPEND PB_LIBS ${CMAKE_CURRENT_BINARY_DIR}/${src}.pb.cc)
endforeach(def)

add_library(pb_classes ${PB_LIBS})

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INCLUDE_DIRS})

set(sems_module_name sctp_bus)
set(sems_module_libs ${Confuse_LIBRARIES} ${SCTP_LIBRARIES} ${PROTOBUF_LIBRARIES} pb_classes)

file(GLOB sctp_bus_SRCS "*.cpp")

set(sctp_bus_config_files "")
set(sctp_bus_config_dist_files sctp_bus)
include(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
