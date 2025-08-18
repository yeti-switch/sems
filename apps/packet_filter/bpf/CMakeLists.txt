set(BPF_PROG0 ${CMAKE_CURRENT_BINARY_DIR}/build/skel/arena_allocator.skel.h)
set(BPF_PROG1 ${CMAKE_CURRENT_BINARY_DIR}/build/skel/ipport2ipport.skel.h)

add_custom_command(OUTPUT ${BPF_PROG0} ${BPF_PROG1}
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND make -f Makefile.bpf
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} )

add_custom_target(sems_packet_filter_bpf
    DEPENDS ${BPF_PROG0} ${BPF_PROG1} )
