cmake_minimum_required(VERSION 3.7.2)
project(j2depkt)

add_custom_command (
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser.c
    COMMAND peg -P ${CMAKE_CURRENT_SOURCE_DIR}/parser.peg -o ${CMAKE_CURRENT_SOURCE_DIR}/parser.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.peg
    COMMENT "generating parser.c..."
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_custom_target(parser DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parser.c)


add_library(depkt depktcap.c utils.c)
add_dependencies(depkt parser)
add_library(depkt_dpdk dpdkrflow.c utils.c)
add_dependencies(depkt_dpdk parser)

add_subdirectory(example/pcapfilter)
add_subdirectory(example/tcpdump)
add_subdirectory(example/dpdkflow)

enable_testing ()
add_subdirectory(tests)

install(FILES depktcap.h DESTINATION include)
install(FILES dpdkrflow.h DESTINATION include)

install(TARGETS depkt DESTINATION lib)
install(TARGETS depkt_dpdk DESTINATION lib)