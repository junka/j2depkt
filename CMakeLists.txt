cmake_minimum_required(VERSION 3.7.2)
project(j2depkt)

add_library(depkt depktcap.c utils.c)

add_library(depkt_dpdk dpdkrflow.c utils.c)

add_subdirectory(example/pcapfilter)
add_subdirectory(example/dpdkflow)
add_subdirectory(example/tcpdump)

add_test(parser validation)

enable_testing()

install(FILES depktcap.h DESTINATION include)
install(FILES dpdkrflow.h DESTINATION include)

install(TARGETS depkt DESTINATION lib)
install(TARGETS depkt_dpdk DESTINATION lib)