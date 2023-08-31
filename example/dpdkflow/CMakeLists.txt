cmake_minimum_required(VERSION 3.7.2)
project(depktdpdkflow)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_library(dpdk libdpdk)


add_executable(dpdkflow main.c)
target_link_libraries(dpdkflow depkt_dpdk)