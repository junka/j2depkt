cmake_minimum_required(VERSION 3.7.2)
project(depktdpdkflow)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O2 -fno-omit-frame-pointer -mssse3")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_package(dpdk REQUIRED)
include_directories(${dpdk_INCLUDE_DIRS})

add_executable(dpdkflow main.c)
target_link_libraries(dpdkflow depkt_dpdk ${dpdk_LIBRARIES})