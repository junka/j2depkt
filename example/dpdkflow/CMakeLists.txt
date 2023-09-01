cmake_minimum_required(VERSION 3.13.2)
project(depktdpdkflow)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O2 -fno-omit-frame-pointer -mssse3")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_package(dpdk REQUIRED)
include_directories(${dpdk_INCLUDE_DIRS})
link_directories(${dpdk_LIBRARY_DIR})

set(dpdk_dep_libs ${dpdk_STATIC_LIBRARIES})
list(FILTER dpdk_dep_libs EXCLUDE REGEX "\\.a$")
list(FILTER dpdk_dep_libs EXCLUDE REGEX "rte")

list(FILTER dpdk_STATIC_LIBRARIES INCLUDE REGEX "\\.a$")

message(STAUS ${dpdk_STATIC_LIBRARIES})

add_executable(dpdkflow main.c)
target_link_libraries(dpdkflow depkt_dpdk ${dpdk_STATIC_LIBRARIES} ${dpdk_dep_libs})
target_link_options(dpdkflow
INTERFACE
-Wl,--whole-archive ${dpdk_STATIC_LIBRARIES} -Wl,--no-whole-archive
)