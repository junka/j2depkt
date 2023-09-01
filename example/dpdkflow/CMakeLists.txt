cmake_minimum_required(VERSION 3.13.2)
project(depktdpdkflow)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O2 -fno-omit-frame-pointer -mssse3")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")

set(ENV{PKG_CONFIG_PATH} "${CMAKE_BINARY_DIR}/install/lib/pkgconfig")

find_package(dpdk REQUIRED)
include_directories(${dpdk_INCLUDE_DIRS})
link_directories(${dpdk_LIBRARY_DIRS})
include_directories(${CMAKE_SOURCE_DIR})

set(dpdk_dep_libs ${dpdk_STATIC_LIBRARIES})
list(FILTER dpdk_dep_libs EXCLUDE REGEX "\\.a$")
list(FILTER dpdk_dep_libs EXCLUDE REGEX "rte")
list(FILTER dpdk_dep_libs EXCLUDE REGEX "rdma")
list(FILTER dpdk_dep_libs EXCLUDE REGEX "efa")

list(FILTER dpdk_STATIC_LIBRARIES INCLUDE REGEX "\\.a$")

add_executable(dpdkflow main.c)

target_link_libraries(dpdkflow PUBLIC depkt_dpdk ${dpdk_dep_libs} "-Wl,--whole-archive -l${dpdk_STATIC_LIBRARIES} -Wl,--no-whole-archive")
#)
