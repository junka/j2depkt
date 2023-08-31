cmake_minimum_required(VERSION 3.7.2)
project(depktpcapfilter)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
find_package(PCAP REQUIRED)
include_directories(${PCAP_INCLUDE_DIRS})

add_executable(pcapfilter main.c)
target_link_libraries(pcapfilter depkt pcap)