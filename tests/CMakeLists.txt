# for cmake > 3.11, we can follow http://google.github.io/googletest/quickstart-cmake.html
cmake_minimum_required(VERSION 3.7.2)
project(parser_test)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(GTEST_SOURCE_DIR googletest)
set(BUILD_GMOCK OFF CACHE BOOL "Builds the Google Mock library")

enable_testing()

add_subdirectory(${GTEST_SOURCE_DIR})
enable_testing()
include_directories(${GTEST_SOURCE_DIR}/googletest/include)

add_executable(parser_test  test_parser.cc)
target_link_libraries(parser_test gtest gtest_main)

add_test(NAME parser_test COMMAND parser_test)

add_custom_target(pytest
    COMMAND ${CMAKE_CTEST_COMMAND} -R "pytest"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Function to add a pytest test
function(add_pytest_test test_name test_file)
    add_test(NAME ${test_name}
        COMMAND pytest ${test_file}
    )
    set_tests_properties(${test_name} PROPERTIES LABELS "pytest")
endfunction()

# add_pytest_test()