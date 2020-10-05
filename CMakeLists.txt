cmake_minimum_required(VERSION 3.15)
project(aes_kalyna)

include(cmake/googletest.cmake)

fetch_googletest(
        ${PROJECT_SOURCE_DIR}/cmake
        ${PROJECT_BINARY_DIR}/googletest
)

add_subdirectory(library)
add_subdirectory(executable)

enable_testing()
add_subdirectory(tests)
