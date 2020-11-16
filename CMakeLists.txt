cmake_minimum_required(VERSION 3.15)
project(aes_kalyna)

set(CMAKE_MODULE_PATH
        ${CMAKE_CURRENT_LIST_DIR}/cmake
        ${CMAKE_MODULE_PATH})

find_package(GMP REQUIRED)

add_subdirectory(library)
add_subdirectory(executable)

enable_testing()
add_subdirectory(tests)
