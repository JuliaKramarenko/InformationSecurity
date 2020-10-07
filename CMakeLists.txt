cmake_minimum_required(VERSION 3.15)
project(aes_kalyna)

add_subdirectory(library)
add_subdirectory(executable)

enable_testing()
add_subdirectory(tests)
