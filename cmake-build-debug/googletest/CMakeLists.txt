# code copied from https://crascit.com/2015/07/25/cmake-gtest/
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(googletest-download NONE)

include(ExternalProject)

ExternalProject_Add(
        googletest
        SOURCE_DIR "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-src"
        BINARY_DIR "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-build"
        GIT_REPOSITORY
        https://github.com/google/googletest.git
        GIT_TAG
        release-1.10.0
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        TEST_COMMAND ""
)
