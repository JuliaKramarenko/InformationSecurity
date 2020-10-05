# the following code to fetch googletest
# is inspired by and adapted after https://crascit.com/2015/07/25/cmake-gtest/
# download and unpack googletest at configure time

macro(fetch_googletest _download_module_path _download_root)
    if (WIN32)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    endif ()
    set(GOOGLETEST_DOWNLOAD_ROOT ${_download_root})
    configure_file(
            ${_download_module_path}/googletest-download.cmake
            ${_download_root}/CMakeLists.txt
            @ONLY
    )
    unset(GOOGLETEST_DOWNLOAD_ROOT)

    execute_process(
            COMMAND
            "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
            WORKING_DIRECTORY
            ${_download_root}
    )
    execute_process(
            COMMAND
            "${CMAKE_COMMAND}" --build .
            WORKING_DIRECTORY
            ${_download_root}
    )

    # adds the targers: gtest, gtest_main, gmock, gmock_main
    add_subdirectory(
            ${_download_root}/googletest-src
            ${_download_root}/googletest-build
    )
endmacro()

macro(add_gtest TESTNAME)
    target_link_libraries(${TESTNAME} PUBLIC gtest gmock gtest_main)

    if (GOOGLE_TEST_INDIVIDUAL)
        if (CMAKE_VERSION VERSION_LESS 3.10)
            gtest_add_tests(TARGET ${TESTNAME}
                    TEST_PREFIX "${TESTNAME}."
                    TEST_LIST TmpTestList)
            set_tests_properties(${TmpTestList} PROPERTIES FOLDER "Tests")
        else ()
            gtest_discover_tests(${TESTNAME}
                    TEST_PREFIX "${TESTNAME}."
                    PROPERTIES FOLDER "Tests")
        endif ()
    else ()
        add_test(${TESTNAME} ${TESTNAME})
        set_target_properties(${TESTNAME} PROPERTIES FOLDER "Tests")
    endif ()

endmacro()