
if(NOT "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-prefix/src/googletest-stamp/googletest-gitinfo.txt" IS_NEWER_THAN "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-prefix/src/googletest-stamp/googletest-gitclone-lastrun.txt")
  message(STATUS "Avoiding repeated git clone, stamp file is up to date: 'C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-prefix/src/googletest-stamp/googletest-gitclone-lastrun.txt'")
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E remove_directory "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: 'C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-src'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "C:/Program Files/Git/cmd/git.exe"  clone  "https://github.com/google/googletest.git" "googletest-src"
    WORKING_DIRECTORY "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest"
    RESULT_VARIABLE error_code
    )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once:
          ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/google/googletest.git'")
endif()

execute_process(
  COMMAND "C:/Program Files/Git/cmd/git.exe"  checkout release-1.10.0 --
  WORKING_DIRECTORY "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: 'release-1.10.0'")
endif()

execute_process(
  COMMAND "C:/Program Files/Git/cmd/git.exe"  submodule update --recursive --init 
  WORKING_DIRECTORY "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: 'C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-src'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy
    "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-prefix/src/googletest-stamp/googletest-gitinfo.txt"
    "C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-prefix/src/googletest-stamp/googletest-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: 'C:/Users/juliy/CLionProjects/aes-kalyna/cmake-build-debug/googletest/googletest-prefix/src/googletest-stamp/googletest-gitclone-lastrun.txt'")
endif()

