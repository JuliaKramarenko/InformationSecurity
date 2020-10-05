add_library(aes
        aes-helpers/tables.h
        aes-helpers/tables.cpp
        aes-helpers/transformations.h
        aes-helpers/transformations.cpp
        include/aes.h
        src/aes.cpp)

add_library(kalyna
        kalyna-helpers/tables.h
        kalyna-helpers/tables.cpp
        kalyna-helpers/transformations.h
        kalyna-helpers/transformations.cpp
        include/kalyna.h
        src/kalyna.cpp)

target_include_directories(aes PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src aes-helpers)

target_include_directories(kalyna PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src kalyna-helpers)

set_target_properties(aes kalyna PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS OFF)
