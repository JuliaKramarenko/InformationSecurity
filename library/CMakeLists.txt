add_library(aes
        aes-helpers/tables.h
        aes-helpers/tables.cpp
        aes-helpers/transformations.h
        aes-helpers/transformations.cpp
        include/aes.h
        src/aes.cpp
        src/rc4.cpp
        include/rc4.h
        include/salsa20.h
        src/salsa20.cpp
        include/sha256.h
        src/sha256.cpp
        src/kupyna.cpp
        include/kupyna.h
        kupyna-helpers/tables.cpp
        kupyna-helpers/tables.h)

add_library(rsa
        include/rsa.h
        src/rsa.cpp
        rsa-helpers/helpers.h
        rsa-helpers/helpers.cpp
        )

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

target_include_directories(rsa PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        rsa-helpers
        PRIVATE src)

target_link_libraries(rsa gmp libgmp)

set_target_properties(aes kalyna rsa PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS OFF)
