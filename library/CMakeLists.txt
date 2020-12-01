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
        kupyna-helpers/tables.h include/ecc.h src/ecc.cpp)

add_library(rsa
        include/rsa.h
        src/rsa.cpp
        rsa-helpers/helpers.h
        rsa-helpers/helpers.cpp
        )
add_library(ecc
        include/ecc.h
        src/ecc.cpp
        ecc-helpers/gf2.cpp
        ecc-helpers/gf2.h
        ecc-helpers/curve.cpp
        ecc-helpers/curve.h
        ecc-helpers/transformations.cpp
        ecc-helpers/transformations.h)

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
target_include_directories(ecc PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ecc-helpers
        PRIVATE src)


target_link_libraries(rsa ecc gmp gmpxx libgmp)

set_target_properties(aes kalyna rsa ecc PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS OFF)
