cmake_minimum_required(VERSION 3.16)

project(SecretHandshakeCpp)

## NOTE: libSodium is required for building the tests, but not the library itself.

add_subdirectory(vendor/monocypher-cpp)

set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD            11)
set(CMAKE_C_STANDARD_REQUIRED   ON)

if (MSVC)
    add_compile_options(/W4) # TODO: Add /WX
else()
    add_compile_options(-Wall -Wpedantic -Werror -Wno-unknown-pragmas)
endif()


include_directories(
    include
    vendor/monocypher-cpp/include
)


#### LIBRARY

add_library( SecretHandshakeCpp STATIC
    src/shs.cc
    src/SecretHandshake.cc
    src/SecretStream.cc
)
target_link_libraries( SecretHandshakeCpp INTERFACE
    MonocypherCpp
)


#### TESTS

if(APPLE)
    # Just for libSodium, used by shs1.c in the tests
    include_directories(SYSTEM PUBLIC
        /opt/homebrew/include
        /usr/local/include
    )
    link_directories(
        /opt/homebrew/lib
        /usr/local/lib
    )
endif()

add_executable( SecretHandshakeTests
    vendor/monocypher-cpp/tests/tests_main.cc           # Include the Monocypher-cpp tests too
    vendor/monocypher-cpp/tests/MonocypherCppTests.cc
    tests/shsTests.cc
    tests/SecretHandshakeTests.cc
    vendor/shs1-c/src/shs1.c
)
target_include_directories( SecretHandshakeTests PRIVATE
    vendor/shs1-c/src/
    vendor/catch2
    vendor/monocypher-cpp/tests/
)
target_link_libraries( SecretHandshakeTests PRIVATE
    SecretHandshakeCpp
    sodium                  # used by shs1-c
)
