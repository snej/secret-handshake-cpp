cmake_minimum_required(VERSION 3.16)

project(SecretHandshakeCpp)

add_subdirectory(vendor/monocypher-cpp)

set(CMAKE_CXX_STANDARD 17)


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
        /usr/local/include
        /opt/homebrew/include
    )
    link_directories(
        /usr/local/lib
        /opt/homebrew/lib
    )
endif()

add_executable( SecretHandshakeTests
    vendor/monocypher-cpp/tests/tests_main.cc
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
