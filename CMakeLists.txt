cmake_minimum_required(VERSION 3.16)

project(SecretHandshakeCapnP)


set(CMAKE_CXX_STANDARD 17)

if(APPLE)
    include_directories(SYSTEM PUBLIC
        /opt/homebrew/include
    )
    link_directories(PRIVATE
        /opt/homebrew/lib   # ditto
    )
endif()


add_library( SecretHandshakeCpp STATIC
    SecretHandshake.cc
    SecretStream.cc
    vendor/shs1-c/src/shs1.c
)

target_include_directories( SecretHandshakeCpp PRIVATE
    vendor/shs1-c/src/
)


add_executable( Tests
    SecretHandshakeTests.cc
)
target_compile_definitions( Tests PRIVATE
    CATCH_CONFIG_MAIN
)
target_include_directories( Tests PRIVATE
    vendor/catch2
)

target_link_libraries( Tests PRIVATE
    SecretHandshakeCpp
    sodium
)

install(TARGETS Tests)

enable_testing()

add_test(
    NAME tests
    COMMAND Tests
)
