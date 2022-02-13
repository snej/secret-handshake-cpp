#! /bin/bash -e

mkdir -p build_cmake
cd build_cmake
cmake ..
make -j 8 SecretHandshakeTests
./SecretHandshakeTests
