#! /bin/bash -e

mkdir -p build_cmake
cd build_cmake
cmake ..
make Tests
./Tests