#! /bin/bash -e

mkdir -p build_cmake
cd build_cmake
cmake ..
cmake --build .

echo "Running tests..."

if [ -e Debug/SecretHandshakeTests.exe ]
then
    Debug/SecretHandshakeTests.exe -r list "$@"
else
    ./SecretHandshakeTests -r list "$@"
fi
