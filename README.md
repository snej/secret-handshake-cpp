#  SecretHandshake Protocol Implementation In C++

This is a C++ implementation of the [SecretHandshake](https://github.com/auditdrivencrypto/secret-handshake) protocol. SecretHandshake upgrades your network connections with encryption and _mutual_ authentication, without all the overhead of using TLS.

There is also some glue code in the [capnproto](capnproto/README.md) subdirectory to use SecretHandshake with the awesome [Cap’n Proto](https://capnproto.org/) RPC library.

## About SecretHandshake

**SecretHandshake** is “a mutually authenticating key agreement handshake, with forward secure identity metadata.” It was designed by Dominic Tarr and is used in the [Secure Scuttlebutt](https://scuttlebutt.nz) P2P social network. There’s a [design paper](http://dominictarr.github.io/secret-handshake-paper/shs.pdf) that presents the algorithm in detail.

It’s based on 256-bit Ed25519 key-pairs. Each peer needs to maintain a long-term key pair, whose public key serves as its global identifier. The peer making the connection (the “client”) must know the public key of the other peer (“server”) to be able to connect. 

The handshake happens when the socket opens. The peers alternate sending and receiving four cryptographic blobs of about 100 bytes each. The server learns the client’s public key during the handshake, and each peer proves to the other that it knows its matching private key. 

The handshake also produces two 256-bit session keys and 192-bit nonces, known to both peers but otherwise secret, which are then used to encrypt the two TCP streams. (This is not strictly speaking part of the SecretHandshake protocol, which ends after key agreement.)

The API in `SecretStream.hh` provides stream encryption using those keys. It supports both Scuttlebutt's "box-stream" protocol based on XSalsa20, and a more compact custom protocol using XChaCha20.

## Implementation & Use

*None of the code here implements networking!* It expects you to open sockets and tell it the data you read, and it will tell you what to send.

- **SecretHandshake** tells you what “challenge” bytes to send, and then expects you to tell it what you got in response. Assuming the handshake succeeds, it gives you a `Session` object containing the keys.
  - **shs** is a lower-level class used by `SecretHandshake`, focusing on the crypto.
- **SecretStream** provides classes that use the keys in the `Session` object to encrypt/decrypt either discrete messages or continuous byte streams.

The crypto primitives themselves come from [Monocypher](https://monocypher.org), a small C crypto library, as wrapped by my own [MonocypherCpp](https://github.com/snej/monocypher-cpp) C++ API.

## Building

*Make sure to check out submodules. Recursively. Otherwise you will get mucho build errors.*

A simple CMake build file is supplied. Or you can use your own build system: just compile the files in `src` and `vendor/monocypher-cpp/src`, and add `include` and `vendor/monocypher/include` to the preprocessor's header path.

There are some unit tests in `SecretHandshakeTests.cc`. They use the [Catch2](https://github.com/catchorg/Catch2) unit test framework. Some of the tests use an existing C implementation of SecretHandshake for validation; that code in turn requires libSodium, so to run the tests you'll need to [install libSodium](https://libsodium.gitbook.io/doc/installation) and make sure it’s in the system header search path. But that's not necessary if you only want to build the library.

## Status

As of February 2022, this is pretty new and minimally tested. It does work, in an app I’m developing, but there are no unit tests.

It’s only been built with Clang 12 (Xcode 13.1), and only run on macOS 12.

I’ll update this notice as things get more solid.

## License

The code in this repo is provided under the MIT license.

Monocypher uses the 2-clause BSD license.

The code in the `shs-1` submodule is LGPL-licensed, but since it is only used in the tests (`shsTests.cc`) it has no effect on the licensing of the library itself.
