#  SecretHandshake For Cap’n Proto

C++ implementation of the [SecretHandshake](https://github.com/auditdrivencrypto/secret-handshake) protocol for the awesome [Cap’n Proto](https://capnproto.org/) RPC library. This lets you upgrade your network connections with encryption and mutual authentication, without all the overhead of OpenSSL.

(You don’t actually need Cap’n Proto to use this, but if so you’ll need to provide your own networking code.)

## About SecretHandshake

**SecretHandshake** is “a mutually authenticating key agreement handshake, with forward secure identity metadata.” It was designed by Dominic Tarr and is used in the Secure Scuttlebutt P2P social network.

It’s based on 256-bit elliptic Ed25519 key-pairs. The peers each maintain a long-term key pair, whose public key serves as a global identifier. The peer making the connection (“client”) must know the public key of the other peer (“server”) to be able to connect, and the server learns the client’s public key during the handshake. Each peer receives proof that the other has the matching private key. Much more detail is available in the [design paper](http://dominictarr.github.io/secret-handshake-paper/shs.pdf).

The handshake also produces two session keys, which are then used to encrypt the channel with the 256-bit symmetric XSalsa20 cipher. (This is not strictly speaking part of the SecretHandshake protocol, which ends after key agreement. Scuttlebutt uses a different encryption scheme based on libSodium’s “secret box”.)

## Implementation & Use

There are three layers here:

- **SecretHandshake** itself. Purely computational; it just tells you what “challenge” bytes to send and then verifies the response bytes. The actual algorithm is implemented by the [shs1-c](https://github.com/AljoschaMeyer/shs1-c) submodule, which itself uses [Sodium](https://libsodium.gitbook.io/doc/)’s crypto primitives.
- **SecretConnection** exposes a `StreamWrapper` class that takes a Cap’n Proto `AsyncIoStream` and returns a new `AsyncIoStream` that internally performs the SecretHandshake and encryption.
- **SecretRPC** exposes client and server classes that mimic Cap’n Proto’s `EzRpcClient`/`Server` classes but use SecretConnection.

If you currently use EzRpc you should be able to drop in SecretRPC pretty easily. You’ll just need to use the `SecretKey` class to generate a key-pair, and persist it somehow.

If you use lower-level Cap’n Proto classes to create connections, you’ll need to use the classes in SecretConnection to wrap your plain-TCP `AsyncIOStream` with the secure one. You can look at the code in `SecretRPC.cc` for clues.

Even if you don’t use Cap’n Proto at all, you can use the classes in SecretHandshake to implement the handshake yourself on top of whatever network streams you’re using.

## Building

There isn’t a makefile. Just compile the three .cc files with a C++ compiler set to C++17 or later. Add vendor/shs1-c to the header search path. You’ll also need to install Sodium and make sure it’s in the system header search path.

If someone wants to write a CMake build file, I’ll gratefully accept it.

## Status

As of December 2021, this is brand new and minimally tested. It does work, in an app I’m developing, but there are no unit tests.

It’s only been built with Clang 12 (Xcode 13.1), and only run on macOS 12.

I’ll update this notice as things get more solid.

## License

The code in this repo is provided under the MIT license (like Cap’n Proto.)

The shs-1 submodule is LGPL-licensed. (This has licensing implications for any code you statically link it with; if you don’t want that, be sure to build it as a shared library and dynamically link it.)

Sodium uses the ISC license.
