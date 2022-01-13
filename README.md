#  SecretHandshake For Cap’n Proto

C++ adapter for using the [SecretHandshake](https://github.com/auditdrivencrypto/secret-handshake) protocol with the awesome [Cap’n Proto](https://capnproto.org/) RPC library.  
SecretHandshake upgrades your network connections with encryption and _mutual_ authentication, without all the overhead of OpenSSL.

(You don’t actually need Cap’n Proto to use this, but you’d need to provide your own networking code.)

>**NOTE:** The initial stream-encryption code was badly broken and has been ripped out. (See #1) The remaining code isn't useable for Cap'n Proto, but can still be used just for the SecretHandshake portion. I will update with actually-working, actually-secure encryption ASAP.

## About SecretHandshake

**SecretHandshake** is “a mutually authenticating key agreement handshake, with forward secure identity metadata.” It was designed by Dominic Tarr and is used in the [Secure Scuttlebutt](https://scuttlebutt.nz) P2P social network.

It’s based on 256-bit Ed25519 key-pairs. Each peer needs to maintain a long-term key pair, whose public key serves as its global identifier. The peer making the connection (the “client”) must know the public key of the other peer (“server”) to be able to connect. The server learns the client’s public key during the handshake. Each peer proves to the other that it knows its matching private key. Much more detail is available in the [design paper](http://dominictarr.github.io/secret-handshake-paper/shs.pdf).

The handshake also produces two 256-bit session keys, known to both peers but otherwise secret, which are then used to encrypt the TCP streams via the symmetric XSalsa20 cipher. (This is not strictly speaking part of the SecretHandshake protocol, which ends after key agreement. Scuttlebutt uses the same cipher but with a different message-oriented protocol based on libSodium’s “secret box”.)

## Implementation & Use

This library is built atop the existing [shs1-c](https://github.com/sunrise-choir/shs1-c) library, a plain C implementation of Secret-Handshake, which in turn uses crypto functions from the ubiquitous [libSodium](https://github.com/jedisct1/libsodium).

My C++ API here has three layers. From top to bottom:

- **SecretRPC** provides high-level RPC client and server classes that mimic Cap’n Proto’s `EzRpcClient`/`Server` classes, but use SecretConnection.
- **SecretConnection** exposes a `StreamWrapper` class that takes a Cap’n Proto `AsyncIoStream` and returns a new `AsyncIoStream` that internally performs the SecretHandshake and encryption.
- **SecretHandshake** itself is purely computational; it just tells you what “challenge” bytes to send, and then expects you to tell it what you got in response. It's just a friendlier, idiomatic C++ API on [shs1-c](https://github.com/sunrise-choir/shs1-c). 

If you currently use Cap'n Proto `EzRpc` you should be able to drop in `SecretRPC` pretty easily. You’ll just need to use the `SecretKey` class to generate a key-pair, and persist it somehow. (Hint: put the secret key someplace secure, like the Mac/iOS Keychain.)

If you use lower-level Cap’n Proto classes to create connections, you’ll need to use the classes in SecretConnection to wrap your plain-TCP `AsyncIOStream` with the secure one. You can look at the code in `SecretRPC.cc` for clues.

Even if you don’t use Cap’n Proto at all, you can use the classes in SecretHandshake to implement the handshake yourself on top of whatever network streams you’re using.

## Building

There isn’t a makefile. ¯\\_(ツ)_/¯ Just compile the three top-level .cc files (C++17 or later), and also `vendor/shs1-c/shs1.c` (C99). Add `vendor/shs1-c/` to the header search path. You’ll also need to install libSodium and make sure it’s in the system header search path.

If someone wants to write a CMake build file, I’ll gratefully accept it.

## Status

As of January 2021, this is pretty new and minimally tested. It does work, in an app I’m developing, but there are no unit tests.

It’s only been built with Clang 12 (Xcode 13.1), and only run on macOS 12.

I’ll update this notice as things get more solid.

In the long run I would like to replace shs1.c with equivalent code based on Monocypher. That's because I already use Monocypher in the rest of my code (it's considerably smaller than libSodium), and because I don't want the clumsiness of having to quarantine shs1.c in a shared library to avoid LGPL encumberment.

## License

The code in this repo is provided under the MIT license (like Cap’n Proto.)

The shs-1 submodule is LGPL-licensed. _(🚨 This has licensing implications for any code you statically link it with. If you don’t want that, be sure to build it as a shared library and dynamically link it.)_

lib`Sodium` uses the ISC license.
