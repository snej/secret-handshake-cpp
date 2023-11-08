#  SecretHandshake Protocol Implementation In C++

This is a C++ implementation of the [SecretHandshake](https://github.com/auditdrivencrypto/secret-handshake) protocol. SecretHandshake upgrades your network connections with encryption and _mutual_ authentication, without all the overhead of using TLS.

An (incomplete) C API is provided, for the use of clients written in C and for binding to other languages.

There is also some glue code to use SecretHandshake with the [capnproto](capnproto/README.md) and [Crouton](crouton/README.md) networking libraries.

## 1. About SecretHandshake

**SecretHandshake** is “a mutually authenticating key agreement handshake, with forward secure identity metadata.” It was designed by Dominic Tarr and is used in the [Secure Scuttlebutt](https://scuttlebutt.nz) P2P social network. There’s a [design paper](http://dominictarr.github.io/secret-handshake-paper/shs.pdf) that presents the algorithm in detail.

It’s based on 256-bit Ed25519 key-pairs. Each peer needs to maintain a long-term key pair, whose public key serves as its global identifier. The peer making the connection (the “client”) must know the public key of the other peer (“server”) to be able to connect. 

The handshake happens when the socket opens. The peers alternate sending and receiving four cryptographic blobs of about 100 bytes each. The server learns the client’s public key during the handshake, and each peer proves to the other that it knows its matching private key. 

The handshake also produces two 256-bit session keys and 192-bit nonces, known to both peers but otherwise secret, which are then used to encrypt the two TCP streams. (This is not strictly speaking part of the SecretHandshake protocol, which ends after key agreement.)

The API in `SecretStream.hh` provides stream encryption using those keys. It supports both Scuttlebutt's "box-stream" protocol based on XSalsa20, and a more compact custom protocol using XChaCha20.

The crypto primitives themselves come from [Monocypher](https://monocypher.org), a small C crypto library, as wrapped by my own [MonocypherCpp](https://github.com/snej/monocypher-cpp) C++ API.

## 3. Building The Library

*Make sure to check out submodules. Recursively. Otherwise you will get mucho build errors.*

A simple CMake build file is supplied. Or you can use your own build system: just compile the files in `src` and `vendor/monocypher-cpp/src`, and add `include` and `vendor/monocypher/include` to the preprocessor's header path.

There are some unit tests in `SecretHandshakeTests.cc`. They use the [Catch2](https://github.com/catchorg/Catch2) unit test framework. Some of the tests use an existing C implementation of SecretHandshake for validation; that code in turn requires libSodium, so to run the tests you'll need to [install libSodium](https://libsodium.gitbook.io/doc/installation) and make sure it’s in the system header search path. But that's not necessary if you only want to build the library.

## 4. Using SecretHandshake

*None of the code here implements networking!* It expects you to open sockets, and tell it the data you read; it will tell you what to send, and whether the handshake succeeded or failed.

### Ahead of time

Come up with an “AppID”, an arbitrary 32-byte value specific to your own application protocol, which will be known to both clients and servers. It’s most convenient to treat this as a zero-padded string, like “MyGame v1”. `Context::appIDFromString()` will convert a C string to a binary AppID struct. 

Usually the AppID is hardcoded into both the server and the client.

The purpose of the AppID is to prevent accidentally connecting to a different application that also happens to use SecretHandshake but runs an incompatible protocol after the handshake.

### Steps to run a server/listener

1. The first time the server starts up, call `KeyPair::generate()` to create a key-pair for it. Save the private signing key in a secure place, like the Keychain on mac/iOS. 
2. Log or otherwise display the public key: clients will need to know it in order to connect. You may want to construct a URL containing the key in base64 encoding.
3. Listen for TCP connections.
4. After accepting a TCP connection, create a `ServerHandshake` instance for the connection. 
5. Proceed to “**The handshake**”, below.

### Steps to run a client

1. The first time the client launches, call `KeyPair::generate()` to create a key-pair for the user. Save the private signing key in a secure place, like the Keychain on mac/iOS.
2. Open a TCP connection to the server’s address & port.
3. Create a `ClientHandshake` instance for the connection. You’ll need to know the *server’s* public key.
4. Proceed to “**The handshake**”, below…

### The handshake

1. Call `handshake.bytesToSend()`. If it returns a non-zero byte count then:
   1.  send those bytes over the socket.
   2. Call `handshake.sendCompleted()`. 
2. Else:
   1. Call handshake.bytesToReceive(), which returns a byte count and a buffer pointer.
   2. Wait to receive that many bytes, and copy them into the buffer. (Or if the peer drops the connection, the handshake of course fails.)
   3. Call `handshake.readCompleted()`.
3. If `handshake.failed()` is true, exit the loop and close the socket.
4. If `handshake.finished()` is false, start the loop over again…

The actual traffic you’ll see during a successful handshake is:

* Client sends 64 bytes
* Server reads those, then sends 64 bytes
* Client reads those, then sends 112 bytes
* Server reads those, then sends 80 bytes; then the server’s handshake is finished.
* Client reads those, then its handshake is finished.

### After a successful handshake

1. Call `handshake.session()`. The returned `Session` struct contains the symmetric session keys and nonces. 
   - If you’re the server, the Session also contains the client’s authenticated public key, which you can use as a persistent identifier instead of requiring a login. If your server only allows registered users to connect, you should close the socket now if the key isn’t known.
2. You can now use `CryptoBox` or `CryptoStream` to send and receive encrypted data over the socket; consult the documentation comments in SecretStream.hh for details. Or you can use whatever other symmetric encryption you want: the keys and nonces in the Session are just random secrets known to both client and server.

### After a failed handshake

Just close the socket. If you’re the client, report that the connection failed. 

There are many reasons a client connection can fail:

- The server you connected to doesn’t actually use SecretHandshake
- The server’s appID doesn’t match yours, i.e. it’s for a different application
- The server’s public key isn’t the one you expected
- The server wasn’t able to send a valid signature proving it owns the matching private key
- The server only allows known users to connect, and it didn’t recognize your public key
- The server sent invalid data, maybe because of a man-in-the-middle attack, maybe just a rare network glitch

The library doesn’t currently let you distinguish between these, so all you can do is tell the user that the connection failed.

## 5. Status

I’ve been using this code since February 2022. It works correctly in an app I’m developing, and has basic unit tests, including a test that the network data it sends is identical to that of an established SecretHandshake implementation. But it has not been used in released software, and hasn’t gone through an audit.

It builds with Clang 12+ and recent GCC, and is run & tested on macOS and Ubuntu by Github CI.

## 6. License

The code in this repo is provided under the MIT license.

Monocypher uses the 2-clause BSD license.

(The code in the `shs-1` submodule is LGPL-licensed, but since it is only used in the tests (`shsTests.cc`) it has no effect on the licensing of the library itself.)
