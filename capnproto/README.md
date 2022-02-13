#  SecretHandshake For Cap’n Proto

These source files let you use the SecretHandshake protocol ([see parent directory](../README.md)) with the awesome [Cap’n Proto](https://capnproto.org/) RPC library.

**SecretRPC** provides high-level RPC client and server classes that mimic Cap’n Proto’s `EzRpcClient`/`Server` classes, but use `SecretConnection` (q.v.)

If you currently use Cap'n Proto `EzRpc` you should be able to drop in `SecretRPC` pretty easily. You’ll just need to use the `SecretKey` class to generate a key-pair, and persist it somehow. (Hint: put the secret key someplace secure, like the Mac/iOS Keychain.)

**SecretConnection** is lower-level: it exposes a `StreamWrapper` class that takes a Cap’n Proto `AsyncIoStream` and returns a new `AsyncIoStream` that internally performs the SecretHandshake and the `SecretStream` encryption.

If you use lower-level Cap’n Proto classes to create connections, you’ll need to use the classes in SecretConnection to wrap your plain-TCP `AsyncIOStream` with the secure one. You can look at the code in `SecretRPC.cc` for clues.