#  SecretHandshake For Crouton

These source files let you use the SecretHandshake protocol ([see parent directory](../README.md))
with the awesome [Crouton](https://github.com/couchbaselabs/crouton) coroutine & I/O library.

* The `SecretHandshake` class simply runs the handshake over a Crouton `IStream`.
* `SecretHandshakeStream` is an `IStream` subclass that wraps another stream, typically from a 
  `TCPSocket`, and transparently runs the handshake and then encrypts/decrypts traffic.

They're both pretty easy to use. See [shsCroutonTests.cc](../tests/shsCroutonTests.cc) for an example.
