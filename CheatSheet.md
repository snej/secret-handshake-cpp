 # Secret Handshake Cheat Sheet

This information comes from the [Secret Handshake paper](http://dominictarr.github.io/secret-handshake-paper/shs.pdf), p.11, but where the implementations differ (I mainly followed [the C one](https://github.com/sunrise-choir/shs1-c)) I've gone with them, because compatibility.

There's also a [visual tutorial](https://ssbc.github.io/scuttlebutt-protocol-guide/#handshake) in the Scuttlebutt Protocol Guide.

For the C++ code implementing this, look at `shs.cc` in this repo.

## Terminology:

"A" is Alice, the peer who's initiating the connection, usually called the "client"; 
"B" is Bob, the peer accepting the connection, usually called the "server".

| Name      | Description                          |
| --------- | ------------------------------------ |
| *K*       | application ID, 256-bit shared value |
| *(A, Ap)* | client's long-term Ed25519 key pair  |
| *(B, Bp)* | server's long-term Ed25519 key pair  |
| *(a, ap)* | client's ephemeral X25519 key pair   |
| *(b, bp)* | server's ephemeral X25519 key pair   |

## Functions:

| Name         | Description |
|--------------|--------------------------------------|
|*x \| y*      | concatenation |
|*x · y*       | Curve25519 scalar multiplication, i.e. _x · yp_, which is the same as _y · xp_ |
|*hmac\[k](d)* | HMAC-SHA-512-256 of data _d_ with key _k_ |
|*hash(d)*     | SHA-256 hash of _d_ |
|*sign\[k](d)* | Ed25519 digital signature of _d_ with key _k_ |
|*box\[k](d)*  | "Secret box" as in libSodium or RFC8439, i.e. *poly1305(d) \| xsalsa20\[k](d)*. |

> Note: HMAC-SHA-512-256 is just HMAC-SHA-512 with output truncated to 256 bits.

> Note: XSalsa20 is used here with an all-zeroes nonce, since each key is only used once.

## The Secret Handshake

### Preconditions:

- Client knows:  *K, A, Ap, Bp*
- Server knows:  *K, B, Bp*

### Protocol:

0. **ephemeral keys**
   - client generates *(a, ap)*, server generates *(b, bp)*
1. **client challenge**
   - client sends ⟹ *hmac\[K](ap) | ap*
2. **server challenge**
   - server verifies client challenge; learns _ap_
   - server sends ⟹ *hmac\[K](bp) | bp*
3. **client auth**
   - client verifies server challenge; learns _bp_
   - client sends ⟹ *box\[K | a·b | a·B](H)*
   - where *H = sign\[A](K | Bp | hash(a·b)) | Ap*
4. **server ack**
   - server decrypts client auth, verifies signature; learns _Ap_
   - server sends ⟹ *box\[K | a·b | a·B | A·b](sign\[B](K | H | hash(a·b)))*
5. **client validates ack**
   - client decrypts server ack, verifies signature

If any verification fails, that peer immediately terminates the connection.

### Postconditions:

- Client now knows: *b*p
- Server now knows: *ap, Ap*

### Afterwards:

Both compute the shared secret *SS = K | a·b | a·B | A·b*

Both derive the following keys & nonces:

- Client encryption key:  *hash(hash(hash(SS)) | Bp)*
- Client nonce:           *hmac\[K](bp)*   [only 1st 24 bytes needed]
- Server encryption key:  *hash(hash(hash(SS)) | Ap)*
- Server nonce:           *hmac\[K](ap)*   [only 1st 24 bytes needed]

They can now communicate using these. Any 256-bit symmetric cipher will work; the Scuttlebutt “box-stream” protocol uses the same secret-box as before, i.e. XSalsa20 prefixed with a Poly1305 MAC.

## Appendix: Compatibility Notes

There are several discrepancies between the the original protocol design published in the paper and the existing implementations. This documentation and code follow the implementations.

* Step 1: The paper has the client send _ap | hmac\[K](ap)_, i.e. public key first, not last.
* Step 2: The paper has the server send _bp | hmac\[K | a·b](bp)_.
  "I was reluctant to change it since it didn't have security implications, and also changing things was hard." —[Dominic Tarr](https://github.com/auditdrivencrypto/secret-handshake/issues/7)
* Step 3: The paper defines H as _Ap | sign\[A](K | Bp | hash(a·b))_, i.e. putting the public key before the signature, not after it.
