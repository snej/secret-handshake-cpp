//
// shs.cc
//
// Copyright © 2022 Jens Alfke. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "shs.hh"


/*
 HERE IS THE MATH:

 From <http://dominictarr.github.io/secret-handshake-paper/shs.pdf>, p.11
 (there's also a tutorial at <https://ssbc.github.io/scuttlebutt-protocol-guide/#handshake>)

 # Terminology:
    "A" means "client" and "B" means "server".
    K       : the application ID (a 256-bit constant known to both, probably hardcoded)
    (A, Ap) : client's long-term Ed25519 key pair
    (B, Bp) : server's long-term Ed25519 key pair
    (a, ap) : client's ephemeral X25519 key pair
    (b, bp) : server's ephemeral X25519 key pair

 # Functions:
    x | y       : string concatenation
    x · y       : Curve25519 scalar multiplication (shared secret derivation) of my _private_ key x
                  and peer's _public_ key y, i.e. x·yp, which is the same as y·xp
    hmac[k](d)  : HMAC-SHA-512-256 of data `d` with key `k`
                  (this is HMAC-SHA-512 with output truncated to 256 bits)
    hash(d)     : SHA256 hash of `d`
    sign[k](d)  : Ed25519 digital signature of `d` with key `k`
    box[k](d)   : "Secret box" as in libSodium or RFC8439, i.e. poly1305(d) | xchacha20[k](d).
                  An all-zeroes nonce is used, as each key is only used once.

 # Before:
    Client knows:  K, A, Ap, Bp
    Server knows:  K, B, Bp

 # Protocol:
    0. (client generates key-pair a/ap, server generates b/bp)
    1. client challenge :  hmac[K](ap) | ap
    2. server challenge :  hmac[K](bp) | bp
    3. client auth      :  box[K | a·b | a·B](H)   ... where H = sign[A](K | Bp | hash(a·b)) | Ap
    4. server ack       :  box[K | a·b | a·B | A·b](sign[B](K | H | hash(a·b)))

 # Afterwards:
    Server now knows:       Ap  ... the client's identity
    Both now know:          SS = K | a·b | a·B | A·b   ...the shared secret

    Now they can communicate using the following keys/nonces:
    Client encryption key:  hash(hash(hash(SS)) | Bp)
    Client nonce:           hmac[K](bp)   [only 1st 24 bytes needed]
    Server encryption key:  hash(hash(hash(SS)) | Ap)
    Server nonce:           hmac[K](ap)   [only 1st 24 bytes needed]

 # Compatibility Notes
    There are several discrepancies between the the original protocol design published in the paper
    and the existing implementations. This documentation and code follow the implementations,
    for compatibility purposes.
    * Step 1: The paper has the client send `ap | hmac[K](ap)`, i.e. public key first, not last.
    * Step 2: The paper has the server send `bp | hmac[K | a·b](bp)`;
      see <https://github.com/auditdrivencrypto/secret-handshake/issues/7>.
      Dominic Tarr: "I was reluctant to change it since it didn't have security implications,
      and also changing things was hard."
    * Step 3: The paper defines H as `Ap | sign[A](K | Bp | hash(a·b))`, i.e. putting the
      public key before the signature, not after it.
 */


namespace snej::shs::impl {
    using namespace std;

    using input_bytes = monocypher::input_bytes;
    using key_exchange = handshake::key_exchange;
    using kx_shared_secret = handshake::kx_shared_secret;
    using kx_public_key = handshake::kx_public_key;


    // Algorithms, named as in the mathematical description:

    static monocypher::ext::sha256 hash(input_bytes in) {
        return monocypher::ext::sha256::create(in);
    }

    struct sha512256 : public byte_array<32> { };

    static inline sha512256 hmac(byte_array<32> const& key, input_bytes in) {
        // HMAC-SHA-512-256 is just the first 256 bits of HMAC-SHA-512.
        auto h = monocypher::hash<monocypher::SHA512>::createMAC(in, key);
        return reinterpret_cast<sha512256&>(h.range<0, 32>());
    }

    static inline nonce hashToNonce(sha512256 const& h) {
        return h.range<0, sizeof(nonce)>();
    }

    static inline box_key makeBoxKey(input_bytes keyMaterial) {
        return box_key(hash(keyMaterial));
    }

    template <size_t InputSize>
    byte_array<InputSize+16> box(box_key const& key, byte_array<InputSize> const& plaintext) {
        return key.box<InputSize+16>(monocypher::session::nonce(0), plaintext);
    }

    template <size_t InputSize>
    optional<byte_array<InputSize-16>> unbox(box_key const& key,
                                             byte_array<InputSize> const& ciphertext) {
        byte_array<InputSize-16> output;
        if (!key.unbox(monocypher::session::nonce(0), ciphertext, output))
            return nullopt;
        return output;
    }


    // Overload `*` for Curve25519 scalar multiplication with Ed25519 keys:
    static inline kx_shared_secret operator* (signing_key const& k, kx_public_key const& pk) {
        return key_exchange(k) * pk;
    }

    static inline kx_shared_secret operator* (key_exchange const& k, public_key const& pk) {
        return k * kx_public_key(pk);
    }


#pragma mark - COMMON CODE:


    handshake::handshake(app_id const& appID,
                         signing_key const& signingKey,
                         public_key const& publicKey)
    :_K(appID)
    ,_X(signingKey)
    ,_Xp(publicKey)
    ,_xp(_x.get_public_key())
    { }


    void handshake::setEphemeralKeys(signing_key const& sk, public_key const& pk) {
        _x = key_exchange((kx_secret_key&)sk);
        _xp = _x.get_public_key();
        assert(_xp == pk);
    }


    // hmac[K](xp) | xp
    ChallengeData handshake::createChallenge() {
        return hmac(_K, _xp) | _xp;
    }


    // hmac[K](yp) | yp
    bool handshake::verifyChallenge(ChallengeData const& challenge) {
        // Unpack hmac[K](yp) and yp:
        auto &challengeHmac   = challenge.range<0,                 sizeof(sha512256)>();
        auto &challengePubKey = challenge.range<sizeof(sha512256), sizeof(kx_public_key)>();
        // Verify hmac:
        if (challengeHmac != hmac(_K, challengePubKey))
            return false;
        // Now we know yp, the peer's ephemeral public key:
        _yp = kx_public_key(challengePubKey);
        _ab = _x * *_yp;
        _hashab = hash(*_ab);
        return true;
    }


    void handshake::getOutcome(session_key & encryptionKey,
                               nonce       & encryptionNonce,
                               session_key & decryptionKey,
                               nonce       & decryptionNonce,
                               public_key  & peerPublicKey)
    {
        auto boxKeyHash = hash(_serverAckKey.value());
        // hash(hash(hash(K | a_s * b_p | a_s * B_p | A_s * b_p)) | Y_p):
        encryptionKey = session_key(hash(boxKeyHash | _Yp.value()));
        // hmac_{K}(b_p):
        encryptionNonce = hashToNonce(hmac(_K, _yp.value()));
        // hash(hash(hash(K | a_s * b_p | a_s * B_p | A_s * b_p)) | X_p):
        decryptionKey = session_key(hash(boxKeyHash | _Xp));
        // hmac_{K}(x_p):
        decryptionNonce = hashToNonce(hmac(_K, _xp));
        peerPublicKey = _Yp.value();
    }


    box_key handshake::clientAuthKey() { // [K | a·b | a·B]
        return makeBoxKey(_K | *_ab | *_aB);
    }


    box_key handshake::serverAckKey() { // [K | a·b | a·B | A·b]
        _serverAckKey = makeBoxKey(_K | _ab.value() | _aB.value() | _Ab.value());
        return *_serverAckKey;
    }



#pragma mark - CLIENT:


#define WITH_CLIENT_VARS \
    __unused auto &A  = _X;\
    __unused auto &Ap = _Xp;\
    __unused auto &Bp = _Yp.value();\
    __unused auto &a  = _x;\
    __unused auto &ap = _xp;\
    __unused auto &bp = _yp.value();


    void handshake::setServerPublicKey(const public_key &pk) {
        _Yp = pk;
    }


    // box[K | a·b | a·B](H)
    ClientAuthData handshake::createClientAuth() {
        WITH_CLIENT_VARS
        // Compute H = sign[A](K | Bp | hash(a·b)) | Ap
        _H = A.sign(_K | Bp | _hashab.value(), Ap) | Ap;
        // Return box[K | a·b | a·B](H)
        _Ab = A * bp;
        _aB = a * Bp;
        auto key = clientAuthKey();
        return box(key, *_H);
    }


    // ack = box[K | a·b | a·B | A·b](sign[B](K | H | hash(a·b)))
    bool handshake::verifyServerAck(ServerAckData const& ack) {
        WITH_CLIENT_VARS
        // Unbox, producing the signature.
        // Then verify it's the true signature of K | H | hash(a·b).
        if (auto sig = unbox(serverAckKey(), ack))
            return Bp.check((signature&)*sig, (_K | _H.value() | _hashab.value()));
        else
            return false;
    }


#pragma mark - SERVER:


#define WITH_SERVER_VARS \
        __unused auto &B  = _X;\
        __unused auto &Bp = _Xp;\
        __unused auto &Ap = _Yp;\
        __unused auto &b  = _x;\
        __unused auto &bp = _xp;\
        __unused auto &ap = _yp.value();\


    // auth = box[K | a·b | a·B](H)   ... where H = sign[A](K | Bp | hash(a·b)) | Ap
    bool handshake::verifyClientAuth(ClientAuthData const& auth) {
        WITH_SERVER_VARS
        _aB = B * ap;           // because a·Bp == ap·B == B·ap
        _H = unbox(clientAuthKey(), auth);
        if (!_H)
            return false;

        // Split H into `Ap` and `sign[A](K | Bp | hash(a·b))`
        auto &sig = (signature&)_H->range<0,sizeof(signature)>();
        Ap = public_key(_H->range<sizeof(signature), sizeof(public_key)>());
        _Ab = b * *Ap;           // because A·bp == Ap·b == b·Ap
        // Verify the signature:
        return Ap->check(sig, _K | Bp | _hashab.value());
    }


    // box[K | a·b | a·B | A·b](sign[B](K | H | hash(a·b)))
    ServerAckData handshake::createServerAck() {
        WITH_SERVER_VARS
        return box(serverAckKey(), B.sign(_K | _H.value() | _hashab.value(), Bp));
    }

}
