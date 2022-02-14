//
// shs.cc
//
// Copyright © 2022 Jens Alfke. All rights reserved.
//
// Licensed under the MIT License:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#include "shs.hh"


/* Follow along with CheatSheet.md! The variable names here follow the same terminology. */


#define _UNUSED
#ifdef __has_attribute
#  if __has_attribute(unused)
#    undef _UNUSED
#    define _UNUSED __attribute__((unused))
#  endif
#endif


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
        // (HMAC-SHA-512-256 is just the first 256 bits of HMAC-SHA-512.)
        auto h = monocypher::hash<monocypher::SHA512>::createMAC(in, key);
        return reinterpret_cast<sha512256&>(h.range<0, 32>());
    }

    static inline nonce hashToNonce(sha512256 const& h) {
        return h.range<0, sizeof(nonce)>();
    }

    static inline box_key makeBoxKey(input_bytes keyMaterial) {
        // The algorithm generates crypto-box keys by running the key material through SHA-256.
        return box_key(hash(keyMaterial));
    }

    template <size_t InputSize>
    byte_array<InputSize+16> box(box_key const& key, byte_array<InputSize> const& plaintext) {
        // This hardcodes an all-zeroes nonce, which is only safe because the protocol uses each
        // key only once!
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
    _UNUSED auto &A  = _X;\
    _UNUSED auto &Ap = _Xp;\
    _UNUSED auto &Bp = _Yp.value();\
    _UNUSED auto &a  = _x;\
    _UNUSED auto &ap = _xp;\
    _UNUSED auto &bp = _yp.value();


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
        _UNUSED auto &B  = _X;\
        _UNUSED auto &Bp = _Xp;\
        _UNUSED auto &Ap = _Yp;\
        _UNUSED auto &b  = _x;\
        _UNUSED auto &bp = _xp;\
        _UNUSED auto &ap = _yp.value();\


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
