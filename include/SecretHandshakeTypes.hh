//
// SecretHandshakeTypes.hh
//
// Copyright © 2021 Jens Alfke. All rights reserved.
//

#pragma once
#include <array>
#include <cstdint>

namespace snej::shs {

    /// This is an idiomatic C++ wrapper implementation of the
    /// ["Secret Handshake"](https://github.com/auditdrivencrypto/secret-handshake) protocol.
    /// This allows a client and server, each with a longterm key-pair, to form a secure
    /// authenticated connection, with a session key for encrypting subsequent traffic.
    /// To connect, the client must already know the server's public key.


    /// An arbitrary 32-byte value identifying your higher-level application protocol.
    /// Client and server must both use the same AppID to connect.
    /// The AppID is usually not secret, unless you want to add a layer of "secrecy through
    /// obscurity" to your protocol.
    using AppID = std::array<uint8_t, 32>;

    /// A 256-bit Ed25519 public key.
    /// Data layout is the same as the public key in Sodium's `crypto_sign_` API
    /// and Monocypher's `crypto_ed25519_` API.
    using PublicKey = std::array<uint8_t, 32>;

    /// A secret "seed" value that can be extracted from an Ed25519 key-pair and reused to
    /// reconstitute it.
    using SigningKey = std::array<uint8_t, 32>;

    /// A 256-bit symmetrical session key.
    /// The Secret Handshake algorithm derives this key, but doesn't care what you do with it.
    /// Scuttlebutt uses it with Sodium's `crypto_box` API to encrypt message bodies.
    /// You could instead use it and the nonce with a stream cipher like XSalsa20; the Session
    /// class provides some utility methods for that.
    using SessionKey = std::array<uint8_t, 32>;

    using KeyPairBytes = std::array<uint8_t, 64>;

    /// A 192-bit nonce for use with a `SessionKey`.
    using Nonce = std::array<uint8_t, 24>;


    /// An Ed25519 key-pair, used for authentication.
    /// Data layout is the same as the "secret key" in Sodium's `crypto_sign_` API.
    struct KeyPair {
        SigningKey signingKey;
        PublicKey  publicKey;

        /// Generates a new key-pair (using Monocypher.)
        static KeyPair generate();

        /// Reconstitutes a key-pair from its private key alone.
        explicit KeyPair(SigningKey const&);

        explicit KeyPair(KeyPairBytes const& bytes) {
            ::memcpy(&signingKey, &bytes, sizeof(bytes));
        }

        KeyPairBytes data() const {
            return *reinterpret_cast<KeyPairBytes const*>(&signingKey);
        }

        ~KeyPair();
    private:
        KeyPair() = default;
    };

    static inline bool operator==(KeyPair const& kp1, KeyPair const& kp2) {
        return kp1.signingKey == kp2.signingKey && kp1.publicKey == kp2.publicKey;
    }



    /// The local state needed to start a handshake: AppID and key-pair.
    struct Context {
        Context(AppID const& a,  KeyPair const& sk)  :appID(a), keyPair(sk) { }
        Context(char const* str, KeyPair const& sk)  :appID(appIDFromString(str)), keyPair(sk) { }

        AppID const   appID;      ///< Arbitrary 32-byte value identifying the app/protocol
        KeyPair const keyPair;    ///< Ed25519 key-pair for authentication

        /// Simple transformation of an ASCII string to an AppID.
        /// Up to 32 bytes of the string are copied to the AppID, and the rest is padded with 00.
        static AppID appIDFromString(const char *str);
    };



    /// Result of the secret handshake:
    /// * session encryption / decryption keys with nonces,
    /// * and the peer's long-term public key (which is news to the server, but not to the client.)
    struct Session {
        SessionKey  encryptionKey;          ///< The session encryption key
        Nonce       encryptionNonce;        ///< Nonce to use with the encryption key
        SessionKey  decryptionKey;          ///< The session decryption key
        Nonce       decryptionNonce;        ///< Nonce to use with the decryption key

        PublicKey   peerPublicKey;          ///< The peer's authenticated public key

        ~Session();
    };

}
