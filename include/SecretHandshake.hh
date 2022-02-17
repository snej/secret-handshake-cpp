//
// SecretHandshake.hh
//
// Copyright © 2021 Jens Alfke. All rights reserved.
//

#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace snej::shs {
    namespace impl { class handshake; }
    struct Session;


    /// This is an idiomatic C++ wrapper for the "shs1-c" implementation of the
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

    /// A secret value that can be extracted from an Ed25519 key-pair and reused to reconstitute it.
    /// (In the Monocypher API, this _is_ the secret key: Monocypher doesn't merge the public key
    /// with the secret key the way Sodium does.)
    using SigningKey = std::array<uint8_t, 32>;

    /// A 256-bit symmetrical session key.
    /// The Secret Handshake algorithm derives this key, but doesn't care what you do with it.
    /// Scuttlebutt uses it with Sodium's `crypto_box` API to encrypt message bodies.
    /// You could instead use it and the nonce with a stream cipher like XSalsa20; the Session
    /// class provides some utility methods for that.
    using SessionKey = std::array<uint8_t, 32>;

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

        AppID const     appID;      ///< Arbitrary 32-byte value identifying the app/protocol
        KeyPair const keyPair;    ///< Ed25519 key-pair for authentication

        /// Simple transformation of an ASCII string to an AppID.
        /// Up to 32 bytes of the string are copied to the AppID, and the rest is padded with 00.
        static AppID appIDFromString(const char *str);
    };


    /// Abstract base class of Secret Handshake protocol.
    /// Superclass of ClientHandshake and ServerHandshake.
    class Handshake {
    public:
        /// Returns the number of bytes the handshake wants to read, and a buffer to put them in.
        /// The returned size may be 0, if nothing needs to be read.
        std::pair<void*, size_t> bytesToRead();

        /// Call this after all bytes have been copied into the buffer returned by `bytesToRead`.
        /// @return  True if the data is valid, false if the handshake has failed.
        bool readCompleted();

        /// Alternative read API; use instead of `bytesToRead` and `readCompleted`.
        /// Call this when data is received from the peer.
        /// @param src  The received data.
        /// @param count  The number of bytes received.
        /// @return  The number of bytes consumed. -1 on error.
        ssize_t receivedBytes(const void *src, size_t count);

        /// Returns the current bytes to send, as a pointer and length.
        /// Call after constructor, and after calling `receivedBytes`.
        /// The length will be 0 if there is nothing to send.
        std::pair<const void*,size_t> bytesToSend();

        /// Call this after fully sending the bytes returned by bytesToSend().
        void sendCompleted();

        /// Alternative sending API; use instead of `bytesToSend` and `sendCompleted`.
        /// Pass it a buffer and the buffer's size, and it will return
        /// the number of bytes from the buffer that were sent.
        /// Call after constructor, and after calling `receivedBytes`.
        /// @param dst  The buffer to copy the bytes to.
        /// @param maxCount  The size of the buffer.
        /// @return  The number of bytes written to the buffer. -1 on error.
        ssize_t copyBytesToSend(void *dst, size_t maxCount);

        /// True if the handshake has failed. You should close the socket.
        bool failed()                  {return _step == Failed;}

        /// Becomes true when the handshake is complete.
        /// Call this after `receivedBytes` and `bytesToSend`.
        bool finished()                {return _step == Finished;}

        /// After the handshake is finished, this returns the results to use for communication.
        Session session();

    protected:
        enum Step {
            Failed = 0,
            ClientChallenge, // start here
            ServerChallenge,
            ClientAuth,
            ServerAck,
            Finished
        };

        explicit Handshake(Context const&);
        virtual ~Handshake();
        void nextStep();
        virtual size_t _byteCountNeeded() =0;                    // # bytes to read at this step
        virtual bool _receivedBytes(const uint8_t*) =0;          // process received bytes
        virtual void _fillOutputBuffer(std::vector<uint8_t>&) =0;// Resize & fill vector with output

        Context                 _context;                   // App ID and local key-pair
        Step                    _step = ClientChallenge;    // Current step in protocol, or Failed
        std::unique_ptr<impl::handshake> _impl;             // Crypto implementation object
    private:
        std::vector<uint8_t>    _inputBuffer;               // Unread bytes
        std::vector<uint8_t>    _outputBuffer;              // Unsent bytes
    };



    /// Client (active) side of Secret Handshake protocol.
    class ClientHandshake final : public Handshake {
    public:
        /// Constructs a Client for making a connection to a Server.
        /// @param context  The application ID and the client's key-pair.
        /// @param serverPublicKey  The server's identity. If this is incorrect the handshake fails.
        ClientHandshake(Context const& context,
                        PublicKey const& serverPublicKey);
    protected:
        size_t _byteCountNeeded() override;
        bool _receivedBytes(const uint8_t *bytes) override;
        void _fillOutputBuffer(std::vector<uint8_t>&) override;
    };



    /// Server (passive) side of Secret Handshake protocol.
    class ServerHandshake final : public Handshake {
    public:
        /// Constructs a Server for accepting a connection from a Client.
        /// @param context  The application ID and the server's key-pair.
        explicit ServerHandshake(Context const& context);

    protected:
        size_t _byteCountNeeded() override;
        bool _receivedBytes(const uint8_t *bytes) override;
        void _fillOutputBuffer(std::vector<uint8_t>&) override;
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
