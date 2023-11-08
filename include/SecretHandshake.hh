//
// SecretHandshake.hh
//
// Copyright © 2021 Jens Alfke. All rights reserved.
//

#pragma once
#include "SecretHandshakeTypes.hh"
#include <cstring>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace snej::shs {
    namespace impl { class handshake; }


    /// This is an idiomatic C++ wrapper implementation of the
    /// ["Secret Handshake"](https://github.com/auditdrivencrypto/secret-handshake) protocol.
    /// This allows a client and server, each with a longterm key-pair, to form a secure
    /// authenticated connection, with a session key for encrypting subsequent traffic.
    /// To connect, the client must already know the server's public key.


    /// Abstract base class of Secret Handshake protocol.
    /// Superclass of ClientHandshake and ServerHandshake.
    class Handshake {
    public:
        /// Returns the number of bytes the handshake wants to read.
        virtual size_t byteCountNeeded() =0;

        /// Returns the number of bytes the handshake wants to read, and a buffer to put them in.
        /// The returned size may be 0, if nothing needs to be read.
        std::pair<void*, size_t> bytesToRead();

        /// Call this after all bytes have been copied into the buffer returned by `bytesToRead`.
        /// @return  True if the data is valid, false if the handshake has failed.
        bool readCompleted();

        /// Call this if the input stream was closed by the peer before requested bytes could be
        /// read. At this point the handshake has of course failed; calling this method will set
        /// the `error` property appropriately.
        void readFailed();

        /// Alternative read API; use instead of `bytesToRead` and `readCompleted`.
        /// Call this when data is received from the peer.
        /// @param src  The received data.
        /// @param count  The number of bytes received.
        /// @return  The number of bytes consumed. -1 on error.
        intptr_t receivedBytes(const void *src, size_t count);

        /// Returns the current bytes to send, as a pointer and length.
        /// Call after constructor, and after calling `receivedBytes`.
        /// The length will be 0 if there is nothing to send.
        std::pair<const void*,size_t> bytesToSend();

        /// Call this after fully sending the bytes returned by bytesToSend().
        void sendCompleted();

        /// Alternative sending API; use instead of `bytesToSend` and `sendCompleted`.
        /// Pass it a buffer and the buffer's size. It will copy any output to the buffer, and return the
        /// number of bytes to send.
        /// @param dst  The buffer to copy the bytes to.
        /// @param maxCount  The size of the buffer.
        /// @return  The number of bytes written to the buffer. -1 on error.
        intptr_t copyBytesToSend(void *dst, size_t maxCount);

        enum Error {
            NoError,            ///< No error yet
            ProtocolError,      ///< The peer does not use SecretHandshake, or a different AppID.
            AuthError,          ///< Server has different public key, or doesn't like the client's.
        };

        /// Current error; if not None, the handshake has failed and you should close the socket.
        /// Call this after `receivedBytes` and `bytesToSend`.
        Error error()                  {return _error;}

        /// Becomes true when the handshake is complete.
        /// Call this after `receivedBytes` and `bytesToSend`.
        bool finished()                {return _step == Finished;}

        /// After the handshake is finished, this returns the results to use for communication.
        Session session();

        virtual ~Handshake();

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
        void nextStep();
        void failed();
        virtual bool _receivedBytes(const uint8_t*) =0;          // process received bytes
        virtual void _fillOutputBuffer(std::vector<uint8_t>&) =0;// Resize & fill vector with output

        Context                 _context;                   // App ID and local key-pair
        Step                    _step = ClientChallenge;    // Current step in protocol, or Failed
        Error                   _error = NoError;           // Current error
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
        
        size_t byteCountNeeded() override;
    protected:
        bool _receivedBytes(const uint8_t *bytes) override;
        void _fillOutputBuffer(std::vector<uint8_t>&) override;
    };



    /// Server (passive) side of Secret Handshake protocol.
    class ServerHandshake final : public Handshake {
    public:
        /// Constructs a Server for accepting a connection from a Client.
        /// @param context  The application ID and the server's key-pair.
        explicit ServerHandshake(Context const& context);

        using ClientAuthorizer = std::function<bool(PublicKey const&)>;

        /// Registers a callback that determines whether a client should be allowed to connect.
        /// It takes the client public key as a parameter, and returns true to allow connection.
        void setClientAuthorizer(ClientAuthorizer a)    {_clientAuth = std::move(a);}

        size_t byteCountNeeded() override;
    protected:
        bool _receivedBytes(const uint8_t *bytes) override;
        void _fillOutputBuffer(std::vector<uint8_t>&) override;

        ClientAuthorizer _clientAuth;
    };

}
