//
// SecretHandshakeStream.hh
//
// Copyright © 2023 Jens Alfke. All rights reserved.
//

#pragma once
#include "../include/SecretHandshakeTypes.hh"
#include "crouton/io/IStream.hh"
#include "crouton/io/ISocket.hh"

namespace snej::shs {
    class DecryptionStream;
    class EncryptionStream;
    class Handshake;
}
namespace snej::shs::crouton {
    using namespace ::crouton;

    /** Error enum for SecretHandshake failures. */
    enum class SecretHandshakeError : errorcode_t {
        ProtocolError = 1,  // Handshake failed due to bad data
        AuthError,          // Handshake failed because peer rejected public key
        DataError,          // Invalid data received after handshake
    };


    /** Runs the SecretHandshake protocol over a Crouton IStream.
        After the handshake completes, it's up to you how to send/receive data.
        You probably want to use SecretHandshakeStream instead. */
    class SecretHandshake {
    public:

        /// Constructs a SecretHandshake.
        /// @param context  Contains your key-pair and the app ID.
        /// @param serverKey  For a client connection, pass the server's known public key.
        ///                   For a server connection, pass nullptr.
        SecretHandshake(shs::Context const& context, PublicKey const* serverKey);

        /// Registers a callback that determines whether a client should be allowed to connect.
        /// It takes the client public key as a parameter, and returns true to allow connection.
        /// If this is not called, the default is to allow any client.
        void setClientAuthorizer(std::function<bool(PublicKey const&)>);

        /// Performs the handshake.
        /// Upon successful completion, returns the Session struct with the sesssion keys.
        /// On failure, returns a SecretHandshakeError.
        ASYNC<shs::Session> handshake(std::shared_ptr<io::IStream>);

    private:
        std::unique_ptr<shs::Handshake> _handshake;
    };



    /** Optional delegate interface for a SecretHandshakeStream. */
    struct SecretHandshakeStreamDelegate {
        virtual bool authorizeSecretHandshake(PublicKey const&) {return true;}
        virtual void secretHandshakeStreamClosed() { }
        virtual ~SecretHandshakeStreamDelegate() = default;
    };


    /** A Crouton IStream implementation that wraps another IStream, probably an ISocket's.
        It runs the SecretHandshake protocol, and on success, encrypts & decrypts stream data.*/
    class SecretHandshakeStream : public io::IStream {
    public:
        SecretHandshakeStream(std::shared_ptr<io::IStream> stream,
                              Context const&,
                              PublicKey const* serverKey);
        ~SecretHandshakeStream();

        bool isOpen() const override;
        ASYNC<void> open() override;
        ASYNC<void> close() override;
        coro_wrapper_ ASYNC<void> closeWrite() override;

        ASYNC<ConstBytes> readNoCopy(size_t maxLen = 65536) override;
        ASYNC<ConstBytes> peekNoCopy() override;

        ASYNC<void> write(ConstBytes) override;
        ASYNC<void> write(std::span<ConstBytes const> buffers) override;

        /// The connected peer's public key. Stream MUST be open.
        PublicKey const& peerPublicKey() const;

        using Delegate = SecretHandshakeStreamDelegate;
        void setDelegate(Delegate*);

    protected:
        friend class SecretHandshakeSocket;
        void setRawStream(std::shared_ptr<io::IStream>);

    private:
        void notifyClosed();

        std::shared_ptr<io::IStream>    _stream;
        SecretHandshake                 _handshake;
        Delegate*                       _delegate = nullptr;
        shs::PublicKey                  _peerPublicKey;
        std::unique_ptr<EncryptionStream> _writer;
        std::unique_ptr<DecryptionStream> _reader;
        size_t                          _lastReadSize = 0;
        size_t                          _lastWriteSize = 0;
        bool                            _open = false;
    };



    /** An ISocket implementation that opens a TCPSocket and wraps its stream with a
        SecretHandshakeStream. */
    class SecretHandshakeSocket : public io::ISocket {
    public:
        SecretHandshakeSocket(Context const&, PublicKey const& serverKey);
        coro_wrapper_ ASYNC<void> open() override;
        std::shared_ptr<io::IStream> stream() override;

    private:
        std::shared_ptr<SecretHandshakeStream> _stream;
    };

}

namespace crouton {
    template <> struct ErrorDomainInfo<snej::shs::crouton::SecretHandshakeError> {
        static constexpr string_view name = "SecretHandshake";
        static string description(errorcode_t);
    };
}
