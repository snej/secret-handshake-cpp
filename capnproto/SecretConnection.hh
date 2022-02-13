//
// SecretConnection.hh
//
// Copyright © 2021 Jens Alfke. All rights reserved.
//

#pragma once
#include "SecretHandshake.hh"
#include <functional>
#include <kj/async-io.h>

namespace snej::shs {

    /// Cap'n Proto AsyncStream wrapper factory for SecretHandshake connections.
    /// This is an abstract class; use `ServerWrapper` or `ClientWrapper`.
    class StreamWrapper {
    public:
        /// A server-side callback that accepts or rejects a client given its public key.
        using Authorizer = std::function<bool(PublicKey const&)>;

        explicit StreamWrapper(Context const& context)     :_context(context) { }
        virtual ~StreamWrapper() = default;

        void setConnectTimeout(kj::Duration timeout, kj::Timer &timer);

        /// Upgrades a regular network stream to use SecretHandshake.
        /// The returned promise resolves when the handshake has completed successfully.
        kj::Promise<kj::Own<kj::AsyncIoStream>> wrap(kj::Own<kj::AsyncIoStream>);

        /// Upgrade a regular authenticated network stream to use SecretHandshake.
        /// The returned promise resolves when the handshake has completed successfully.
        /// @note  The stream's `peerIdentity` will be a `SHSPeerIdentity`.
        kj::Promise<kj::AuthenticatedStream> wrap(kj::AuthenticatedStream stream);

    protected:
        virtual kj::Own<Handshake> newHandshake() =0;

        Context                 _context;
        Authorizer              _authorizer;
        kj::Maybe<kj::Duration> _connectTimeout;
        kj::Maybe<kj::Timer*>   _connectTimer;
    };



    /// Cap'n Proto AsyncStream wrapper factory for SecretHandshake server (incoming) connections.
    class ServerWrapper final : public StreamWrapper {
    public:
        /// Constructs a ServerWrapper.
        /// @param context  The app ID and key-pair.
        /// @param auth  Callback that accepts or rejects a client given its public key.
        explicit ServerWrapper(Context const& context,
                               Authorizer auth)
            :StreamWrapper(context) {_authorizer = kj::mv(auth);}

        Authorizer const& authorizer() const                {return _authorizer;}

    private:
        kj::Own<Handshake> newHandshake() override;
    };



    /// Cap'n Proto AsyncStream wrapper factory for SecretHandshake client (outgoing) connections.
    class ClientWrapper final : public StreamWrapper {
    public:
        /// Constructs a ClientWrapper.
        /// @param context  The app ID and key-pair.
        /// @param serverKey  The server's public key. The handshake will verify this.
        ClientWrapper(Context const& context,
                      PublicKey const& serverKey)
            :StreamWrapper(context) ,_serverPublicKey(serverKey) { }

        PublicKey const& serverPublicKey() const            {return _serverPublicKey;}

    private:
        kj::Own<Handshake> newHandshake() override;
        PublicKey const _serverPublicKey;
    };



    /// PeerIdentity of an AuthenticatedStream produced by a SecretHandshake Context.
    /// Reveals the peer's public key. This is useful for the server, but not for the client
    /// (which had to know the server's public key already, to make the handshake.)
    class SHSPeerIdentity final : public kj::PeerIdentity {
    public:
        SHSPeerIdentity(PublicKey const& key,
                        kj::Own<kj::PeerIdentity> inner)
            :_publicKey(key), _inner(kj::mv(inner)) { }

        kj::String toString() override;

        /// The peer's public key.
        PublicKey publicKey() const                         {return _publicKey;}

        /// The identity information of the underlying transport.
        kj::PeerIdentity const* inner() const               {return _inner.get();}

    private:
        PublicKey const           _publicKey;
        kj::Own<kj::PeerIdentity> _inner;
    };
}
