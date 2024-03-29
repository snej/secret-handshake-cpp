//
// SecretRPC.hh
//
// Copyright © 2021 Jens Alfke. All rights reserved.
//

#pragma once
#include "SecretConnection.hh"
#include <capnp/capability.h>
#include <capnp/message.h>
#include <functional>

namespace snej::shs {

    /// Easy Cap'n Proto RPC server using the Secret Handshake protocol.
    class SecretRPCServer {
    public:
        /// Factory function for the server's main/root capability.
        /// This is called when a new client connection opens, and is passed the peer identity,
        /// from which you can get the peer's authenticated public key. (If secrecy is disabled for
        /// this server, this parameter will be nullptr.)
        /// You can either ignore the identity and return a singleton object, as with EzRpcServer,
        /// or you can create a new capability per connection and pass it the connection's public
        /// key, so it can authorize calls to its API.
        using MainInterfaceFactory = std::function<capnp::Capability::Client(const SHSPeerIdentity*)>;

        /// Initializes & starts the server, asynchronously.
        /// @param shsWrapper  The server's SecretHandshake info, or empty to disable secrecy.
        /// @param mainInterface  The root object to be served.
        /// @param bindAddress  The address of the interface to bind to, or "*" for all interfaces.
        /// @param defaultPort  The TCP port to listen on, or 0 to pick a random port.
        /// @param readerOpts  Options for reading incoming serialized messages.
        SecretRPCServer(kj::Own<ServerWrapper> shsWrapper,
                        MainInterfaceFactory mainInterface,
                        kj::StringPtr bindAddress,
                        uint16_t defaultPort,
                        capnp::ReaderOptions readerOpts);

        ~SecretRPCServer() noexcept(false);

        kj::Promise<capnp::uint> getPort();

        kj::WaitScope& getWaitScope();

        kj::AsyncIoProvider& getIoProvider();

        kj::LowLevelAsyncIoProvider& getLowLevelIoProvider();

        
        /// Constructor that doesn't open a listening socket.
        /// Instead, you have to call `acceptStream` to connect streams to it. Used for testing.
        SecretRPCServer(kj::Own<ServerWrapper> shsContext,
                        MainInterfaceFactory mainInterfaceFactory,
                        capnp::ReaderOptions readerOpts);

        /// Connects a (promised) stream to the server, as though a client had connected.
        /// Used for testing.
        void acceptStream(kj::Promise<kj::AuthenticatedStream> streamPromise,
                          capnp::ReaderOptions readerOpts = {});

    private:
        struct Impl;
        kj::Own<Impl> _impl;
    };

    

    /// Easy Cap'n Proto RPC client using the Secret Handshake protocol.
    class SecretRPCClient {
    public:
        /// Initializes the client and connects asynchronously.
        /// @param shsWrapper  The client's SecretHandshake info, or empty to disable secrecy.
        /// @param serverAddress  The address to connect to.
        /// @param serverPort  The TCP port to connect to.
        /// @param readerOpts  RPC options controlling how data is read.
        SecretRPCClient(kj::Own<ClientWrapper> shsWrapper,
                        kj::StringPtr serverAddress,
                        uint16_t serverPort,
                        capnp::ReaderOptions readerOpts = {});

        /// Initializes the client on a (promised) stream.
        /// @param shsWrapper  The client's SecretHandshake info, or empty to disable secrecy.
        /// @param streamPromise  The promised AsyncIoStream.
        /// @param readerOpts  RPC options controlling how data is read.
        SecretRPCClient(kj::Own<ClientWrapper> shsWrapper,
                        kj::Promise<kj::Own<kj::AsyncIoStream>> streamPromise,
                        capnp::ReaderOptions readerOpts = {});

        SecretRPCClient(SecretRPCClient &&other);

        ~SecretRPCClient() noexcept(false);

        template <typename Type>
        typename Type::Client getMain();

        capnp::Capability::Client getMain();

        kj::WaitScope& getWaitScope();

        kj::AsyncIoProvider& getIoProvider();

        kj::LowLevelAsyncIoProvider& getLowLevelIoProvider();

    private:
        struct Impl;
        kj::Own<Impl> _impl;
    };



    template <typename Type>
    inline typename Type::Client SecretRPCClient::getMain() {
        return getMain().castAs<Type>();
    }


    /** Automatically manages an AsyncIoContext per thread.
        Just call RPCContext::getThreadLocal. Hang onto the reference for as long as
        you need to do RPC stuff. */
    class RPCContext: public kj::Refcounted {
    public:
        static kj::Own<RPCContext> getThreadLocal();

        kj::AsyncIoContext& getIoContext()                   {return ioContext;}
        kj::WaitScope& getWaitScope()                        {return ioContext.waitScope;}
        kj::AsyncIoProvider& getIoProvider()                 {return *ioContext.provider;}
        kj::LowLevelAsyncIoProvider& getLowLevelIoProvider() {return *ioContext.lowLevelProvider;}

        // do not call these
        RPCContext();
        ~RPCContext() noexcept(false);

    private:
        kj::AsyncIoContext ioContext;
    };
}
