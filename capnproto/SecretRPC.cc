//
// SecretRPC.cc
//
// Copyright © 2021 Jens Alfke. All rights reserved.
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


// Adapted from Cap'n Proto's ez-rpc.c++
// <https://github.com/capnproto/capnproto/blob/master/c%2B%2B/src/capnp/ez-rpc.c%2B%2B>
// Copyright (c) 2013-2014 Sandstorm Development Group, Inc. and contributors

#include "SecretRPC.hh"
#include <capnp/rpc-twoparty.h>
#include <kj/async-io.h>
#include <kj/threadlocal.h>
#include <map>

namespace snej::shs {
    using namespace capnp;

    class SecretRPCContext;

    KJ_THREADLOCAL_PTR(SecretRPCContext) threadSecretContext = nullptr;

    class SecretRPCContext: public kj::Refcounted {
    public:
        SecretRPCContext(): ioContext(kj::setupAsyncIo()) {
            threadSecretContext = this;
        }

        ~SecretRPCContext() noexcept(false) {
            KJ_REQUIRE(threadSecretContext == this,
                       "SecretRPCContext destroyed from different thread than it was created.") {
                return;
            }
            threadSecretContext = nullptr;
        }

        kj::WaitScope& getWaitScope() {
            return ioContext.waitScope;
        }

        kj::AsyncIoProvider& getIoProvider() {
            return *ioContext.provider;
        }

        kj::LowLevelAsyncIoProvider& getLowLevelIoProvider() {
            return *ioContext.lowLevelProvider;
        }

        static kj::Own<SecretRPCContext> getThreadLocal() {
            SecretRPCContext* existing = threadSecretContext;
            if (existing != nullptr) {
                return kj::addRef(*existing);
            } else {
                return kj::refcounted<SecretRPCContext>();
            }
        }

    private:
        kj::AsyncIoContext ioContext;
    };


#pragma mark - SERVER:


    struct SecretRPCServer::Impl final : public SturdyRefRestorer<AnyPointer>,
                                         public kj::TaskSet::ErrorHandler
    {
        struct ExportedCap {
            kj::String name;
            Capability::Client cap = nullptr;

            ExportedCap(kj::StringPtr name, Capability::Client cap)
            : name(kj::heapString(name)), cap(cap) {}

            ExportedCap() = default;
            ExportedCap(const ExportedCap&) = delete;
            ExportedCap(ExportedCap&&) = default;
            ExportedCap& operator=(const ExportedCap&) = delete;
            ExportedCap& operator=(ExportedCap&&) = default;
            // Make std::map happy...
        };


        // Represents an incoming client connection.
        struct Connection : public SturdyRefRestorer<AnyPointer> {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"  // SturdyRefRestorer is deprecated
            Connection(kj::AuthenticatedStream&& authStream,
                       Capability::Client mainInterface,
                       SturdyRefRestorer<AnyPointer>& parentRestorer,
                       ReaderOptions readerOpts)
            :_stream(kj::mv(authStream))
            ,_network(*this->_stream.stream, capnp::rpc::twoparty::Side::SERVER, readerOpts)
            ,_mainInterface(mainInterface)
            ,_parentRestorer(parentRestorer)
            ,_rpcSystem(makeRpcServer(_network, *this))
            { }

            Capability::Client restore(AnyPointer::Reader objectId) override {
                if (objectId.isNull()) {
                    return _mainInterface;
                } else {
                    return _parentRestorer.restore(objectId);
                }
            }
#pragma GCC diagnostic pop

            kj::AuthenticatedStream                 _stream;
            TwoPartyVatNetwork                      _network;
            RpcSystem<capnp::rpc::twoparty::VatId>  _rpcSystem;
            Capability::Client                      _mainInterface;
            SturdyRefRestorer<AnyPointer>&          _parentRestorer;
        };


        Impl(MainInterfaceFactory mainInterfaceFactory,
             kj::StringPtr bindAddress,
             uint defaultPort,
             ReaderOptions readerOpts,
             kj::Own<StreamWrapper> shsContext)
        :_mainInterfaceFactory(kj::mv(mainInterfaceFactory))
        ,_context(SecretRPCContext::getThreadLocal())
        ,_portPromise(nullptr)
        ,_tasks(*this)
        ,_shsWrapper(kj::mv(shsContext))
        {
            auto paf = kj::newPromiseAndFulfiller<uint>();
            _portPromise = paf.promise.fork();

            _tasks.add(_context->getIoProvider().getNetwork().parseAddress(bindAddress, defaultPort)
                       .then(kj::mvCapture(paf.fulfiller,
                                           [this, readerOpts](kj::Own<kj::PromiseFulfiller<uint>>&& portFulfiller,
                                                              kj::Own<kj::NetworkAddress>&& addr) {
                auto listener = addr->listen();
                portFulfiller->fulfill(listener->getPort());
                acceptLoop(kj::mv(listener), readerOpts);
            })));
        }

        void acceptLoop(kj::Own<kj::ConnectionReceiver>&& listener, ReaderOptions readerOpts) {
            auto ptr = listener.get();
            auto streamPromise = ptr->acceptAuthenticated();
            if (_shsWrapper) {
                streamPromise = streamPromise.then([&](auto asyncStream) {
                    return _shsWrapper->wrap(kj::mv(asyncStream));
                });
            }
            _tasks.add(streamPromise.then(kj::mvCapture(
                                    kj::mv(listener),
                                    [this, readerOpts](kj::Own<kj::ConnectionReceiver>&& listener,
                                                       kj::AuthenticatedStream&& stream)
            {
                acceptLoop(kj::mv(listener), readerOpts);
                auto peerID = dynamic_cast<const shs::SHSPeerIdentity*>(stream.peerIdentity.get());
                auto mainInterface = _mainInterfaceFactory(peerID);

                auto connection = kj::heap<Connection>(kj::mv(stream), mainInterface, *this, readerOpts);
                // Arrange to destroy the Connection when all references are gone, or when the
                // Server is destroyed (which will destroy the TaskSet).
                _tasks.add(connection->_network.onDisconnect().attach(kj::mv(connection)));
            })));
        }

        Capability::Client restore(AnyPointer::Reader objectId) override {
            auto name = objectId.getAs<Text>();
            auto iter = _exportMap.find(name);
            if (iter == _exportMap.end()) {
                KJ_FAIL_REQUIRE("Server exports no such capability.", name) { break; }
                return nullptr;
            } else {
                return iter->second.cap;
            }
        }

        void taskFailed(kj::Exception&& exception) override {
            kj::throwFatalException(kj::mv(exception));
        }

        MainInterfaceFactory                 _mainInterfaceFactory;
        kj::Own<SecretRPCContext>            _context;
        kj::ForkedPromise<uint>              _portPromise;
        kj::TaskSet                          _tasks;
        kj::Own<StreamWrapper>               _shsWrapper;
        std::map<kj::StringPtr, ExportedCap> _exportMap;
    };

    

    SecretRPCServer::SecretRPCServer(kj::Own<ServerWrapper> shsContext,
                                     MainInterfaceFactory mainInterfaceFactory,
                                     kj::StringPtr bindAddress,
                                     uint16_t defaultPort,
                                     capnp::ReaderOptions readerOpts)
    :_impl(kj::heap<Impl>(mainInterfaceFactory, bindAddress, defaultPort, readerOpts,
                          kj::mv(shsContext)))
    { }

    SecretRPCServer::~SecretRPCServer() noexcept(false) { }

    kj::Promise<uint> SecretRPCServer::getPort() {
        return _impl->_portPromise.addBranch();
    }

    kj::WaitScope& SecretRPCServer::getWaitScope() {
        return _impl->_context->getWaitScope();
    }

    kj::AsyncIoProvider& SecretRPCServer::getIoProvider() {
        return _impl->_context->getIoProvider();
    }

    kj::LowLevelAsyncIoProvider& SecretRPCServer::getLowLevelIoProvider() {
        return _impl->_context->getLowLevelIoProvider();
    }



#pragma mark - CLIENT:


    static kj::Promise<kj::Own<kj::AsyncIoStream>> connectAttach(kj::Own<kj::NetworkAddress>&& addr) {
        return addr->connect().attach(kj::mv(addr));
    }

    struct SecretRPCClient::Impl {

        struct ClientContext {
            kj::Own<kj::AsyncIoStream> stream;
            TwoPartyVatNetwork network;
            RpcSystem<capnp::rpc::twoparty::VatId> rpcSystem;

            ClientContext(kj::Own<kj::AsyncIoStream>&& stream,
                          ReaderOptions readerOpts)
            :stream(kj::mv(stream))
            ,network(*this->stream, capnp::rpc::twoparty::Side::CLIENT, readerOpts)
            ,rpcSystem(makeRpcClient(network))
            { }

            Capability::Client getMain() {
                word scratch[4];
                memset(scratch, 0, sizeof(scratch));
                MallocMessageBuilder message(scratch);
                auto hostId = message.getRoot<capnp::rpc::twoparty::VatId>();
                hostId.setSide(capnp::rpc::twoparty::Side::SERVER);
                return rpcSystem.bootstrap(hostId);
            }

            Capability::Client restore(kj::StringPtr name) {
                word scratch[64];
                memset(scratch, 0, sizeof(scratch));
                MallocMessageBuilder message(scratch);

                auto hostIdOrphan = message.getOrphanage().newOrphan<capnp::rpc::twoparty::VatId>();
                auto hostId = hostIdOrphan.get();
                hostId.setSide(capnp::rpc::twoparty::Side::SERVER);

                auto objectId = message.getRoot<AnyPointer>();
                objectId.setAs<Text>(name);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                return rpcSystem.restore(hostId, objectId);
#pragma GCC diagnostic pop
            }
        };


        Impl(kj::StringPtr serverAddress,
             uint defaultPort,
             ReaderOptions readerOpts,
             kj::Own<ClientWrapper> shsWrapper)
        :_context(SecretRPCContext::getThreadLocal())
        ,_shsWrapper(kj::mv(shsWrapper))
        ,_setupPromise(_context->getIoProvider().getNetwork()
                       .parseAddress(serverAddress, defaultPort)
                       .then([](kj::Own<kj::NetworkAddress>&& addr) {
            return connectAttach(kj::mv(addr));
        }).then([this](kj::Own<kj::AsyncIoStream>&& stream)
                -> kj::Promise<kj::Own<kj::AsyncIoStream>> {
            if (_shsWrapper) {
                return _shsWrapper->wrap(kj::mv(stream));
            } else {
                return kj::mv(stream);
            }
        }).then([this, readerOpts](kj::Own<kj::AsyncIoStream>&& stream) {
            _clientContext = kj::heap<ClientContext>(kj::mv(stream),
                                                     readerOpts);
        }).fork())
        { }


        Capability::Client getMain() {
            KJ_IF_MAYBE(client, _clientContext) {
                return client->get()->getMain();
            } else {
                return _setupPromise.addBranch().then([this]() {
                    return KJ_ASSERT_NONNULL(_clientContext)->getMain();
                });
            }
        }

        template <typename Type>
        inline typename Type::Client getMain() {
            return getMain().castAs<Type>();
        }

        kj::Own<SecretRPCContext>           _context;
        kj::Own<ClientWrapper>              _shsWrapper;
        kj::ForkedPromise<void>             _setupPromise;
        kj::Maybe<kj::Own<ClientContext>>   _clientContext; // Filled in before `setupPromise` resolves.
    };



    SecretRPCClient::SecretRPCClient(kj::Own<ClientWrapper> shsContext,
                                     kj::StringPtr serverAddress,
                                     uint16_t serverPort,
                                     capnp::ReaderOptions readerOpts)
    :_impl(kj::heap<Impl>(serverAddress, serverPort, readerOpts, kj::mv(shsContext)))
    { }

    SecretRPCClient::~SecretRPCClient() noexcept(false) { }

    Capability::Client SecretRPCClient::getMain() {
        KJ_IF_MAYBE(client, _impl->_clientContext) {
            return client->get()->getMain();
        } else {
            return _impl->_setupPromise.addBranch().then([this]() {
                return KJ_ASSERT_NONNULL(_impl->_clientContext)->getMain();
            });
        }
    }

    SecretRPCClient::SecretRPCClient(SecretRPCClient &&other)
    :_impl(kj::mv(other._impl))
    { }


    kj::WaitScope& SecretRPCClient::getWaitScope() {
        return _impl->_context->getWaitScope();
    }

    kj::AsyncIoProvider& SecretRPCClient::getIoProvider() {
        return _impl->_context->getIoProvider();
    }

    kj::LowLevelAsyncIoProvider& SecretRPCClient::getLowLevelIoProvider() {
        return _impl->_context->getLowLevelIoProvider();
    }

}
