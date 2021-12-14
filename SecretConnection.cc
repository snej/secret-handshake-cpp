//
// SecretConnection.cc
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


// This code is adapted from Cap'n Proto's c++/src/kj/compat/tls.c++
// <https://github.com/capnproto/capnproto/blob/master/c%2B%2B/src/kj/compat/tls.c%2B%2B>
// Copyright (c) 2016 Sandstorm Development Group, Inc. and contributors

#include "SecretConnection.hh"
#include "SecretHandshake.hh"
#include <kj/async-queue.h>
#include <kj/debug.h>
#include <kj/vector.h>

namespace snej::shs {

#pragma mark - STREAM:


    class WrappedStream final: public kj::AsyncIoStream {
    public:
        WrappedStream(kj::Own<kj::AsyncIoStream> stream,
                      kj::Own<Handshake> handshake,
                      StreamWrapper::Authorizer authorizer)
        :WrappedStream(*stream, kj::mv(handshake), kj::mv(authorizer))
        {
            _ownInner = kj::mv(stream);
        }


        WrappedStream(kj::AsyncIoStream& stream,
                      kj::Own<Handshake> handshake,
                      StreamWrapper::Authorizer authorizer)
        :_handshake(kj::mv(handshake))
        ,_inner(stream)
        ,_authorizer(kj::mv(authorizer))
        { }


        ~WrappedStream() noexcept(false) { }


        kj::Promise<Session> runHandshake() {
            if (_handshake->finished()) {
                auto result = _handshake->session();
                _handshake = nullptr;
                if (_authorizer && !_authorizer(result.peerPublicKey))
                    return KJ_EXCEPTION(DISCONNECTED, "Unauthorized client key");
                return result;
            } else if (auto [toSend, sendSize] = _handshake->bytesToSend(); sendSize > 0) {
                return _inner.write(toSend, sendSize).then([&]() {
                    _handshake->sendCompleted();
                    return runHandshake(); // continue
                });
            } else if (auto [toRead, readSize] = _handshake->bytesToRead(); readSize > 0) {
                return _inner.read(toRead, readSize).then([&]() {
                    _handshake->readCompleted();
                    return runHandshake(); // continue
                });
            } else {
                assert(_handshake->failed());
                return KJ_EXCEPTION(DISCONNECTED, "SecretHandshake protocol failed to connect");
            }
        }


        kj::Promise<void> connect() {
            return runHandshake().then([&](Session result) {
                _session = result;
            });
        }


        kj::Own<SHSPeerIdentity> getIdentity(kj::Own<kj::PeerIdentity> inner) {
            KJ_IF_MAYBE(keys, _session) {
                return kj::heap<SHSPeerIdentity>(keys->peerPublicKey, kj::mv(inner));
            } else {
                return {};
            }
        }


        kj::Promise<size_t> tryRead(void* buffer, size_t minBytes, size_t maxBytes) override {
            return _inner.tryRead(buffer, minBytes, maxBytes).then([=](size_t nBytes) {
                KJ_REQUIRE_NONNULL(_session).decrypt(buffer, buffer, nBytes);
                return nBytes;
            });
        }


        kj::Promise<void> write(const void* buffer, size_t size) override {
            //TODO: Apparently only one write is active at once, so writeBuf can be a member variable
            auto writeBuf = std::make_unique<uint8_t[]>(size);
            KJ_REQUIRE_NONNULL(_session).encrypt(writeBuf.get(), buffer, size);
            return _write(std::move(writeBuf), size);
        }


        kj::Promise<void> write(kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>> pieces) override {
            size_t size = 0;
            for (auto &piece : pieces)
                size += piece.size();
            auto writeBuf = std::make_unique<uint8_t[]>(size);
            auto dst = writeBuf.get();
            for (auto &piece : pieces) {
                KJ_REQUIRE_NONNULL(_session).encrypt(dst, piece.begin(), piece.size());
                dst += piece.size();
            }
            return _write(std::move(writeBuf), size);
        }


        kj::Promise<void> _write(std::unique_ptr<uint8_t[]> &&buf, size_t size) {
            return _inner.write(buf.get(), size).attach(std::move(buf));
        }


        void shutdownWrite() override {
            _inner.shutdownWrite();
        }
        kj::Promise<void> whenWriteDisconnected() override {
            return _inner.whenWriteDisconnected();
        }
        void abortRead() override {
            _inner.abortRead();
        }
        void getsockopt(int level, int option, void* value, kj::uint* length) override {
            _inner.getsockopt(level, option, value, length);
        }
        void setsockopt(int level, int option, const void* value, kj::uint length) override {
            _inner.setsockopt(level, option, value, length);
        }
        void getsockname(struct sockaddr* addr, kj::uint* length) override {
            _inner.getsockname(addr, length);
        }
        void getpeername(struct sockaddr* addr, kj::uint* length) override {
            _inner.getpeername(addr, length);
        }
        kj::Maybe<int> getFd() const override {
            return _inner.getFd();
        }

    private:
        kj::Own<Handshake>          _handshake;
        kj::Maybe<Session>          _session;
        StreamWrapper::Authorizer   _authorizer;
        kj::AsyncIoStream&          _inner;
        kj::Own<kj::AsyncIoStream>  _ownInner;
        kj::Maybe<kj::Promise<void>> _shutdownTask;
        bool                        _disconnected = false;
    };


#pragma mark - CONTEXT:


    void StreamWrapper::setConnectTimeout(kj::Duration timeout, kj::Timer &timer) {
        _connectTimeout = timeout;
        _connectTimer = &timer;
    }

    
    kj::Promise<kj::Own<kj::AsyncIoStream>> StreamWrapper::wrap(kj::Own<kj::AsyncIoStream> stream) {
        auto conn = kj::heap<WrappedStream>(kj::mv(stream), newHandshake(), _authorizer);
        auto promise = conn->connect();
        return promise.then(kj::mvCapture(conn, [](kj::Own<WrappedStream> conn)
                                          -> kj::Own<kj::AsyncIoStream> {
            return kj::mv(conn);
        }));
        // FIXME: Handle timeout, like the other `wrap` method (in fact, combine the two methods.)
    }


    kj::Promise<kj::AuthenticatedStream> StreamWrapper::wrap(kj::AuthenticatedStream stream) {
        auto conn = kj::heap<WrappedStream>(kj::mv(stream.stream), newHandshake(), _authorizer);
        auto promise = conn->connect();
        KJ_IF_MAYBE(timeout, _connectTimeout) {
            promise = KJ_REQUIRE_NONNULL(_connectTimer)->afterDelay(*timeout).then([]() -> kj::Promise<void> {
                return KJ_EXCEPTION(DISCONNECTED, "timed out during Secret Handshake");
            }).exclusiveJoin(kj::mv(promise));
        }
        return promise.then([conn=kj::mv(conn),innerId=kj::mv(stream.peerIdentity)]() mutable {
            auto id = conn->getIdentity(kj::mv(innerId));
            return kj::AuthenticatedStream { kj::mv(conn), kj::mv(id) };
        });
    }


    kj::Own<Handshake> ServerWrapper::newHandshake() {
        return kj::heap<ServerHandshake>(_context);
    }

    kj::Own<Handshake> ClientWrapper::newHandshake() {
        return kj::heap<ClientHandshake>(_context, _serverPublicKey);
    }


#pragma mark - PEER IDENTITY:


    kj::String SHSPeerIdentity::toString() {
        return kj::str("(public key)");     //TODO: Write key as hex string
    }

}  // namespace
