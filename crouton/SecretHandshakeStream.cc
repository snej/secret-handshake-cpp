//
// SecretHandshakeStream.cc
//
// Copyright © 2023 Jens Alfke. All rights reserved.
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

#include "SecretHandshakeStream.hh"
#include "../include/SecretHandshake.hh"
#include "../include/SecretStream.hh"
#include "crouton/Future.hh"
#include "crouton/util/Logging.hh"

namespace snej::shs::crouton {
    using namespace std;
    using namespace ::crouton;


    SecretHandshake::SecretHandshake(Context const& context, PublicKey const* serverKey) {
        if (serverKey)
            _handshake = make_unique<ClientHandshake>(context, *serverKey);
        else
            _handshake = make_unique<ServerHandshake>(context);
    }


    void SecretHandshake::setClientAuthorizer(ServerHandshake::ClientAuthorizer auth) {
        dynamic_cast<ServerHandshake&>(*_handshake).setClientAuthorizer(std::move(auth));
    }


    ASYNC<Session> SecretHandshake::handshake(std::shared_ptr<io::IStream> stream) {
        precondition(stream);
        AWAIT stream->open();

        // Handshake:
        LNet->info("Starting SecretHandshake");
        do {
            auto [toSend, sizeToSend] = _handshake->bytesToSend();
            if (sizeToSend > 0) {
                AWAIT stream->write(ConstBytes{toSend, sizeToSend});
                _handshake->sendCompleted();
            }
            auto [toRead, sizeToRead] = _handshake->bytesToRead();
            if (sizeToRead > 0) {
                size_t n = AWAIT stream->read(MutableBytes{toRead, sizeToRead});
                if (n == sizeToRead)
                    _handshake->readCompleted();
                else
                    _handshake->readFailed();
            }
        } while (!_handshake->finished() && !_handshake->error());

        if (_handshake->error()) {
            Error err(SecretHandshakeError(int(_handshake->error())));
            _handshake = nullptr;
            LNet->error("...SecretHandshake failed: {}", crouton::mini::format("{}",err));
            RETURN err;
        }

        // Handshake succeeded:
        auto session = _handshake->session();
        _handshake = nullptr;
        LNet->info("...SecretHandshake succeeded!");
        RETURN session;
    }


#pragma mark - SECRET HANDSHAKE STREAM:


    SecretHandshakeStream::SecretHandshakeStream(std::shared_ptr<io::IStream> stream,
                                                 Context const& context,
                                                 PublicKey const* serverKey)
    :_stream(stream)
    ,_handshake(context, serverKey)
    { }

    SecretHandshakeStream::~SecretHandshakeStream() = default;

    void SecretHandshakeStream::setDelegate(Delegate* d)   {_delegate = d;}
    bool SecretHandshakeStream::isOpen() const             {return _open;}
    void SecretHandshakeStream::setRawStream(shared_ptr<io::IStream> stream) {_stream = std::move(stream);}


    ASYNC<void> SecretHandshakeStream::open() {
        if (_delegate) {
            _handshake.setClientAuthorizer([this](PublicKey const& clientKey) {
                bool ok = _delegate->authorizeSecretHandshake(clientKey);
                if (!ok)
                    LNet->error("SecretHandshake delegate rejected peer");
                return ok;
            });
        }

        Result<Session> session = AWAIT NoThrow(_handshake.handshake(_stream));
        if (session.ok()) {
            _peerPublicKey = session->peerPublicKey;
            _writer = make_unique<EncryptionStream>(*session);
            _reader = make_unique<DecryptionStream>(*session);
            _open = true;
        } else {
            AWAIT _stream->close();
            notifyClosed();
        }
        RETURN session.error();
    }


    void SecretHandshakeStream::notifyClosed() {
        if (_delegate)
            _delegate->secretHandshakeStreamClosed();
    }


    PublicKey const& SecretHandshakeStream::peerPublicKey() const {
        precondition(_open);
        return _peerPublicKey;
    }


    ASYNC<void> SecretHandshakeStream::close() {
        _open = false;
        if (!_stream)
            RETURN noerror;
        Result<void> result = AWAIT NoThrow(_stream->close());
        notifyClosed();
        RETURN result.error();
    }


    ASYNC<void> SecretHandshakeStream::closeWrite() {
        assert(_stream);
        return _stream->closeWrite();
    }


    ASYNC<ConstBytes> SecretHandshakeStream::peekNoCopy() {
        if (!_open)
            RETURN CroutonError::InvalidState;
        if (_lastReadSize > 0) {
            _reader->skip(_lastReadSize);
            _lastReadSize = 0;
        }
        while (_reader->bytesAvailable() == 0) {
            ConstBytes encBytes = AWAIT _stream->readNoCopy();
            if (encBytes.empty()) {
                if (_reader->close()) {
                    LNet->debug("SecretHandshakeStream {} read EOF", (void*)this);
                    RETURN ConstBytes{};
                } else {
                    LNet->error("SecretHandshakeStream {} unexpected EOF!", (void*)this);
                    (void)close();
                    RETURN Error(SecretHandshakeError::DataError);
                }
            }
            LNet->debug("SecretHandshakeStream {} received {} encrypted bytes", (void*)this, encBytes.size());
            if (!_reader->push(encBytes.data(), encBytes.size())) {
                (void)close();
                RETURN Error(SecretHandshakeError::DataError);
            }
            LNet->debug("SecretHandshakeStream {} has {} bytes available", (void*)this, _reader->availableData().size);
        }
        input_data avail = _reader->availableData();
        RETURN ConstBytes(avail.data, avail.size);
    }


    ASYNC<ConstBytes> SecretHandshakeStream::readNoCopy(size_t maxLen) {
        ConstBytes bytes = AWAIT peekNoCopy();
        bytes = bytes.read(maxLen);
        _lastReadSize = bytes.size();
        RETURN bytes;
    }


    ASYNC<void> SecretHandshakeStream::write(ConstBytes bytes) {
        return write(&bytes, 1);
    }

    ASYNC<void> SecretHandshakeStream::write(const ConstBytes buffers[], size_t nBuffers) {
        _writer->skip(_lastWriteSize);
        _lastWriteSize = 0;
        if (LNet->level() <= crouton::log::level::debug) {
            size_t total = 0;
            for (size_t i = 0; i < nBuffers; ++i)
                total += buffers[i].size();
            LNet->debug("SecretHandshakeStream {} writing {} bytes", (void*)this, total);
        }
        if (!_open)
            return CroutonError::InvalidState;
        for (size_t i = 0; i < nBuffers; ++i)
            _writer->pushPartial(buffers[i].data(), buffers[i].size());
        _writer->flush();
        auto encBytes = _writer->availableData();
        _lastWriteSize = encBytes.size;
        LNet->debug("SecretHandshakeStream {} sending {} encrypted bytes", (void*)this, encBytes.size);
        return _stream->write(ConstBytes{encBytes.data, encBytes.size});
    }


#pragma mark - SOCKET:


    SecretHandshakeSocket::SecretHandshakeSocket(Context const& context,
                                                 PublicKey const& serverKey)
    :_stream(make_shared<SecretHandshakeStream>(nullptr, context, &serverKey))
    { }


    ASYNC<void> SecretHandshakeSocket::open() {
        return stream()->open();
    }


    shared_ptr<io::IStream> SecretHandshakeSocket::stream() {
        if (!_stream->_stream) {
            auto tcpSocket = io::ISocket::newSocket(false);
            tcpSocket->bind(*this->_binding);
            _stream->setRawStream(tcpSocket->stream());
        }
        return _stream;
    }

}


namespace crouton {
    string ErrorDomainInfo<snej::shs::crouton::SecretHandshakeError>::description(errorcode_t code) {
        static constexpr string_view kErrorNames[] = {
            "", "protocol error", "authentication error", "data error" };
        return string(kErrorNames[code]);
    }
}
