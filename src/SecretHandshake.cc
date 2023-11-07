//
// SecretHandshake.cc
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

#include "SecretHandshake.hh"
#include "shs.hh"
#include "monocypher/signatures.hh"
#include <cstring>
#include <mutex>
#include <stdexcept>

// Minimalist logging. Define LOG_SECRET_HANDSHAKE=1 to enable it.
#ifndef LOG_SECRET_HANDSHAKE
#  define LOG_SECRET_HANDSHAKE 0
#endif
#ifdef LOG_SECRET_HANDSHAKE
#  include <iostream>
#endif
#define LOG  if (LOG_SECRET_HANDSHAKE) std::cerr << "SecretHandshake: " <<

namespace snej::shs {


    KeyPair::KeyPair(SigningKey const& sk)
    :signingKey(sk)
    ,publicKey(impl::signing_key(sk).get_public_key())
    { }
    

    KeyPair KeyPair::generate() {
        return KeyPair(impl::key_pair::generate());
    }


    KeyPair::~KeyPair() {
        monocypher::wipe(&signingKey, sizeof(signingKey));
    }


    AppID Context::appIDFromString(const char *str) {
        monocypher::byte_array<32> id;
        id.fillWithString(str);
        return id;
    }


    Session::~Session() {
        monocypher::wipe(this, sizeof(*this));
    }


#pragma mark - HANDSHAKE:


    Handshake::Handshake(Context const& context)
    :_context(context)
    ,_impl(std::make_unique<impl::handshake>(impl::app_id(context.appID),
                                            impl::signing_key(context.keyPair.signingKey),
                                            impl::public_key(context.keyPair.publicKey)))
    { }


    Handshake::~Handshake() = default;


    void Handshake::nextStep() {
        assert(_step > Failed && _step < Finished);
        _step = Step(_step + 1);
        if (_step == Finished)
            LOG "Success!\n";
    }


    std::pair<void*, size_t> Handshake::bytesToRead() {
        size_t needed = byteCountNeeded();
        if (needed > 0)
            LOG "Step " << _step << "/4: Awaiting " << needed << " bytes...\n";
        _inputBuffer.resize(needed);
        return {_inputBuffer.data(), needed};
    }


    bool Handshake::readCompleted() {
        if (_inputBuffer.size() != byteCountNeeded())
            throw std::logic_error("Unexpected call to Handshake::readCompleted");
        if (_receivedBytes(_inputBuffer.data()) > 0) {
            LOG "          ...OK!\n";
            nextStep();
            _inputBuffer.clear();
            return true;
        } else {
            LOG "          ...invalid data; HANDSHAKE FAILED\n";
            failed();
            return false;
        }
    }


    void Handshake::readFailed() {
        LOG "          ...unexpected EOF; HANDSHAKE FAILED\n";
        failed();
    }


    void Handshake::failed() {
        _error = (_step < ClientAuth) ? Error::ProtocolError : Error::AuthError;
        _step = Failed;
    }


    intptr_t Handshake::receivedBytes(const void *src, size_t count) {
        if (_step == Failed || _step == Finished)
            return -1;
        size_t needed = byteCountNeeded();
        if (needed == 0)
            return 0;
        count = std::min(count, needed - _inputBuffer.size());
        _inputBuffer.reserve(needed);
        _inputBuffer.insert(_inputBuffer.end(), (uint8_t*)src, (uint8_t*)src + count);
        if (_inputBuffer.size() < needed) {
            // Wait for more bytes:
            LOG "          ...Received " << count << "bytes; waiting...\n";
        } else {
            // Buffer has enough bytes, so consume it:
            readCompleted();
        }
        return _step != Failed ? count : -1;
    }


    std::pair<const void*,size_t> Handshake::bytesToSend() {
        if (_step == Failed || _step == Finished)
            return {};
        if (_outputBuffer.empty())
            _fillOutputBuffer(_outputBuffer);
        if (!_outputBuffer.empty())
            LOG "Step " << _step << "/4: Sending " << _outputBuffer.size() << " bytes...\n";
        return {_outputBuffer.data(), _outputBuffer.size()};
    }


    void Handshake::sendCompleted() {
        if (_outputBuffer.empty())
            throw std::logic_error("Unexpected call to Handshake::sendCompleted");
        LOG "          ...Send completed\n";
        _outputBuffer.clear();
        nextStep();
    }


    intptr_t Handshake::copyBytesToSend(void *dst, size_t maxCount) {
        if (_step == Failed)
            return -1;
        if (_outputBuffer.empty()) {
            // Fill buffer:
            if (bytesToSend().second == 0)
                return {};
        }
        // Copy bytes from buffer to dst:
        size_t count = std::min(_outputBuffer.size(), maxCount);
        ::memcpy(dst, _outputBuffer.data(), count);
        _outputBuffer.erase(_outputBuffer.begin(), _outputBuffer.begin() + count);
        if (_outputBuffer.empty()) {
            // Write is complete:
            LOG "        ...Send completed\n";
            nextStep();
        } else {
            LOG "        ...Sent " << count << "bytes...\n";
        }
        return count;
    }


    Session Handshake::session() {
        if (_step != Finished)
            throw std::logic_error("Secret Handshake protocol isn't complete");
        Session session;
        _impl->getOutcome((impl::session_key&)session.encryptionKey,
                          (impl::nonce&)session.encryptionNonce,
                          (impl::session_key&)session.decryptionKey,
                          (impl::nonce&)session.decryptionNonce,
                          (impl::public_key&)session.peerPublicKey);
        return session;
    }


    template <class T>
    static T& spaceFor(std::vector<uint8_t> &output) {
        output.resize(sizeof(T));
        return *(T*)output.data();
    }


#pragma mark - CLIENT:


    /* Notes on interpreting client-side failures:
     - EOF before receiving the server challenge:
         - It's not a SecretHandshake server
         - It doesn't use the same AppID
     - Invalid server challenge:
         - It's not a SecretHandshake server
     - EOF before receiving the server ack:
         - Server has a different public key
         - Server doesn't allow connections from your public key

     Data corruption or a MITM altering data is also possible.
     */


    ClientHandshake::ClientHandshake(Context const& context,
                                     PublicKey const& theirPublicKey)
    :Handshake(context)
    {
        _impl->setServerPublicKey(impl::public_key(theirPublicKey));
    }


    size_t ClientHandshake::byteCountNeeded() {
        switch (_step) {
            case ServerChallenge:  return sizeof(impl::ChallengeData);
            case ServerAck:        return sizeof(impl::ServerAckData);
            default:               return 0;
        }
    }


    bool ClientHandshake::_receivedBytes(const uint8_t *bytes) {
        switch (_step) {
            case ServerChallenge:  return _impl->verifyChallenge(*(impl::ChallengeData*)bytes);
            case ServerAck:        return _impl->verifyServerAck(*(impl::ServerAckData*)bytes);
            default:               return false;
        }
    }


    void ClientHandshake::_fillOutputBuffer(std::vector<uint8_t> &output) {
        switch (_step) {
            case ClientChallenge:
                spaceFor<impl::ChallengeData>(output) = _impl->createClientChallenge();
                break;
            case ClientAuth:
                spaceFor<impl::ClientAuthData>(output) = _impl->createClientAuth();
                break;
            default:
                break;
        }
    }


#pragma mark - SERVER:


    #define _serverState() (impl::shs_server*)_state.get()


    ServerHandshake::ServerHandshake(Context const& context)
    :Handshake(context)
    { }


    size_t ServerHandshake::byteCountNeeded() {
        switch (_step) {
            case ClientChallenge:  return sizeof(impl::ChallengeData);
            case ClientAuth:       return sizeof(impl::ClientAuthData);
            default:               return 0;
        }
    }


    bool ServerHandshake::_receivedBytes(const uint8_t *bytes) {
        switch (_step) {
            case ClientChallenge:
                return _impl->verifyChallenge(*(impl::ChallengeData*)bytes);
            case ClientAuth:  
                return _impl->verifyClientAuth(*(impl::ClientAuthData*)bytes)
                    && (!_clientAuth || _clientAuth(_impl->getPeerPublicKey()));
            default:
                return false;
        }
    }


    void ServerHandshake::_fillOutputBuffer(std::vector<uint8_t> &output) {
        switch (_step) {
            case ServerChallenge:
                spaceFor<impl::ChallengeData>(output) = _impl->createServerChallenge();
                break;
            case ServerAck:
                spaceFor<impl::ServerAckData>(output) = _impl->createServerAck();
                break;
            default:
                break;
        }
    }

}


#pragma mark - C GLUE:


#include "SecretHandshake.h"

using namespace snej::shs;

static inline SHSHandshake* external(Handshake* h)   {return (SHSHandshake*)h;}
static inline Handshake* internal(SHSHandshake* h)   {return (Handshake*)h;}


void SHSErase(void *dst, size_t size) {
    monocypher::wipe(dst, size);
}

SHSKeyPair SHSKeyPair_Generate(void) {
    auto pair = KeyPair::generate();
    return (const SHSKeyPair&)pair;
}

SHSKeyPair SHSKeyPair_Regenerate(const SHSSigningKey* signingKey) {
    KeyPair pair(*(SigningKey*)signingKey);
    return (const SHSKeyPair&)pair;
}

SHSAppID SHSAppID_FromString(const char* str) {
    auto id = Context::appIDFromString(str);
    return (const SHSAppID&)id;
}

SHSHandshake* SHSHandshake_CreateClient(const SHSAppID *appID,
                                        const SHSKeyPair *keyPair,
                                        const SHSPublicKey *serverPublicKey)
{
    Context ctx((AppID&)*appID, (KeyPair&)*keyPair);
    return external(new ClientHandshake(ctx, (PublicKey&)*serverPublicKey));
}

SHSHandshake* SHSHandshake_CreateServer(const SHSAppID *appID,
                                        const SHSKeyPair *keyPair) {
    Context ctx((AppID&)*appID, (KeyPair&)*keyPair);
    return external(new ServerHandshake(ctx));
}


void SHSHandshake_Free(SHSHandshake *h) {
    delete internal(h);
}


size_t SHSHandshake_GetBytesNeeded(SHSHandshake *h) {
    return internal(h)->byteCountNeeded();
}


void* SHSHandshake_GetInputBuffer(SHSHandshake *h) {
    return internal(h)->bytesToRead().first;
}


bool SHSHandshake_ReadCompleted(SHSHandshake *h) {
    return internal(h)->readCompleted();
}


intptr_t SHSHandshake_ReceivedBytes(SHSHandshake *h, const void *src, size_t count) {
    return internal(h)->receivedBytes(src, count);
}


SHSInputBuffer SHSHandshake_GetBytesToSend(SHSHandshake *h) {
    auto buf = internal(h)->bytesToSend();
    return {buf.first, buf.second};
}


void SHSHandshake_SendCompleted(SHSHandshake *h) {
    internal(h)->sendCompleted();
}


intptr_t SHSHandshake_CopyBytesToSend(SHSHandshake *h, void *dst, size_t capacity) {
    return internal(h)->copyBytesToSend(dst, capacity);
}


SHSError SHSHandshake_GetError(SHSHandshake *h) {
    return SHSError(internal(h)->error());
}


bool SHSHandshake_Finished(SHSHandshake *h) {
    return internal(h)->finished();
}


SHSSession SHSHandshake_GetSession(SHSHandshake *h) {
    Session s = internal(h)->session();
    return (SHSSession&)s;
}

