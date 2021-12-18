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
extern "C" {
    #include "shs1.h"
}
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

    // Make sure the wrapper types are the correct size:
    static_assert(sizeof(PublicKey)     == crypto_sign_PUBLICKEYBYTES);
    static_assert(sizeof(SecretKey)     == crypto_sign_SECRETKEYBYTES);
    static_assert(sizeof(SecretKeySeed) == crypto_sign_SEEDBYTES);
    static_assert(sizeof(SessionKey)    == crypto_secretbox_KEYBYTES);
    static_assert(sizeof(Nonce)         == crypto_secretbox_NONCEBYTES);


    static void INIT() {
        static std::once_flag flag;
        std::call_once(flag, [] {
            if (::sodium_init() != 0)
                throw std::runtime_error("Error initializing crypto (libsodium)");
        });
    }


    static void check(int naResult) {
        if (naResult != 0)
            throw std::runtime_error("Crypto error from libsodium");
    }


    SecretKey::~SecretKey() {
        ::sodium_memzero(this, sizeof(this));
    }

    SecretKey::SecretKey(SecretKeySeed const& seed) {
        INIT();
        PublicKey publicKey; // unused
        check(::crypto_sign_seed_keypair(publicKey.data(), data(), seed.data()));
    }
    

    SecretKey SecretKey::generate() {
        INIT();
        SecretKey keyPair;
        PublicKey publicKey; // unused
        check(::crypto_sign_keypair(publicKey.data(), keyPair.data()));
        return keyPair;
    }


    PublicKey SecretKey::publicKey() const {
        PublicKey result;
        check(::crypto_sign_ed25519_sk_to_pk(result.data(), data()));
        return result;
    }


    SecretKeySeed SecretKey::seed() const {
        SecretKeySeed result;
        check(::crypto_sign_ed25519_sk_to_seed(result.data(), data()));
        return result;
    }


    AppID Context::appIDFromString(const char *str) {
        AppID id;
        ::strncpy((char*)&id, str, sizeof(id));
        return id;
        // (Yes, the call to strncpy is safe. It copies `str` into the buffer `id` and zeroes the
        // rest. If `str` is too long to fit it does not zero-terminate, but that isn't a problem
        // because `AppID` isn't a string and doesn't need to end with a 00.)
    }


#pragma mark - HANDSHAKE:


    Handshake::Handshake(Context const& context, size_t stateSize)
    :_context(context)
    ,_publicKey(context.keyPair.publicKey())
    ,_state(std::make_unique<uint8_t[]>(stateSize))
    {
        INIT();
        static_assert(sizeof(_ephemeralPublicKey) == crypto_box_PUBLICKEYBYTES);
        static_assert(sizeof(_ephemeralSecretKey) == crypto_box_SECRETKEYBYTES);
        check(::crypto_box_keypair(_ephemeralPublicKey.data(), _ephemeralSecretKey.data()));
    }


    Handshake::~Handshake() {
        ::sodium_memzero(&_ephemeralSecretKey, sizeof(_ephemeralSecretKey));
    }


    void Handshake::nextStep() {
        assert(_step > Failed && _step < Finished);
        _step = Step(_step + 1);
        if (_step == Finished)
            LOG "Success!\n";
    }


    std::pair<void*, size_t> Handshake::bytesToRead() {
        size_t needed = _byteCountNeeded();
        if (needed > 0)
            LOG "Step " << _step << "/4: Awaiting " << needed << " bytes...\n";
        _inputBuffer.resize(needed);
        return {_inputBuffer.data(), needed};
    }


    bool Handshake::readCompleted() {
        if (_inputBuffer.size() != _byteCountNeeded())
            throw std::logic_error("Unexpected call to Handshake::readCompleted");
        if (_receivedBytes(_inputBuffer.data()) > 0) {
            LOG "          ...OK!\n";
            nextStep();
            _inputBuffer.clear();
            return true;
        } else {
            LOG "          ...invalid data; HANDSHAKE FAILED\n";
            _step = Failed;
            return false;
        }
    }


    ssize_t Handshake::receivedBytes(const void *src, size_t count) {
        if (_step == Failed || _step == Finished)
            return -1;
        size_t needed = _byteCountNeeded();
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


    ssize_t Handshake::copyBytesToSend(void *dst, size_t maxCount) {
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
        SHS1_Outcome oc;
        _fillOutcome(&oc);
        Session session;
        session.encryptionKey   = *(SessionKey*)&oc.encryption_key;
        session.decryptionKey   = *(SessionKey*)&oc.decryption_key;
        session.encryptionNonce = *(Nonce*)&oc.encryption_nonce;
        session.decryptionNonce = *(Nonce*)&oc.decryption_nonce;
        session.peerPublicKey   = *(PublicKey*)&oc.peer_longterm_pk;
        return session;
    }


#pragma mark - CLIENT:


    #define _clientState() (SHS1_Client*)_state.get()


    ClientHandshake::ClientHandshake(Context const& context,
                                     PublicKey const& theirPublicKey)
    :Handshake(context, sizeof(SHS1_Client))
    ,_serverPublicKey(theirPublicKey)
    {
        ::shs1_init_client(_clientState(),
                           _context.appID.data(), _publicKey.data(), _context.keyPair.data(),
                           _ephemeralPublicKey.data(), _ephemeralSecretKey.data(),
                           _serverPublicKey.data());
    }


    ClientHandshake::~ClientHandshake() {
        ::shs1_client_clean(_clientState());
    }


    size_t ClientHandshake::_byteCountNeeded() {
        switch (_step) {
            case ServerChallenge:  return SHS1_SERVER_CHALLENGE_BYTES;
            case ServerAck:        return SHS1_SERVER_ACK_BYTES;
            default:                return 0;
        }
    }


    bool ClientHandshake::_receivedBytes(const uint8_t *bytes) {
        auto state = _clientState();
        switch (_step) {
            case ServerChallenge:  return ::shs1_verify_server_challenge(bytes, state);
            case ServerAck:        return ::shs1_verify_server_ack(bytes, state);
            default:               return false;
        }
    }


    void ClientHandshake::_fillOutputBuffer(std::vector<uint8_t> &output) {
        auto state = _clientState();
        switch (_step) {
            case ClientChallenge:
                output.resize(SHS1_CLIENT_CHALLENGE_BYTES);
                ::shs1_create_client_challenge(output.data(), state);
                break;
            case ClientAuth:
                output.resize(SHS1_CLIENT_AUTH_BYTES);
                ::shs1_create_client_auth(output.data(), state);
                break;
            default:
                break;
        }
    }


    void ClientHandshake::_fillOutcome(void *outcome) {
        ::shs1_client_outcome((SHS1_Outcome*)outcome, _clientState());
    }


#pragma mark - SERVER:


    #define _serverState() (SHS1_Server*)_state.get()


    ServerHandshake::ServerHandshake(Context const& context)
    :Handshake(context, sizeof(SHS1_Server))
    {
        ::shs1_init_server(_serverState(),
                           _context.appID.data(), _publicKey.data(), _context.keyPair.data(),
                           _ephemeralPublicKey.data(), _ephemeralSecretKey.data());
    }


    ServerHandshake::~ServerHandshake() {
        ::shs1_server_clean(_serverState());
    }


    size_t ServerHandshake::_byteCountNeeded() {
        switch (_step) {
            case ClientChallenge:  return SHS1_CLIENT_CHALLENGE_BYTES;
            case ClientAuth:       return SHS1_CLIENT_AUTH_BYTES;
            default:               return 0;
        }
    }


    bool ServerHandshake::_receivedBytes(const uint8_t *bytes) {
        auto state = _serverState();
        switch (_step) {
            case ClientChallenge:  return ::shs1_verify_client_challenge(bytes, state);
            case ClientAuth:       return ::shs1_verify_client_auth(bytes, state);
            default:               return false;
        }
    }


    void ServerHandshake::_fillOutputBuffer(std::vector<uint8_t> &output) {
        auto state = _serverState();
        switch (_step) {
            case ServerChallenge:
                output.resize(SHS1_SERVER_CHALLENGE_BYTES);
                ::shs1_create_server_challenge(output.data(), state);
                break;
            case ServerAck:
                output.resize(SHS1_SERVER_ACK_BYTES);
                ::shs1_create_server_ack(output.data(), state);
                break;
            default:
                break;
        }
    }


    void ServerHandshake::_fillOutcome(void *outcome) {
        ::shs1_server_outcome((SHS1_Outcome*)outcome, _serverState());
    }


#pragma mark - SESSION:


    Session::~Session() {
        ::sodium_memzero(this, sizeof(*this));
    }


    void Session::encrypt(void *outCiphertext, const void *cleartext, size_t size) const {
        check(::crypto_stream_xor((uint8_t*)outCiphertext, (const uint8_t*)cleartext, size,
                                  encryptionNonce.data(), encryptionKey.data()));
    }

    
    void Session::decrypt(void *outCleartext, const void *ciphertext, size_t size) const {
        check(::crypto_stream_xor((uint8_t*)outCleartext, (const uint8_t*)ciphertext, size,
                                  decryptionNonce.data(), decryptionKey.data()));
    }

}
