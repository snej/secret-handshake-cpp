//
// SecretStream.cc
//
// Copyright © 2022 Jens Alfke. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "SecretStream.hh"
#include <sodium.h>
#include <stdexcept>

namespace snej::shs {

    static_assert(sizeof(SessionKey) == crypto_secretbox_KEYBYTES);
    static_assert(sizeof(Nonce)      == crypto_secretbox_NONCEBYTES);


    static Nonce& operator++ (Nonce &nonce) {
        sodium_increment(nonce.data(), nonce.size());
        return nonce;
    }


    size_t CryptoBox::encryptedSize(size_t inputSize) {
        return 2 + crypto_secretbox_MACBYTES + inputSize;
    }


    CryptoBox::status CryptoBox::encrypt(input_data in, output_buffer &out) {
        if (in.size > 0xFFFF)
            throw std::invalid_argument("CryptoBox message too large");
        size_t encSize = encryptedSize(in.size);
        if (out.size < encSize)
            return OutTooSmall;

        // Encrypt:
        out.size = encSize;
        auto dst = (uint8_t*)out.data;
        crypto_secretbox_easy(dst + 2,
                              (const uint8_t*)in.data, in.size,
                              _session.encryptionNonce.data(),
                              _session.encryptionKey.data());
        ++_session.encryptionNonce;

        // Now write the byte count at the start:
        encSize -= 2;  // don't include the size of the byte-count in the byte-count
        dst[0] = (encSize >> 8) & 0xFF;
        dst[1] = encSize & 0xFF;
        return Success;
    }


    std::pair<CryptoBox::status, size_t> CryptoBox::getDecryptedSize(input_data in) {
        if (in.size < 2)
            return {IncompleteInput, 0};
        auto src = (const uint8_t*)in.data;
        size_t boxSize = (size_t(src[0]) << 8) | src[1];
        if (boxSize < crypto_secretbox_MACBYTES)
            return {CorruptData, 0};
        return {Success, boxSize - crypto_secretbox_MACBYTES};
    }


    CryptoBox::status CryptoBox::decrypt(input_data &in, output_buffer &out) {
        auto [status, msgSize] = getDecryptedSize(in);
        if (status != Success)
            return status;
        size_t encSize = encryptedSize(msgSize);
        if (in.size < encSize)
            return IncompleteInput;
        if (out.size < msgSize)
            return OutTooSmall;

        auto src = (const uint8_t*)in.data;
        if (0 != crypto_secretbox_open_easy((uint8_t*)out.data,
                                            src + 2, encSize - 2,   // skip the byte-count
                                            _session.decryptionNonce.data(),
                                            _session.decryptionKey.data()))
            return CorruptData;
        ++_session.decryptionNonce;
        out.size = msgSize;
        in.data = src + encSize;
        in.size -= encSize;
        return Success;
    }


#pragma mark - CRYPTOSTREAM:


    size_t CryptoStream::skip(size_t maxSize) {
        size_t n = std::min(maxSize, _processedBytes);
        if (n > 0) {
            _buffer.erase(_buffer.begin(), _buffer.begin() + n);
            _processedBytes -= n;
        }
        return n;
    }


    size_t CryptoStream::pull(void *dst, size_t dstSize) {
        auto avail = availableData();
        avail.size = std::min(avail.size, dstSize);
        if (avail.size > 0) {
            memcpy(dst, avail.data, avail.size);
            skip(avail.size);
        }
        return avail.size;
    }


    void EncryptionStream::push(const void *data, size_t size) {
        // Append data to the buffer:
        auto begin = (const uint8_t*)data;
        _buffer.insert(_buffer.end(), begin, begin + size);
    }


    void EncryptionStream::endMessage() {
        size_t msgSize = _buffer.size() - _processedBytes;
        _buffer.resize(_processedBytes + encryptedSize(msgSize));
        input_data in = {&_buffer[_processedBytes], msgSize};
        output_buffer out = {(void*)in.data, _buffer.size() - _processedBytes};
        auto status = encrypt(in, out);
        assert(status == Success);
        _processedBytes += out.size;
        _buffer.resize(_processedBytes);
    }


    bool DecryptionStream::push(const void *data, size_t size) {
        // Append data to the buffer:
        auto begin = (const uint8_t*)data;
        _buffer.insert(_buffer.end(), begin, begin + size);

        while (true) {
            // See if there's enough to decrypt:
            output_buffer out = {&_buffer[_processedBytes],
                                 _buffer.size() - _processedBytes};
            input_data in = {out.data, out.size};
            switch (decrypt(in, out)) {
                case Success:
                    _processedBytes += out.size;
                    // Decrypting the data shortened it, so cut out the remaining space:
                    _buffer.erase(_buffer.begin() + _processedBytes,
                                  _buffer.begin() + ((uint8_t*)in.data - _buffer.data()));
                    // Continue the `while` loop, in case there's another complete message:
                    break;
                case IncompleteInput:
                    return true;    // Done
                case CorruptData:
                    return false;   // Failure
                case OutTooSmall:
                    throw std::logic_error("DecryptionStream failure"); // impossible
            }
        }
    }


}
