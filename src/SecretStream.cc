//
// SecretStream.cc
//
// Copyright © 2022 Jens Alfke. All rights reserved.
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

#include "SecretStream.hh"
#include "shs.hh"
#include "monocypher/encryption.hh"
#include <stdexcept>
#include <string.h>
#include <assert.h>


#define _UNUSED
#ifdef __has_attribute
#  if __has_attribute(unused)
#    undef _UNUSED
#    define _UNUSED __attribute__((unused))
#  endif
#endif


namespace snej::shs {
    using box_stream_key = monocypher::session::encryption_key<monocypher::ext::XSalsa20_Poly1305>;
    using compact_key    = monocypher::session::key;
    using session_nonce  = monocypher::session::nonce;

    static_assert(sizeof(SessionKey) == sizeof(box_stream_key));
    static_assert(sizeof(SessionKey) == sizeof(compact_key));
    static_assert(sizeof(Nonce)      == sizeof(session_nonce));

    using MAC               = monocypher::session::mac;

    struct CryptoBox::BoxStreamHeader {
        uint8_t size_be[2];
        MAC     mac;
    };


    static inline void writeUint16At(uint8_t *dst, size_t size) {
        assert (size <= 0xFFFF);
        dst[0] = (size >> 8) & 0xFF;
        dst[1] = size & 0xFF;
    }

    static inline size_t readUint16At(const uint8_t *src) {
        return (size_t(src[0]) << 8) | src[1];
    }


    size_t CryptoBox::encryptedSize(size_t inputSize) {
        static_assert(sizeof(CryptoBox::BoxStreamHeader) == 2 + sizeof(MAC));

        if (_protocol == BoxStream)
            return sizeof(BoxStreamHeader) + sizeof(MAC) + inputSize;
        else
            return 2 + sizeof(MAC) + inputSize;
    }


    CryptoBox::~CryptoBox() {
        monocypher::wipe((void*)&_key, sizeof(_key));
    }


    status EncryptoBox::encrypt(input_data in, output_buffer &out) {
        if (in.size > 0xFFFF)
            throw std::invalid_argument("CryptoBox message too large");
        size_t encSize = encryptedSize(in.size);
        if (out.size < encSize)
            return OutTooSmall;

        // Encrypt:
        out.size = encSize;
        auto dst = (uint8_t*)out.data;
        auto &nonce = (session_nonce&)_nonce;
        if (_protocol == BoxStream) {
            // Create a header buffer that starts with the cleartext length:
            auto &key = (const box_stream_key&)_key;
            BoxStreamHeader header;
            writeUint16At(header.size_be, in.size);
            // Encrypt the message. Ciphertext goes into `out`, MAC goes into the header:
            auto ciphertextp = dst + sizeof(header) + sizeof(MAC);
            header.mac = key.lock(nonce, {in.data, in.size}, ciphertextp);
            ++nonce;
            // Now encrypt the header and put it at the start of the output:
            key.box(nonce, {&header, sizeof(header)}, {dst, encSize});
            ++nonce;
        } else {
            // Simpler protocol -- just plaintext_size + box
            auto &key = (const compact_key&)_key;
            key.box(nonce, {in.data, in.size}, {dst + 2, encSize - 2});
            ++nonce;
            writeUint16At(dst, in.size);
        }
        return Success;
    }


    std::pair<status, size_t> DecryptoBox::decryptBoxStreamHeader(input_data in,
                                                                  BoxStreamHeader &header)
    {
        if (in.size < sizeof(MAC) + sizeof(header))
            return {IncompleteInput, 0};
        // The nonce has to be incremented first, because on the sending side the header was the
        // second thing to be encrypted. But leave the session's nonce alone for now.
        auto &key = (const box_stream_key&)_key;
        auto nonce = (session_nonce&)_nonce;
        ++nonce;
        auto out = key.unbox(nonce,
                             {in.data, sizeof(MAC) + sizeof(header)},
                             {&header, sizeof(header)});
        if (out.size != sizeof(header))
            return {CorruptData, 0};
        return {Success, readUint16At(header.size_be)};
    }


    std::pair<status, size_t> DecryptoBox::getDecryptedSize(input_data in) {
        if (_protocol == BoxStream) {
            BoxStreamHeader header;
            return decryptBoxStreamHeader(in, header);
        } else {
            if (in.size < 2)
                return {IncompleteInput, 0};
            return {Success, readUint16At((const uint8_t*)in.data)};
        }
    }


    status DecryptoBox::decrypt(input_data &in, output_buffer &out) {
        auto src = (const uint8_t*)in.data;
        status stat;
        size_t msgSize, encSize;
        auto &nonce = (session_nonce&)_nonce;
        if (_protocol == BoxStream) {
            BoxStreamHeader header;
            std::tie(stat, msgSize) = decryptBoxStreamHeader(in, header);
            if (stat != Success)
                return stat;
            encSize = encryptedSize(msgSize);
            if (in.size < encSize)
                return IncompleteInput;

            auto &key = (const box_stream_key&)_key;
            if (!key.unlock(nonce, header.mac,
                            {src + sizeof(MAC) + sizeof(header), msgSize},      // ciphertext
                            out.data))                                          // output plaintext
                return CorruptData;
            ++nonce; // extra increment due to 2nd decryption
        } else {
            std::tie(stat, msgSize) = getDecryptedSize(in);
            if (stat != Success)
                return stat;
            encSize = encryptedSize(msgSize);
            if (in.size < encSize)
                return IncompleteInput;
            if (out.size < msgSize)
                return OutTooSmall;

            auto &key = (const compact_key&)_key;
            if (key.unbox(nonce, {src + 2, encSize - 2}, {out.data, out.size}).size != msgSize)
                return CorruptData;
        }
        ++nonce;
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
        pushPartial(data, size);
        flush();
    }


    void EncryptionStream::pushPartial(const void *data, size_t size) {
        // Append data to the buffer. The unprocessed data can only grow to 64KB (kMaxMessageSize),
        // so if there's more data than that, flush periodically.
        auto begin = (const uint8_t*)data;
        while (size > 0) {
            size_t maxSize = EncryptoBox::kMaxMessageSize - (_buffer.size() - _processedBytes);
            size_t chunk = std::min(size, maxSize);
            _buffer.insert(_buffer.end(), begin, begin + chunk);
            size -= chunk;
            if (size > 0) {
                begin += chunk;
                flush();
            }
        }
    }


    void EncryptionStream::flush() {
        size_t msgSize = _buffer.size() - _processedBytes;
        if (msgSize > 0) {
            _buffer.resize(_processedBytes + _encryptor.encryptedSize(msgSize));
            input_data in = {&_buffer[_processedBytes], msgSize};
            output_buffer out = {(void*)in.data, _buffer.size() - _processedBytes};
            _UNUSED auto status = _encryptor.encrypt(in, out);
            assert(status == Success);
            _processedBytes += out.size;
            _buffer.resize(_processedBytes);
        }
    }


    bool DecryptionStream::push(const void *data, size_t size) {
        // Append data to the buffer:
        auto begin = (const uint8_t*)data;
        _buffer.insert(_buffer.end(), begin, begin + size);

        while (true) {
            // See if there's enough to decrypt:
            output_buffer out = {nullptr, _buffer.size() - _processedBytes};
            if (out.size > 0)
                out.data = &_buffer[_processedBytes];
            input_data in = {out.data, out.size};
            switch (_decryptor.decrypt(in, out)) {
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
