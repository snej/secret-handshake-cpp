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
#include <sodium.h>
#include <stdexcept>

namespace snej::shs {

    static_assert(sizeof(SessionKey) == crypto_secretbox_KEYBYTES);
    static_assert(sizeof(Nonce)      == crypto_secretbox_NONCEBYTES);

    using MAC               = std::array<uint8_t,crypto_secretbox_MACBYTES>;
    using BoxStreamHeader   = std::array<uint8_t,2+crypto_secretbox_MACBYTES>;


    static Nonce& operator++ (Nonce &nonce) {
        sodium_increment(nonce.data(), nonce.size());
        return nonce;
    }


    size_t CryptoBox::encryptedSize(size_t inputSize) {
#if BOXSTREAM_COMPATIBLE
        return sizeof(BoxStreamHeader) + sizeof(MAC) + inputSize;
#else
        return 2 + sizeof(MAC) + inputSize;
#endif
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
#if BOXSTREAM_COMPATIBLE
        // Create a header buffer that starts with the cleartext length:
        BoxStreamHeader header;
        header[0] = (in.size >> 8) & 0xFF;
        header[1] = in.size & 0xFF;
        // Encrypt the message. Ciphertext goes into `out`, MAC goes into the header:
        crypto_secretbox_detached(dst + sizeof(MAC) + sizeof(header), // ->ciphertext
                                  &header[2],                         // ->MAC
                                  (const uint8_t*)in.data, in.size,   // cleartext
                                  _session.encryptionNonce.data(),    // nonce
                                  _session.encryptionKey.data());     // key
        ++_session.encryptionNonce;
        // Now encrypt the header and put it at the start of the output:
        crypto_secretbox_easy(dst,                                    // ->ciphertext
                              header.data(), header.size(),           // cleartext
                              _session.encryptionNonce.data(),        // nonce
                              _session.encryptionKey.data());         // key
        ++_session.encryptionNonce;
#else
        crypto_secretbox_easy(dst + 2,                                // ->ciphertext
                              (const uint8_t*)in.data, in.size,       // cleartext
                              _session.encryptionNonce.data(),        // nonce
                              _session.encryptionKey.data());         // key
        ++_session.encryptionNonce;

        // Now write the byte count at the start:
        encSize -= 2;  // don't include the size of the byte-count in the byte-count
        dst[0] = (encSize >> 8) & 0xFF;
        dst[1] = encSize & 0xFF;
#endif
        return Success;
    }


#if BOXSTREAM_COMPATIBLE
    static std::pair<CryptoBox::status, size_t> decryptBoxStreamHeader(input_data in,
                                                              BoxStreamHeader &header,
                                                              const Session &session)
    {
        if (in.size < sizeof(MAC) + sizeof(header))
            return {CryptoBox::IncompleteInput, 0};
        // The nonce has to be incremented, because on the sending side the header was the
        // second thing to be encrypted. But leave the session's nonce alone for now.
        Nonce nonce = session.decryptionNonce;
        ++nonce;
        if (0 != crypto_secretbox_open_easy(header.data(),
                                            (const uint8_t*)in.data,
                                            sizeof(MAC) + sizeof(header),
                                            nonce.data(),
                                            session.decryptionKey.data()))
            return {CryptoBox::CorruptData, 0};
        return {CryptoBox::Success, (size_t(header[0]) << 8) | header[1]};
    }
#endif


    std::pair<CryptoBox::status, size_t> CryptoBox::getDecryptedSize(input_data in) {
#if BOXSTREAM_COMPATIBLE
        BoxStreamHeader header;
        return decryptBoxStreamHeader(in, header, _session);
#else
        if (in.size < 2)
            return {IncompleteInput, 0};
        auto src = (const uint8_t*)in.data;
        size_t boxSize = (size_t(src[0]) << 8) | src[1];
        if (boxSize < sizeof(MAC))
            return {CorruptData, 0};
        return {Success, boxSize - sizeof(MAC)};
#endif
    }


    CryptoBox::status CryptoBox::decrypt(input_data &in, output_buffer &out) {
        auto src = (const uint8_t*)in.data;
#if BOXSTREAM_COMPATIBLE
        BoxStreamHeader header;
        auto [stat, msgSize] = decryptBoxStreamHeader(in, header, _session);
        if (stat != Success)
            return stat;
        size_t encSize = encryptedSize(msgSize);
        if (in.size < encSize)
            return IncompleteInput;
        if (0 != crypto_secretbox_open_detached((uint8_t*)out.data,                // ->output
                                                src + sizeof(MAC) + sizeof(header),// ciphertext
                                                &header[2],                        // MAC
                                                msgSize,                           // ciphertext len
                                                _session.decryptionNonce.data(),   // nonce
                                                _session.decryptionKey.data()))    // key
            return CorruptData;
        ++_session.decryptionNonce; // extra increment due to 2nd decryption
#else
        auto [status, msgSize] = getDecryptedSize(in);
        if (status != Success)
            return status;
        size_t encSize = encryptedSize(msgSize);
        if (in.size < encSize)
            return IncompleteInput;
        if (out.size < msgSize)
            return OutTooSmall;

        if (0 != crypto_secretbox_open_easy((uint8_t*)out.data,                 // ->output
                                            src + 2, encSize - 2,               // ciphertext, size
                                            _session.decryptionNonce.data(),    // nonce
                                            _session.decryptionKey.data()))     // key
            return CorruptData;
#endif
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
        pushPartial(data, size);
        flush();
    }


    void EncryptionStream::pushPartial(const void *data, size_t size) {
        // Append data to the buffer:
        auto begin = (const uint8_t*)data;
        _buffer.insert(_buffer.end(), begin, begin + size);
    }


    void EncryptionStream::flush() {
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
