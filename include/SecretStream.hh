//
// SecretStream.hh
//
// Copyright © 2022 Jens Alfke. All rights reserved.
//

#pragma once
#include "SecretHandshake.hh"

namespace snej::shs {

    /// Points to immutable data to be encrypted or decrypted.
    struct input_data {
        const void* data;   ///< The address of the input data
        size_t      size;   ///< The length of the input data in bytes
    };


    /// Points to a mutable buffer for encrypted/decrypted data to be written to.
    struct output_buffer {
        void*       data;   ///< The address to write to
        size_t      size;   ///< On input, the capacity of the buffer; on output, the data size.
    };


    /// Success or failure status of a `CryptoBox` / `CryptoStream` operation.
    enum status {
        Success,            ///< Encryption/decryption succeeded
        OutTooSmall,        ///< The output's capacity is too small
        IncompleteInput,    ///< Need more input data to decrypt
        CorruptData         ///< The encrypted data is corrupted
    };



    /// Message-oriented encryption using keys & nonces from a Session;
    /// abstract base class of `EncryptoBox` and `DecryptoBox`.
    class CryptoBox {
    public:
        /// Data format to use for encrypted messages.
        enum Protocol {
            Compact,    ///< Less overhead, but message lengths are eavesdroppable.
            BoxStream   ///< Scuttlebutt-compatible. More overhead, but msg lengths are encrypted.
        };

        /// Returns the encrypted size of a message. (It will be somewhat larger than the input.)
        size_t encryptedSize(size_t inputSize);

        ~CryptoBox();

    protected:
        CryptoBox(SessionKey const& key, Nonce const& nonce, Protocol protocol =Compact)
        :_key(key)
        ,_nonce(nonce)
        ,_protocol(protocol)
        { }

        struct BoxStreamHeader;

        SessionKey const _key;
        Nonce            _nonce;
        Protocol const   _protocol;
    };



    /// Message-oriented encryption using keys & nonces from a Session.
    /// Encrypts a sequence of arbitrary-size blocks of data ("messages"). Each encrypted message
    /// is prefixed with its size and a MAC. The nonce is incremented after each message.
    ///
    /// `EncryptionStream` wraps this to provide a byte-oriented stream API.
    class EncryptoBox : public CryptoBox {
    public:
        /// Constructs an `EncryptoBox` from an encryption key and nonce.
        EncryptoBox(SessionKey const& key, Nonce const& nonce, Protocol protocol =Compact)
        :CryptoBox(key, nonce, protocol) { }

        explicit EncryptoBox(Session const& session, Protocol p =CryptoBox::Compact)
        :EncryptoBox(session.encryptionKey, session.encryptionNonce, p) { }

        /// The maximum byte length of a message, before encryption.
        static constexpr size_t kMaxMessageSize = 0xFFFF;

        /// Encrypts an outgoing message, attaching the MAC and size.
        /// @note  Currently the maximum size message is 65535 bytes.
        /// @param in  The message to be sent.
        /// @param out  Where to write the encrypted message.
        ///             On entry `out.data` must be set and `out.size` must be the maximum capacity.
        ///             On success, `out.size` will be set to the encrypted size.
        /// @return  The status, either `Success` or `OutTooSmall`.
        status encrypt(input_data in, output_buffer &out);
    };


    /// Message-oriented decryption using keys & nonces from a Session:
    /// Decrypts _entire messages_ created by `EncryptoBox`, in the same order they were created.
    /// Reads the message size so it knows how big the full message is, and indicates whether the
    /// message is incomplete.
    ///
    /// `DecryptionStream` wraps this to provide a byte-oriented stream API.
    class DecryptoBox : public CryptoBox {
        public:
        /// Constructs a `DecryptoBox` from an encryption key and nonce.
        DecryptoBox(SessionKey const& key, Nonce const& nonce, Protocol protocol =Compact)
        :CryptoBox(key, nonce, protocol) { }

        explicit DecryptoBox(Session const& session, Protocol p =CryptoBox::Compact)
        :DecryptoBox(session.decryptionKey, session.decryptionNonce, p) { }

        /// Returns the size of message that the input data will decrypt to, if known.
        /// The data doesn't need to contain a complete message, just the first few bytes.
        /// This can be used to ensure the output buffer passed to `decrypt` has enough capacity.
        /// The `status` value will be:
        /// - `Success` if the size is known; the `size_t` will be the decrypted message size.
        /// - `IncompleteInput` if there's not enough input to determine the size
        /// - `CorruptData` if the input data is corrupted
        std::pair<status, size_t> getDecryptedSize(input_data);

        /// Decrypts incoming data from the encrypted stream, reading the next message if it's
        /// completely available. This always reads one entire message, as passed to `encrypt`
        /// on the other end.
        ///
        /// If the input data is incomplete (doesn't contain the entire message), nothing is
        /// consumed and `IncompleteInput` is returned.
        ///
        /// If the output buffer is too small to hold the entire message, nothing is consumed
        /// and `OutTooSmall` is returned. You can then call `getDecryptedSize` to find out how big
        /// a buffer you need.
        ///
        /// If the input data contains more than just one message, the extra data is not
        /// consumed; `in.data` will be adjusted to point to the remaining data.
        ///
        /// After `Success` is returned, there could be another complete message remaining in the
        /// buffer, so you should call `decrypt` again (potentially multiple times.)
        ///
        /// @param in  Data from the stream. On success, **this will be adjusted** to account for
        ///            the bytes consumed: `data` will point to the first unread byte, and `size`
        ///            will be set to the number of remaining bytes.
        /// @param out  Where to write the decrypted message.
        ///             On input, its `data` must be set, and `size` must be the maximum capacity.
        ///             On success, its `size` will be set to the decrypted message's size.
        /// @return  The status; see the description of the 'status' enum values.
        status decrypt(input_data &in, output_buffer &out);

    private:
        std::pair<status, size_t> decryptBoxStreamHeader(input_data in, BoxStreamHeader &header);
    };



    /// Byte-oriented stream crypto API;
    /// abstract base class of EncryptionStream and DecryptionStream.
    class CryptoStream {
    public:
        using Protocol = CryptoBox::Protocol;

        /// Reads processed (encrypted or decrypted) data, copying it from the internal buffer.
        /// @param buffer  The address to copy data to
        /// @param maxSize  The maximum number of bytes to copy
        /// @return  The number of bytes copied
        size_t pull(void *buffer, size_t maxSize);

        /// Similar to `pull` but doesn't copy the data; instead it returns a pointer and size.
        /// After you're done with the data, call `skip` to remove it from the buffer.
        /// @warning  The returned pointer is invalidated if you call `push`.
        input_data availableData() const        {return {_buffer.data(), _processedBytes};}

        /// Returns the number of bytes available to pull.
        size_t bytesAvailable() const           {return _processedBytes;}

        /// Removes processed data from the internal buffer. Usually called after `availableData`.
        size_t skip(size_t);

    protected:
        CryptoStream() = default;
        CryptoStream(const CryptoStream&) = delete;
        CryptoStream& operator=(const CryptoStream&) = delete;

        std::vector<uint8_t> _buffer;                // processed followed by unprocessed bytes
        size_t               _processedBytes = 0;    // # of bytes already encrypted/decrypted
    };



    /// Stream-oriented adapter for Session-based encryption.
    /// You _push_ cleartext bytes into it, and _pull_ encrypted bytes out of it.
    /// Pull doesn't have to keep up with push; data will be buffered as needed.
    class EncryptionStream : public CryptoStream {
    public:
        /// Constructs an EncryptionStream.
        EncryptionStream(SessionKey const& key, Nonce const& nonce, Protocol p =CryptoBox::Compact)
        :_encryptor(key, nonce, p) { }

        explicit EncryptionStream(Session const& session, Protocol p =CryptoBox::Compact)
        :_encryptor(session.encryptionKey, session.encryptionNonce, p) { }

        /// Encrypts data. The ciphertext is then available to pull.
        /// @param data  The address of the cleartext data to add
        /// @param size  The size of the data
        void push(const void *data, size_t size);

        /// Appends cleartext data to the internal buffer, but does not encrypt it yet.
        /// You can call this multiple times, then call `flush`.
        /// @param data  The address of the cleartext data to add
        /// @param size  The size of the data
        void pushPartial(const void *data, size_t size);

        /// Encrypts all data buffered by `pushPartial`, which is then available to pull.
        void flush();

    private:
        EncryptoBox _encryptor;
    };



    /// Stream-oriented adapter for Session-based decryption.
    /// You _push_ encrypted bytes into it from the network (or wherever),
    /// and _pull_ decrypted bytes out of it.
    /// Push and pull can run at different rates; data will be buffered as needed.
    class DecryptionStream : public CryptoStream {
    public:
        /// Constructs a DecryptionStream.
        DecryptionStream(SessionKey const& key, Nonce const& nonce, Protocol p =CryptoBox::Compact)
        :_decryptor(key, nonce, p) { }

        explicit DecryptionStream(Session const& session, Protocol p =CryptoBox::Compact)
        :_decryptor(session.decryptionKey, session.decryptionNonce, p) { }

        /// Adds encrypted data received from the sender.
        /// It will be internally buffered and decrypted.
        /// @note Pushing data doesn't guarantee there will be bytes to pull;
        ///       decryption only occurs when a complete encrypted block is received.
        /// @param data  The address of the encrypted data to add
        /// @param size  The size of the encrypted data
        /// @return  True on success, false if the data is corrupted.
        bool push(const void *data, size_t size);

    private:
        DecryptoBox _decryptor;
    };

}
