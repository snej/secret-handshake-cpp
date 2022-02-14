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



    /// Message-oriented encryption using keys & nonces from a Session:
    /// - Encrypts a sequence of arbitrary-size blocks of data ("messages"). Each encrypted message
    ///   is prefixed with its size and a MAC.
    /// - Decrypts _entire messages_ in the same order they were sent. Reads the message size so it
    ///   knows how big the full message is, and indicates whether the message is incomplete.
    /// `EncryptionStream` and `DecryptionStream` wrap this to provide a byte-oriented stream API.
    class CryptoBox {
    public:
        /// Data format to use for encrypted messages.
        enum Protocol {
            Compact,    ///< Less overhead, but message lengths are eavesdroppable.
            BoxStream   ///< Scuttlebutt-compatible. More overhead, but msg lengths are encrypted.
        };

        enum status {
            Success,            ///< Encryption/decryption succeeded
            OutTooSmall,        ///< The output's capacity is too small
            IncompleteInput,    ///< Need more input data to decrypt
            CorruptData         ///< The encrypted data is corrupted
        };

        /// Constructs a CryptoBox on a Session.
        /// @note It keeps a pointer to the Session, which must remain valid.
        explicit CryptoBox(Session &session, Protocol protocol =Compact)
        :_session(session)
        ,_protocol(protocol)
        { }

        /// The maximum byte length of a message, before encryption.
        static constexpr size_t kMaxMessageSize = 0xFFFF;

        /// Returns the encrypted size of a message. (It will be somewhat larger than the input.)
        size_t encryptedSize(size_t inputSize);

        /// Encrypts an outgoing message, attaching the MAC and size.
        /// @note  Currently the maximum size message is 65535 bytes.
        /// @param in  The message to be sent.
        /// @param out  Where to write the encrypted message.
        ///             On entry `out.data` must be set and `out.size` must be the maximum capacity.
        ///             On success, `out.size` will be set to the encrypted size.
        /// @return  The status, either `Success` or `OutTooSmall`.
        status encrypt(input_data in, output_buffer &out);

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
        Session&       _session;
        Protocol const _protocol;
    };



    // Abstract base class of EncryptionStream and DecryptionStream.
    class CryptoStream : protected CryptoBox {
    public:
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
        explicit CryptoStream(Session &session, Protocol p) :CryptoBox(session, p) { }
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
        /// Constructs a DecryptionStream on a Session.
        /// @note It keeps a pointer to the Session, which must remain valid.
        explicit EncryptionStream(Session &session, CryptoBox::Protocol protocol =Compact)
        :CryptoStream(session, protocol) { }

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
    };



    /// Stream-oriented adapter for Session-based decryption.
    /// You _push_ encrypted bytes into it from the network (or wherever),
    /// and _pull_ decrypted bytes out of it.
    /// Push and pull can run at different rates; data will be buffered as needed.
    class DecryptionStream : public CryptoStream {
    public:
        /// Constructs a DecryptionStream on a Session.
        /// @note It keeps a pointer to the Session, which must remain valid.
        explicit DecryptionStream(Session &session, CryptoBox::Protocol protocol =Compact)
        :CryptoStream(session, protocol) { }

        /// Adds encrypted data received from the sender.
        /// It will be internally buffered and decrypted.
        /// @note Pushing data doesn't guarantee there will be bytes to pull;
        ///       decryption only occurs when a complete encrypted block is received.
        /// @param data  The address of the encrypted data to add
        /// @param size  The size of the encrypted data
        /// @return  True on success, false if the data is corrupted.
        bool push(const void *data, size_t size);
    };

}