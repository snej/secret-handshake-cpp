//
//  SecretStream.h
//
//  Copyright © 2022 Jens Alfke. All rights reserved.
//

#ifndef SecretStream_h
#define SecretStream_h
#include "SecretHandshake.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    Compact,    ///< Less overhead, but message lengths are eavesdroppable.
    BoxStream   ///< Scuttlebutt-compatible. More overhead, but msg lengths are encrypted.
} SHSCryptoBoxProtocol;

typedef enum {
    Success,            ///< Encryption/decryption succeeded
    OutTooSmall,        ///< The output's capacity is too small
    IncompleteInput,    ///< Need more input data to decrypt
    CorruptData         ///< The encrypted data is corrupted
} SHSStatus;


//-------- ENCRYPTION:

/// Message-oriented encryption using keys & nonces from a Session.
/// Encrypts a sequence of arbitrary-size blocks of data ("messages"), to be written to a stream.
/// Each encrypted message is prefixed with its size and a MAC.
/// The nonce is incremented after each message.
typedef struct SHSEncryptoBox SHSEncryptoBox;

/// Constructs an `SHSEncryptoBox` from the encryption key and nonce of a SHSSession.
SHSEncryptoBox* SHSEncryptoBox_Create(const SHSSession *session, SHSCryptoBoxProtocol);

void SHSEncryptoBox_Free(SHSEncryptoBox*);

/// Returns the encrypted size of a message. (It will be somewhat larger than the input.)
size_t SHSEncryptoBox_GetEncryptedSize(SHSEncryptoBox*, size_t inputSize);

/// Encrypts an outgoing message, attaching the MAC and size.
/// @note  Currently the maximum size message is 65535 bytes.
/// @param in  The message to be sent.
/// @param out  Where to write the encrypted message.
///             On entry `out.data` must be set and `out.size` must be the maximum capacity.
///             On success, `out.size` will be set to the encrypted size.
/// @return  The status, either `Success` or `OutTooSmall`.
SHSStatus SHSEncryptoBox_Encrypt(SHSEncryptoBox*, SHSInputBuffer in, SHSOutputBuffer* out);


//-------- DECRYPTION:


/// Message-oriented decryption using keys & nonces from a Session:
/// Reads & decrypts _entire messages_ created by `EncryptoBox`, in the same order they were created.
/// Reads the message size so it knows how big the full message is, and indicates whether the
/// message is incomplete.
typedef struct SHSDecryptoBox SHSDecryptoBox;

typedef struct SHSPeekResult {
    SHSStatus status;
    size_t decryptedSize;
    size_t encryptedSize;
} SHSPeekResult;

/// Constructs an `SHSDecryptoBox` from the decryption key and nonce of a SHSSession.
SHSDecryptoBox* SHSDecryptoBox_Create(const SHSSession *session, SHSCryptoBoxProtocol);

void SHSDecryptoBox_Free(SHSDecryptoBox*);

/// Returns the minimum number of input bytes needed for `SHSDecryptoBox_Peek` to succeed.
size_t SHSDecryptoBox_MinPeekSize(SHSDecryptoBox*);

/// Looks at the input data (which must start on a message boundary but can be incomplete)
/// and returns the length of the encrypted and decrypted messages.
/// The `status` value will be:
/// - `Success` if the size is known; `encryptedSize` and `decryptedSize` will be accurate.
/// - `IncompleteInput` if there's not enough input to determine the size; `decryptedSize`
///   will be set to the length of input needed to determine it.
/// - `CorruptData` if the input data is corrupted
SHSPeekResult  SHSDecryptoBox_Peek(SHSDecryptoBox*, SHSInputBuffer);

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
SHSStatus SHSDecryptoBox_Decrypt(SHSDecryptoBox*, SHSInputBuffer *in, SHSOutputBuffer *out);


#ifdef __cplusplus
}
#endif

#endif /* SecretStream_h */
