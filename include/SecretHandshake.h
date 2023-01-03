//
//  SecretHandshake.h
//
// Copyright © 2022 Jens Alfke. All rights reserved.
//

#pragma once
#ifndef SecretHandshake_h
#define SecretHandshake_h
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


    typedef struct { uint8_t bytes[32]; } SHSAppID;      ///< Arbitrary ID for your protocol
    typedef struct { uint8_t bytes[32]; } SHSPublicKey;  ///< A 256-bit Ed25519 public key.
    typedef struct { uint8_t bytes[32]; } SHSSigningKey; ///< A 256-bit Ed25519 private key.
    typedef struct { uint8_t bytes[32]; } SHSSessionKey; ///< A 256-bit random value for use as a key.
    typedef struct { uint8_t bytes[24]; } SHSNonce;      ///< A 192-bit random value for use as a nonce.

    void SHSErase(void *dst, size_t size);

#define SHSKey_Erase(KEY) SHSErase(&(KEY).bytes, sizeof(KEY))

    static inline void SHSSigningKey_Erase(SHSSigningKey *key)    {SHSKey_Erase(*key);}

    typedef struct {
        SHSSigningKey signingKey;
        SHSPublicKey  publicKey;
    } SHSKeyPair;

    /// Randomly generates a new key pair.
    SHSKeyPair SHSKeyPair_Generate(void);

    /// Reconstructs the public key of a KeyPair given the private signing key.
    SHSKeyPair SHSKeyPair_Regenerate(const SHSSigningKey*);

    /// Securely erases the private key of a key-pair.
    static inline void SHSKeyPair_Erase(SHSKeyPair *kp)    {SHSKey_Erase(kp->signingKey);}


    /// Initializes an AppID by copying up to the first 32 bytes of a string to it;
    /// if the string is shorter than 32 bytes, the rest is zeroed.
    SHSAppID SHSAppID_FromString(const char* str);


    /// Result of the secret handshake:
    /// * session encryption / decryption keys with nonces,
    /// * and the peer's long-term public key (which is news to the server, but not to the client.)
    /// You can use the keys and nonces with whatever symmetric cipher you want; they're effectively
    /// random data that happens to be known by both you and the peer after a successful handshake.
    typedef struct {
        SHSSessionKey  encryptionKey;          ///< The session encryption key
        SHSNonce       encryptionNonce;        ///< Nonce to use with the encryption key
        SHSSessionKey  decryptionKey;          ///< The session decryption key
        SHSNonce       decryptionNonce;        ///< Nonce to use with the decryption key
        SHSPublicKey   peerPublicKey;          ///< The peer's authenticated public key
    } SHSSession;

    /// Securely erases the memory occupied by a SHSSession. Call this when finished with it.
    static inline void SHSSession_Erase(SHSSession *s)    {SHSErase(s, sizeof(*s));}


    /// Points to immutable data to be sent, encrypted or decrypted.
    typedef struct {
        const void* src;    ///< The bytes received
        size_t size;        ///< Number of bytes received
    } SHSInputBuffer;

    /// Points to a mutable buffer for data received, encrypted or decrypted to be written to.
    typedef struct {
        void* dst;          ///< Where to write the bytes to send
        size_t size;        ///< Number of bytes available at `dst`
    } SHSOutputBuffer;

    typedef enum {
        SHSNoError,            ///< No error yet
        SHSProtocolError,      ///< The peer does not use SecretHandshake, or a different AppID.
        SHSAuthError,          ///< Server has different public key, or doesn't like the client's.
    } SHSError;


    /// Opaque reference to an object that runs the SecretHandshake protocol.
    typedef struct SHSHandshake SHSHandshake;

    /// Constructs a client-side handshake for making a connection to a server.
    /// @param appID  The application ID. Both server and client must use the same appID.
    /// @param keyPair  The client's public and private key.
    /// @param serverPublicKey  The server's identity. If this is incorrect the handshake fails.
    SHSHandshake* SHSHandshake_CreateClient(const SHSAppID *appID,
                                            const SHSKeyPair *keyPair,
                                            const SHSPublicKey *serverPublicKey);

    /// Constructs a server-side handshake for accepting a connection from a client.
    /// @param appID  The application ID. Both server and client must use the same appID.
    /// @param keyPair  The server's public and private key.
    SHSHandshake* SHSHandshake_CreateServer(const SHSAppID *appID,
                                            const SHSKeyPair *keyPair);

    /// Frees memory allocated by the handshake, and securely erases private keys.
    void SHSHandshake_Free(SHSHandshake*);

    /// Returns the number of bytes the handshake wants to read. May be 0.
    size_t SHSHandshake_GetBytesNeeded(SHSHandshake*);

    /// Returns a buffer to copy bytes received to. Its size is `GetBytesNeeded`.
    void* SHSHandshake_GetInputBuffer(SHSHandshake*);

    static inline SHSOutputBuffer SHSHandshake_GetBytesToRead(SHSHandshake *h) {
        SHSOutputBuffer buf = {SHSHandshake_GetInputBuffer(h), SHSHandshake_GetBytesNeeded(h)};
        return buf;
    }

    /// Call this after all bytes have been copied into the buffer returned by `GetInputBuffer`.
    /// @return  True if the data is valid, false if the handshake has failed.
    bool SHSHandshake_ReadCompleted(SHSHandshake*);

    /// Alternative read API; use instead of `GetInputBuffer`.
    /// Call this when data is received from the peer.
    /// @param src  The received data.
    /// @param count  The number of bytes received.
    /// @return  The number of bytes consumed by the protocol, or -1 on error.
    intptr_t SHSHandshake_ReceivedBytes(SHSHandshake*, const void *src, size_t count);

    /// Returns the current bytes to send, as a pointer and length.
    /// Call after creating the handshake, and after calling `receivedBytes`.
    /// The length will be 0 if there is nothing to send.
    SHSInputBuffer SHSHandshake_GetBytesToSend(SHSHandshake*);

    /// Call this after fully sending the bytes returned by bytesToSend().
    void SHSHandshake_SendCompleted(SHSHandshake*);

    /// Alternative sending API; use instead of `GetBytesToSend` and `SendCompleted`.
    /// Pass it a buffer and the buffer's size. It will copy any output to the buffer, and return the
    /// number of bytes to send.
    /// @param dst  The buffer to copy the bytes to.
    /// @param capacity  The number of bytes that can be written to your buffer.
    /// @return  The number of bytes written to the buffer. -1 on error.
    intptr_t SHSHandshake_CopyBytesToSend(SHSHandshake*, void *dst, size_t capacity);

    /// The current error. (If not `SHSNoError`, you should close the socket.)
    /// Check this after sending and receiving data.
    SHSError SHSHandshake_GetError(SHSHandshake*);

    /// True if the handshake is complete and successful.
    /// Check this after sending and receiving data.
    bool SHSHandshake_Finished(SHSHandshake*);

    /// After the handshake is finished, this returns the results to use for communication.
    SHSSession SHSHandshake_GetSession(SHSHandshake*);

#ifdef __cplusplus
}
#endif

#endif /* SecretHandshake_h */
