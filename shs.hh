//
// shs.hh
//
// Copyright © 2022 Jens Alfke. All rights reserved.
//

#pragma once
#include "monocypher/encryption.hh"
#include "monocypher/signatures.hh"
#include "monocypher/ext/ed25519.hh"
#include "monocypher/ext/sha256.hh"
#include <optional>

#ifndef SHS_SCUTTLEBUTT_COMPATIBLE
/// If this is true, use XSalsa20 instead of XChaCha20, for compatibility with other
/// implementations of SecretHandshake.
#define SHS_SCUTTLEBUTT_COMPATIBLE 1
#endif

#if SHS_SCUTTLEBUTT_COMPATIBLE
#include "monocypher/ext/xsalsa20.hh"
#endif


namespace snej::shs::impl {
    template <size_t S> using byte_array = monocypher::byte_array<S>;

    // Types used by the handshake:

    using app_id         = byte_array<32>;

    using signing_key    = monocypher::signing_key<monocypher::Ed25519>;
    using public_key     = monocypher::public_key<monocypher::Ed25519>;
    using signature      = signing_key::signature;

    using ChallengeData  = byte_array<64>;
    using ClientAuthData = byte_array<112>;
    using ServerAckData  = byte_array<80>;

    using session_key    = monocypher::secret_byte_array<32>;
    using nonce          = byte_array<24>;

#if SHS_SCUTTLEBUTT_COMPATIBLE
    using box_key = monocypher::session::encryption_key<monocypher::ext::XSalsa20_Poly1305>;
#else
    using box_key = monocypher::session::key;
#endif


    /// Low-level implementation of SecretHandshake crypto operations.
    class handshake {
    public:
        handshake(app_id const& appID,
                  signing_key const& longTermSigningKey,
                  public_key const& longTermPublicKey);

        /// Setting custom ephemeral keys is optional; typically only done by unit tests.
        void setEphemeralKeys(signing_key const&, public_key const&);

        // The client must call these in order:

        void setServerPublicKey(public_key const&);
        ChallengeData createClientChallenge()               {return createChallenge();}
        bool verifyServerChallenge(ChallengeData const& c)  {return verifyChallenge(c);}
        ClientAuthData createClientAuth();
        bool verifyServerAck(ServerAckData const&);

        // The server must call these in order:

        bool verifyClientChallenge(ChallengeData const& c)  {return verifyChallenge(c);}
        ChallengeData createServerChallenge()               {return createChallenge();}
        bool verifyClientAuth(ClientAuthData const&);
        ServerAckData createServerAck();

        // Both client and server call this last, to get the session keys:
        void getOutcome(session_key &encryptionKey,
                        nonce       &encryptionNonce,
                        session_key &decryptionKey,
                        nonce       &decryptionNonce,
                        public_key  &peerPublicKey);


        // optional non-denominational names:
        ChallengeData createChallenge();
        bool verifyChallenge(ChallengeData const&);

        using key_exchange = monocypher::key_exchange<monocypher::X25519_Raw>;
        using kx_public_key = key_exchange::public_key;
        using kx_secret_key = key_exchange::secret_key;
        using kx_shared_secret = key_exchange::shared_secret;
        using sha256 = monocypher::ext::sha256;

    private:
        box_key clientAuthKey();
        box_key serverAckKey();

        // Input data. Here, 'x' means 'me' and 'y' means 'the peer'.
        app_id const                     _K;             // Application ID
        signing_key                      _X;             // My signing key (A or B)
        public_key                       _Xp;            // My public key (Ap or Bp)
        key_exchange                     _x;             // My ephemeral key-pair (a or b)
        kx_public_key                    _xp;            // My ephemeral public key (ap or bp)

        // These get set as the challenge progresses:
        std::optional<public_key>        _Yp;            // Peer's public key (Bp or Ap)
        std::optional<kx_public_key>     _yp;            // Peer's ephemeral public key (bp or ap)
        std::optional<kx_shared_secret>  _ab;            // _x * _yp, which is a·b on both sides
        std::optional<sha256>            _hashab;        // SHA256(a·b)
        std::optional<kx_shared_secret>  _aB;            // a·Bp, which is also B·ap
        std::optional<kx_shared_secret>  _Ab;            // A·bp, which is also b·Ap
        std::optional<box_key>           _serverAckKey;  // hash(K | a·b | a·B | A·b)
        std::optional<byte_array<96>>    _H;             // sign[A](K | Bp | hash(a·b)) | Ap
    };

}
