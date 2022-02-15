//
// shsTests.cc
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

#include "shs.hh"
#include "hexString.hh"
#include <iostream>
#include "catch.hpp"        // https://github.com/catchorg/Catch2

// `SHS_TESTS_COMPARE_C` controls whether to test that shs.cc produces the same results as an
// existing implementation, shs.c. It's enabled if predefined to 1, or if we can determine that
// libSodium is installed (since shs.c requires libSodium.)
#if !defined(SHS_TESTS_COMPARE_C)
#  define SHS_TESTS_COMPARE_C 0
#  if defined(__has_include)
#    if __has_include(<sodium.h>)
#      undef SHS_TESTS_COMPARE_C
#      define SHS_TESTS_COMPARE_C 1
#    endif
#  endif
#endif

#if SHS_TESTS_COMPARE_C
    extern "C" {
        #include "shs1.h"
    }
#endif


using namespace std;
using namespace snej::shs::impl;


TEST_CASE("shs Cpp vs C", "[SecretHandshake]") {
    signing_key clientSK = signing_key::generate(),   serverSK = signing_key::generate();
    public_key  clientPK = clientSK.get_public_key(), serverPK = serverSK.get_public_key();
    key_exchange clientEph, serverEph;

#if SHS_TESTS_COMPARE_C
    REQUIRE(::sodium_init() == 0);
    uint8_t clientKeyPair[64];
    REQUIRE(::crypto_sign_keypair(clientPK.data(), clientKeyPair) == 0);
    REQUIRE(::crypto_sign_ed25519_sk_to_seed(clientSK.data(), clientKeyPair) == 0);
    uint8_t serverKeyPair[64];
    REQUIRE(::crypto_sign_keypair(serverPK.data(), serverKeyPair) == 0);
    REQUIRE(::crypto_sign_ed25519_sk_to_seed(serverSK.data(), serverKeyPair) == 0);

    REQUIRE(::crypto_box_keypair(clientEph.get_public_key().data(),
                                 clientEph.get_secret_key().data()) == 0);
    REQUIRE(::crypto_box_keypair(serverEph.get_public_key().data(),
                                 serverEph.get_secret_key().data()) == 0);
#else
    cout << "** NOTE: Not comparing with shs-1 C implementation **\n";
#endif

    app_id appID;
    strcpy((char*)&appID, "shsTests");

    cout << "Client pub key:     " << hexString(clientPK) << endl;
    cout << "Client sec key:     " << hexString(clientSK) << endl;
    cout << "Client eph pub key: " << hexString(clientEph.get_public_key()) << endl;
    cout << "Client eph sec key: " << hexString(clientEph.get_secret_key()) << endl;
    cout << "Server pub key:     " << hexString(serverPK) << endl;
    cout << "Server sec key:     " << hexString(serverSK) << endl;
    cout << "Server eph pub key: " << hexString(serverEph.get_public_key()) << endl;
    cout << "Server eph sec key: " << hexString(serverEph.get_secret_key()) << endl;


    handshake client(appID, clientSK, clientPK);
    client.setServerPublicKey(serverPK);
    client.setEphemeralKeys(clientEph);
    handshake server(appID, serverSK, serverPK);
    server.setEphemeralKeys(serverEph);

#if SHS_TESTS_COMPARE_C
    auto clientEphPub = clientEph.get_public_key(), serverEphPub = serverEph.get_public_key();
    auto clientEphSec = clientEph.get_secret_key(), serverEphSec = serverEph.get_secret_key();
    SHS1_Client cClient;
    shs1_init_client(&cClient, appID.data(), clientPK.data(), clientKeyPair,
                     clientEphPub.data(), clientEphSec.data(), serverPK.data());
    SHS1_Server cServer;
    shs1_init_server(&cServer, appID.data(), serverPK.data(), serverKeyPair,
                     serverEphPub.data(), serverEphSec.data());
#endif

    cout << "\n1. Client Challenge\n";
    ChallengeData clientCh, cClientCh;
    clientCh = client.createChallenge();
    cout << "C++ client challenge: " << hexString(clientCh) << endl;
#if SHS_TESTS_COMPARE_C
    shs1_create_client_challenge(cClientCh.data(), &cClient);
    cout << "C   client challenge: " << hexString(cClientCh) << endl;
    REQUIRE(clientCh == cClientCh);
#endif

    cout << "\n2. Verify Client Challenge\n";
    REQUIRE(server.verifyChallenge(clientCh));
#if SHS_TESTS_COMPARE_C
    REQUIRE(shs1_verify_client_challenge(cClientCh.data(), &cServer));
#endif

    cout << "\n3. Server Challenge\n";
    ChallengeData serverCh, cServerCh;
    serverCh = server.createChallenge();
    cout << "C++ server challenge: " << hexString(serverCh) << endl;
#if SHS_TESTS_COMPARE_C
    shs1_create_server_challenge(cServerCh.data(), &cServer);
    cout << "C   server challenge: " << hexString(cServerCh) << endl;
    REQUIRE(serverCh == cServerCh);
#endif

    cout << "\n4. Verify Server Challenge\n";
    REQUIRE(client.verifyChallenge(serverCh));
#if SHS_TESTS_COMPARE_C
    REQUIRE(shs1_verify_server_challenge(cServerCh.data(), &cClient));
#endif

    cout << "\n4. Client Auth\n";
    ClientAuthData clientAuth, cClientAuth;
    clientAuth = client.createClientAuth();
    cout << "C++ client auth: " << hexString(clientAuth) << endl;
#if SHS_TESTS_COMPARE_C
    shs1_create_client_auth(cClientAuth.data(), &cClient);
    cout << "C   client auth: " << hexString(cClientAuth) << endl;
    REQUIRE(clientAuth == cClientAuth);
#endif

    cout << "\n4. Verify Client Auth\n";
    REQUIRE(server.verifyClientAuth(clientAuth));
#if SHS_TESTS_COMPARE_C
    REQUIRE(shs1_verify_client_auth(cClientAuth.data(), &cServer));
#endif

    cout << "\n5. Server Ack\n";
    ServerAckData serverAck, cServerAck;
    serverAck = server.createServerAck();
    cout << "C++ server ack: " << hexString(serverAck) << endl;
#if SHS_TESTS_COMPARE_C
    shs1_create_server_ack(cServerAck.data(), &cServer);
    cout << "C   server ack: " << hexString(cServerAck) << endl;
    REQUIRE(serverAck == cServerAck);
#endif

    cout << "\n5. Verify Server Ack\n";
    REQUIRE(client.verifyServerAck(serverAck));
#if SHS_TESTS_COMPARE_C
    REQUIRE(shs1_verify_server_ack(cServerAck.data(), &cClient));
#endif

    cout << "\n6. Outcomes\n";
    session_key clientEncKey, clientDecKey, serverEncKey, serverDecKey;
    nonce       clientEncNonce, clientDecNonce, serverEncNonce, serverDecNonce;
    public_key  clientPeerPubKey, serverPeerPubKey;

    client.getOutcome(clientEncKey, clientEncNonce, clientDecKey, clientDecNonce, clientPeerPubKey);
    server.getOutcome(serverEncKey, serverEncNonce, serverDecKey, serverDecNonce, serverPeerPubKey);

    cout << "C++ client enc key: " << hexString(clientEncKey) << endl;
    cout << "C++ server dec key: " << hexString(serverDecKey) << endl;
    cout << "C++ client enc non: " << hexString(clientEncNonce) << endl;
    cout << "C++ server dec non: " << hexString(serverDecNonce) << endl;
    cout << "C++ client dec key: " << hexString(clientDecKey) << endl;
    cout << "C++ server enc key: " << hexString(serverEncKey) << endl;
    cout << "C++ client dec non: " << hexString(clientDecNonce) << endl;
    cout << "C++ server enc non: " << hexString(serverEncNonce) << endl;

#if SHS_TESTS_COMPARE_C
    SHS1_Outcome cClientOut, cServerOut;
    shs1_client_outcome(&cClientOut, &cClient);
    shs1_server_outcome(&cServerOut, &cServer);

    auto &cClientEncKey = *(session_key*)cClientOut.encryption_key;
    auto &cClientDecKey = *(session_key*)cClientOut.decryption_key;
    auto &cClientEncNonce = *(nonce*)cClientOut.encryption_nonce;
    auto &cClientDecNonce = *(nonce*)cClientOut.decryption_nonce;

    cout << endl;
    cout << "C   client enc key: " << hexString(cClientEncKey) << endl;
    cout << "C   client enc non: " << hexString(cClientEncNonce) << endl;
    cout << "C   client dec key: " << hexString(cClientDecKey) << endl;
    cout << "C   client dec non: " << hexString(cClientDecNonce) << endl;

    REQUIRE(clientEncKey == cClientEncKey);
    REQUIRE(clientEncNonce == cClientEncNonce);
    REQUIRE(clientDecKey == cClientDecKey);
    REQUIRE(clientDecNonce == cClientDecNonce);
#endif

    REQUIRE(clientEncKey     == serverDecKey);
    REQUIRE(clientEncNonce   == serverDecNonce);
    REQUIRE(clientDecKey     == serverEncKey);
    REQUIRE(clientDecNonce   == serverEncNonce);
    REQUIRE(clientPK         == serverPeerPubKey);
}
