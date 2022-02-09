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

extern "C" {
#include "shs1.h"
}

#include <iostream>
#include "IOUtil.hh"

#include "catch.hpp"        // https://github.com/catchorg/Catch2

using namespace std;
using namespace snej::shs::impl;


TEST_CASE("shs Cpp vs C", "[SecretHandshake]") {
    REQUIRE(::sodium_init() == 0);

    signing_key clientSK = signing_key::generate(), serverSK = signing_key::generate(),
        clientEphSK = signing_key::generate(), serverEphSK = signing_key::generate();
    public_key  clientPK = clientSK.get_public_key(), serverPK = serverSK.get_public_key(),
        clientEphPK = clientEphSK.get_public_key(), serverEphPK = serverEphSK.get_public_key();

    uint8_t clientKeyPair[64];
    REQUIRE(::crypto_sign_keypair(clientPK.data(), clientKeyPair) == 0);
    REQUIRE(::crypto_sign_ed25519_sk_to_seed(clientSK.data(), clientKeyPair) == 0);
    uint8_t serverKeyPair[64];
    REQUIRE(::crypto_sign_keypair(serverPK.data(), serverKeyPair) == 0);
    REQUIRE(::crypto_sign_ed25519_sk_to_seed(serverSK.data(), serverKeyPair) == 0);

    REQUIRE(::crypto_box_keypair(clientEphPK.data(), clientEphSK.data()) == 0);
    REQUIRE(::crypto_box_keypair(serverEphPK.data(), serverEphSK.data()) == 0);

    app_id appID;
    strcpy((char*)&appID, "shsTests");

    cout << "Client pub key:     " << tendril::hexString(clientPK) << endl;
    cout << "Client sec key:     " << tendril::hexString(clientSK) << endl;
    cout << "Client eph pub key: " << tendril::hexString(clientEphPK) << endl;
    cout << "Client eph sec key: " << tendril::hexString(clientEphSK) << endl;
    cout << "Server pub key:     " << tendril::hexString(serverPK) << endl;
    cout << "Server sec key:     " << tendril::hexString(serverSK) << endl;
    cout << "Server eph pub key: " << tendril::hexString(serverEphPK) << endl;
    cout << "Server eph sec key: " << tendril::hexString(serverEphSK) << endl;


    handshake client(appID, clientSK, clientPK);
    client.setServerPublicKey(serverPK);
    client.setEphemeralKeys(clientEphSK, clientEphPK);
    handshake server(appID, serverSK, serverPK);
    server.setEphemeralKeys(serverEphSK, serverEphPK);

    SHS1_Client cClient;
    shs1_init_client(&cClient, appID.data(), clientPK.data(), clientKeyPair,
                     clientEphPK.data(), clientEphSK.data(), serverPK.data());
    SHS1_Server cServer;
    shs1_init_server(&cServer, appID.data(), serverPK.data(), serverKeyPair,
                     serverEphPK.data(), serverEphSK.data());

    cout << "\n1. Client Challenge\n";
    ChallengeData clientCh, cClientCh;
    clientCh = client.createChallenge();
    shs1_create_client_challenge(cClientCh.data(), &cClient);
    cout << "C++ client challenge: " << tendril::hexString(clientCh) << endl;
    cout << "C   client challenge: " << tendril::hexString(cClientCh) << endl;
    REQUIRE(clientCh == cClientCh);

    cout << "\n2. Verify Client Challenge\n";
    REQUIRE(server.verifyChallenge(clientCh));
    REQUIRE(shs1_verify_client_challenge(cClientCh.data(), &cServer));

    cout << "\n3. Server Challenge\n";
    ChallengeData serverCh, cServerCh;
    serverCh = server.createChallenge();
    shs1_create_server_challenge(cServerCh.data(), &cServer);
    cout << "C++ server challenge: " << tendril::hexString(serverCh) << endl;
    cout << "C   server challenge: " << tendril::hexString(cServerCh) << endl;
    REQUIRE(serverCh == cServerCh);

    cout << "\n4. Verify Server Challenge\n";
    REQUIRE(client.verifyChallenge(serverCh));
    REQUIRE(shs1_verify_server_challenge(cServerCh.data(), &cClient));

    cout << "\n4. Client Auth\n";
    ClientAuthData clientAuth, cClientAuth;
    clientAuth = client.createClientAuth();
    shs1_create_client_auth(cClientAuth.data(), &cClient);
    cout << "C++ client auth: " << tendril::hexString(clientAuth) << endl;
    cout << "C   client auth: " << tendril::hexString(cClientAuth) << endl;
    REQUIRE(clientAuth == cClientAuth);

    cout << "\n4. Verify Client Auth\n";
    REQUIRE(server.verifyClientAuth(clientAuth));
    REQUIRE(shs1_verify_client_auth(cClientAuth.data(), &cServer));

    cout << "\n5. Server Ack\n";
    ServerAckData serverAck, cServerAck;
    serverAck = server.createServerAck();
    shs1_create_server_ack(cServerAck.data(), &cServer);
    cout << "C++ server ack: " << tendril::hexString(serverAck) << endl;
    cout << "C   server ack: " << tendril::hexString(cServerAck) << endl;
    REQUIRE(serverAck == cServerAck);

    cout << "\n5. Verify Server Ack\n";
    REQUIRE(client.verifyServerAck(serverAck));
    REQUIRE(shs1_verify_server_ack(cServerAck.data(), &cClient));

    cout << "\n6. Outcomes\n";
    session_key clientEncKey, clientDecKey, serverEncKey, serverDecKey;
    nonce       clientEncNonce, clientDecNonce, serverEncNonce, serverDecNonce;
    public_key  clientPeerPubKey, serverPeerPubKey;

    client.getOutcome(clientEncKey, clientEncNonce, clientDecKey, clientDecNonce, clientPeerPubKey);
    server.getOutcome(serverEncKey, serverEncNonce, serverDecKey, serverDecNonce, serverPeerPubKey);

    SHS1_Outcome cClientOut, cServerOut;
    shs1_client_outcome(&cClientOut, &cClient);
    shs1_server_outcome(&cServerOut, &cServer);

    auto &cClientEncKey = *(session_key*)cClientOut.encryption_key;
    auto &cClientDecKey = *(session_key*)cClientOut.decryption_key;
    auto &cClientEncNonce = *(nonce*)cClientOut.encryption_nonce;
    auto &cClientDecNonce = *(nonce*)cClientOut.decryption_nonce;

    cout << "C++ client enc key: " << tendril::hexString(clientEncKey) << endl;
    cout << "C++ server dec key: " << tendril::hexString(serverDecKey) << endl;
    cout << "C   client enc key: " << tendril::hexString(cClientEncKey) << endl;

    cout << "C++ client enc non: " << tendril::hexString(clientEncNonce) << endl;
    cout << "C++ server dec non: " << tendril::hexString(serverDecNonce) << endl;
    cout << "C   client enc non: " << tendril::hexString(cClientEncNonce) << endl;

    cout << "C++ client dec key: " << tendril::hexString(clientDecKey) << endl;
    cout << "C++ server enc key: " << tendril::hexString(serverEncKey) << endl;
    cout << "C   client dec key: " << tendril::hexString(cClientDecKey) << endl;

    cout << "C++ client dec non: " << tendril::hexString(clientDecNonce) << endl;
    cout << "C++ server enc non: " << tendril::hexString(serverEncNonce) << endl;
    cout << "C   client dec non: " << tendril::hexString(cClientDecNonce) << endl;

    REQUIRE(clientEncKey == serverDecKey);
    REQUIRE(clientEncNonce == serverDecNonce);
    REQUIRE(clientDecKey == serverEncKey);
    REQUIRE(clientDecNonce == serverEncNonce);
    REQUIRE(serverPeerPubKey == clientPK);

    REQUIRE(clientEncKey == cClientEncKey);
    REQUIRE(clientEncNonce == cClientEncNonce);
    REQUIRE(clientDecKey == cClientDecKey);
    REQUIRE(clientDecNonce == cClientDecNonce);
}
