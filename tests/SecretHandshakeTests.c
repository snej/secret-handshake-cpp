//
// SecretHandshakeTests.c
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

#include "SecretHandshake.h"
#include "SecretStream.h"
#include <string.h>
#include <stdio.h>

bool test_C_Handshake(void);
bool test_C_HandshakeWrongServerKey(void);


static bool sTestResult;

#define CHECK(X)    if (!(X)) {sTestResult = false; \
                               fprintf(stderr, "CHECK failed: %s at line %d\n", #X, __LINE__);}
#define REQUIRE(X)  if (!(X)) {CHECK(X); return false;}

#define EqualStructs(A, B) (0 == memcmp(&(A), &(B), sizeof(A)))


typedef struct HandshakeTest {
    SHSAppID appID;
    SHSKeyPair serverKey, clientKey;
    SHSHandshake* server;
    SHSHandshake* client;
} HandshakeTest;


static void initHandshakeTest(HandshakeTest *test) {
    test->appID = SHSAppID_FromString("App");
    test->serverKey = SHSKeyPair_Generate();
    test->clientKey = SHSKeyPair_Generate();
    test->server = SHSHandshake_CreateServer(&test->appID, &test->serverKey);
    test->client = SHSHandshake_CreateClient(&test->appID, &test->clientKey, &test->serverKey.publicKey);
}

static void freeHandshakeTest(HandshakeTest *test) {
    SHSKeyPair_Erase(&test->serverKey);
    SHSKeyPair_Erase(&test->clientKey);
    SHSHandshake_Free(test->server);
    SHSHandshake_Free(test->client);
}

static bool sendFromTo(SHSHandshake *src, SHSHandshake *dst, size_t expectedCount) {
    // One step of the handshake:
    CHECK(SHSHandshake_GetBytesNeeded(src) == 0);
    CHECK(SHSHandshake_GetBytesToSend(dst).size == 0);
    SHSInputBuffer toSend = SHSHandshake_GetBytesToSend(src);
    CHECK(toSend.size == expectedCount);
    SHSOutputBuffer toRead = SHSHandshake_GetBytesToRead(dst);
    CHECK(toRead.size == toSend.size);
    memcpy(toRead.dst, toSend.src, toSend.size);
    SHSHandshake_ReadCompleted(dst);
    SHSHandshake_SendCompleted(src);
    return !SHSHandshake_GetError(src) && !SHSHandshake_GetError(dst);
}


bool test_C_Handshake(void) {
    sTestResult = true;
    HandshakeTest test;
    initHandshakeTest(&test);

    // Run the handshake:
    REQUIRE(sendFromTo(test.client, test.server,  64));
    REQUIRE(sendFromTo(test.server, test.client,  64));
    REQUIRE(sendFromTo(test.client, test.server, 112));
    REQUIRE(sendFromTo(test.server, test.client,  80));

    REQUIRE(SHSHandshake_Finished(test.server));
    REQUIRE(SHSHandshake_Finished(test.client));

    // Check that they ended up with matching session keys, and each other's public keys:
    SHSSession clientSession = SHSHandshake_GetSession(test.client);
    SHSSession serverSession = SHSHandshake_GetSession(test.server);
    CHECK(EqualStructs(clientSession.encryptionKey   , serverSession.decryptionKey));
    CHECK(EqualStructs(clientSession.encryptionNonce , serverSession.decryptionNonce));
    CHECK(EqualStructs(clientSession.decryptionKey   , serverSession.encryptionKey));
    CHECK(EqualStructs(clientSession.decryptionNonce , serverSession.encryptionNonce));

    CHECK(EqualStructs(serverSession.peerPublicKey   , test.clientKey.publicKey));
    CHECK(EqualStructs(clientSession.peerPublicKey   , test.serverKey.publicKey));

    SHSSession_Erase(&serverSession);
    SHSSession_Erase(&clientSession);
    freeHandshakeTest(&test);
    return sTestResult;
}


bool test_C_HandshakeWrongServerKey(void) {
    sTestResult = true;
    HandshakeTest test;
    initHandshakeTest(&test);
    
    // Create a client that has the wrong server public key:
    SHSPublicKey badServerKey = test.serverKey.publicKey;
    badServerKey.bytes[17]++;
    SHSHandshake* badClient = SHSHandshake_CreateClient(&test.appID, &test.clientKey, &badServerKey);

    // Run the handshake:
    REQUIRE(sendFromTo(badClient, test.server,  64));
    REQUIRE(sendFromTo(test.server, badClient,  64));
    REQUIRE(!sendFromTo(badClient, test.server, 112));
    REQUIRE(SHSHandshake_GetError(test.server) == SHSAuthError);

    SHSHandshake_Free(badClient);
    freeHandshakeTest(&test);
    return sTestResult;
}
