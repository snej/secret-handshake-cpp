//
// SecretHandshakeTests.cc
//
// Copyright © 2021 Jens Alfke. All rights reserved.
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

#include "SecretHandshake.hh"
#include "SecretStream.hh"
#include "monocypher/base.hh"
#include "hexString.hh"
#include <iostream>

#include "catch.hpp"

using namespace std;
using namespace snej::shs;


template <size_t SIZE>
static void randomize(std::array<uint8_t,SIZE> &array) {
    monocypher::randomize(array.data(), SIZE);
}


TEST_CASE("SecretKey", "[SecretHandshake]") {
    KeyPair kp = KeyPair::generate();
    PublicKey pk = kp.publicKey;
    SigningKey sk = kp.signingKey;

    KeyPair kp2 = KeyPair(sk);
    PublicKey pk2 = kp2.publicKey;
    CHECK(kp2 == kp);
    CHECK(pk2 == pk);
}


TEST_CASE("AppID", "[SecretHandshake]") {
    AppID id = Context::appIDFromString("");
    CHECK(hexString(id) == "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000");
    id = Context::appIDFromString("ABCDEF");
    CHECK(hexString(id) == "41424344 45460000 00000000 00000000 00000000 00000000 00000000 00000000");
    id = Context::appIDFromString("A string that is too long to fit in an AppID");
    CHECK(hexString(id) == "41207374 72696E67 20746861 74206973 20746F6F 206C6F6E 6720746F 20666974");
}


struct HandshakeTest {
    KeyPair serverKey, clientKey;
    ServerHandshake server;
    ClientHandshake client;

    HandshakeTest()
    :serverKey(KeyPair::generate())
    ,clientKey(KeyPair::generate())
    ,server({"App", serverKey})
    ,client({"App", clientKey}, serverKey.publicKey)
    { }

    bool sendFromTo(Handshake &src, Handshake &dst, size_t expectedCount) {
        // One step of the handshake:
        CHECK(src.bytesToRead().second == 0);
        CHECK(dst.bytesToSend().second == 0);
        auto toSend = src.bytesToSend();
        CHECK(toSend.second == expectedCount);
        auto toRead = dst.bytesToRead();
        CHECK(toRead.second == toSend.second);
        memcpy(toRead.first, toSend.first, toSend.second);
        dst.readCompleted();
        src.sendCompleted();
        return !src.failed() && !dst.failed();
    }
};


TEST_CASE_METHOD(HandshakeTest, "Handshake", "[SecretHandshake]") {
    // Run the handshake:
    REQUIRE(sendFromTo(client, server,  64));
    REQUIRE(sendFromTo(server, client,  64));
    REQUIRE(sendFromTo(client, server, 112));
    REQUIRE(sendFromTo(server, client,  80));

    REQUIRE(server.finished());
    REQUIRE(client.finished());

    // Check that they ended up with matching session keys, and each other's public keys:
    Session clientSession = client.session(), serverSession = server.session();
    CHECK(clientSession.encryptionKey   == serverSession.decryptionKey);
    CHECK(clientSession.encryptionNonce == serverSession.decryptionNonce);
    CHECK(clientSession.decryptionKey   == serverSession.encryptionKey);
    CHECK(clientSession.decryptionNonce == serverSession.encryptionNonce);

    CHECK(serverSession.peerPublicKey   == clientKey.publicKey);
    CHECK(clientSession.peerPublicKey   == serverKey.publicKey);
}


TEST_CASE_METHOD(HandshakeTest, "Handshake with wrong server key", "[SecretHandshake]") {
    // Create a client that has the wrong server public key:
    PublicKey badServerKey = serverKey.publicKey;
    badServerKey[17]++;
    ClientHandshake badClient({"App", clientKey}, badServerKey);

    // Run the handshake:
    CHECK(sendFromTo(badClient, server,  64));
    CHECK(sendFromTo(server, badClient,  64));
    CHECK(!sendFromTo(badClient, server, 112));
    CHECK(server.failed());
}


struct SessionTest {
    Session session1, session2;

    SessionTest() {
        randomize(session1.encryptionKey);
        randomize(session1.encryptionNonce);
        randomize(session1.decryptionKey);
        randomize(session1.decryptionNonce);

        session2.encryptionKey   = session1.decryptionKey;
        session2.encryptionNonce = session1.decryptionNonce;
        session2.decryptionKey   = session1.encryptionKey;
        session2.decryptionNonce = session1.encryptionNonce;
    }
};


using getSizeResult = std::pair<status, size_t>;


TEST_CASE_METHOD(SessionTest, "Encrypted Messages", "[SecretHandshake]") {
    auto protocol = GENERATE(CryptoBox::Compact, CryptoBox::BoxStream);
    EncryptoBox box1(session1, protocol);
    DecryptoBox box2(session2, protocol);
    cerr << "\t---- protocol=" << int(protocol) << endl;

    // Encrypt a message:
    constexpr const char *kCleartext = "Beware the ides of March. We attack at dawn.";
    input_data inClear = {kCleartext, strlen(kCleartext)};

    // Encrypt:
    uint8_t cipherBuf[256] = {};
    output_buffer outCipher = {cipherBuf, 0};
    CHECK(box1.encrypt(inClear, outCipher) == OutTooSmall);
    outCipher.size = inClear.size;
    CHECK(box1.encrypt(inClear, outCipher) == OutTooSmall);
    outCipher.size = box1.encryptedSize(inClear.size);
    CHECK(box1.encrypt(inClear, outCipher) == Success);
    CHECK(outCipher.data == cipherBuf);
    CHECK(outCipher.size == box1.encryptedSize(inClear.size));

    // Decrypt:
    uint8_t clearBuf[256] = {};
    CHECK(box2.getDecryptedSize({cipherBuf, 0}) == getSizeResult{IncompleteInput, 0});
    CHECK(box2.getDecryptedSize({cipherBuf, 1}) == getSizeResult{IncompleteInput, 0});
    if (protocol != CryptoBox::BoxStream) {
        CHECK(box2.getDecryptedSize({cipherBuf, 2}) == getSizeResult{Success, inClear.size});
    }
    CHECK(box2.getDecryptedSize({cipherBuf, sizeof(cipherBuf)}) == getSizeResult{Success, inClear.size});

    input_data inCipher = {cipherBuf, 0};
    output_buffer outClear = {clearBuf, sizeof(clearBuf)};
    CHECK(box2.decrypt(inCipher, outClear) == IncompleteInput);
    inCipher.size = 2;
    CHECK(box2.decrypt(inCipher, outClear) == IncompleteInput);
    inCipher.size = outCipher.size - 1;
    CHECK(box2.decrypt(inCipher, outClear) == IncompleteInput);
    inCipher.size = outCipher.size;
    CHECK(box2.decrypt(inCipher, outClear) == Success);
    CHECK(inCipher.size == 0);
    CHECK(inCipher.data == &cipherBuf[outCipher.size]);
    CHECK(outClear.data == clearBuf);
    CHECK(outClear.size == inClear.size);
    CHECK(memcmp(kCleartext, outClear.data, outClear.size) == 0);

    // Encrypt another message:
    constexpr const char *kMoreCleartext = "Alea jacta est";
    inClear = {kMoreCleartext, strlen(kMoreCleartext)};
    outCipher = {cipherBuf, sizeof(cipherBuf)};
    CHECK(box1.encrypt(inClear, outCipher) == Success);
    CHECK(outCipher.data == cipherBuf);
    CHECK(outCipher.size == box1.encryptedSize(inClear.size));

    // Decrypt it:
    inCipher = {cipherBuf, sizeof(cipherBuf)};
    outClear = {clearBuf, sizeof(clearBuf)};
    CHECK(box2.decrypt(inCipher, outClear) == Success);
    CHECK(inCipher.size == sizeof(cipherBuf) - outCipher.size);
    CHECK(inCipher.data == &cipherBuf[outCipher.size]);
    CHECK(outClear.data == clearBuf);
    CHECK(outClear.size == inClear.size);
    CHECK(memcmp(kMoreCleartext, outClear.data, outClear.size) == 0);
}


TEST_CASE_METHOD(SessionTest, "Encrypted Messages Overlapping Buffers", "[SecretHandshake]") {
    auto protocol = GENERATE(CryptoBox::Compact, CryptoBox::BoxStream);
    EncryptoBox box1(session1, protocol);
    DecryptoBox box2(session2, protocol);
    cerr << "\t---- protocol=" << int(protocol) << endl;

    // Check that it's OK to use the same buffer for the input and the output:
    constexpr const char *kCleartext = "Beware the ides of March. We attack at dawn.";
    char buffer[256];
    strcpy(buffer, kCleartext);
    input_data inClear = {buffer, strlen(kCleartext)};
    output_buffer outCipher = {buffer, sizeof(buffer)};
    CHECK(box1.encrypt(inClear, outCipher) == Success);

    if (protocol != CryptoBox::BoxStream) {
        CHECK(box2.getDecryptedSize({buffer, 2}) == getSizeResult{Success, inClear.size});
    }

    input_data inCipher = {buffer, sizeof(buffer)};
    output_buffer outClear = {buffer, sizeof(buffer)};
    CHECK(box2.decrypt(inCipher, outClear) == Success);
    CHECK(inCipher.size == sizeof(buffer) - outCipher.size);
    CHECK(inCipher.data == &buffer[outCipher.size]);
    CHECK(outClear.data == buffer);
    CHECK(outClear.size == inClear.size);
    CHECK(memcmp(kCleartext, outClear.data, outClear.size) == 0);
}


TEST_CASE_METHOD(SessionTest, "Decryption Stream", "[SecretHandshake]") {
    auto protocol = GENERATE(CryptoBox::Compact, CryptoBox::BoxStream);
    size_t kEncOverhead = 18 + (protocol == CryptoBox::BoxStream) * 16;
    cerr << "\t---- protocol=" << int(protocol) << endl;

    EncryptionStream enc(session1, protocol);
    DecryptionStream dec(session2, protocol);
    char cipherBuf[256], clearBuf[256];

    CHECK(dec.pull(clearBuf, sizeof(clearBuf)) == 0);

    auto transfer = [&](size_t nBytes) {
        nBytes = enc.pull(cipherBuf, nBytes);
        CHECK(dec.push(cipherBuf, nBytes));
    };

    // Encrypt a message:
    enc.pushPartial("Hel", 3);
    CHECK(enc.bytesAvailable() == 0);
    enc.pushPartial("lo", 2);
    CHECK(enc.bytesAvailable() == 0);
    enc.flush();
    CHECK(enc.bytesAvailable() == 5 + kEncOverhead);

    // Transfer it in two parts:
    transfer(10);
    CHECK(enc.bytesAvailable() == 5 + kEncOverhead - 10);
    CHECK(dec.bytesAvailable() == 0);
    transfer(100);
    CHECK(enc.bytesAvailable() == 0);
    CHECK(dec.bytesAvailable() == 5);

    // Read it:
    size_t bytesRead = dec.pull(clearBuf, sizeof(clearBuf));
    CHECK(bytesRead == 5);
    CHECK(memcmp(clearBuf, "Hello", 5) == 0);

    // Now add two encrypted mesages, but only transfer the first:
    enc.push(" there", 6);
    enc.pushPartial(", world", 7);
    transfer(100);
    enc.flush();
    CHECK(enc.bytesAvailable() == 7 + kEncOverhead);

    // Now read part of the first:
    CHECK(dec.bytesAvailable() == 6);
    size_t n = dec.pull(&clearBuf[bytesRead], 3);
    CHECK(n == 3);
    bytesRead += n;
    CHECK(memcmp(clearBuf, "Hello th", bytesRead) == 0);

    // Transfer the second:
    transfer(100);
    CHECK(enc.bytesAvailable() == 0);
    CHECK(dec.bytesAvailable() == 10);

    // Read the rest:
    n = dec.pull(&clearBuf[bytesRead], 100);
    CHECK(n == 10);
    bytesRead += n;
    CHECK(memcmp(clearBuf, "Hello there, world", bytesRead) == 0);
    CHECK(dec.pull(&clearBuf[bytesRead], 100) == 0);
    CHECK(dec.bytesAvailable() == 0);
}


TEST_CASE_METHOD(SessionTest, "Decryption Stream large data", "[SecretHandshake]") {
    auto protocol = GENERATE(CryptoBox::Compact, CryptoBox::BoxStream);
    size_t kEncOverhead = 18 + (protocol == CryptoBox::BoxStream) * 16;
    cerr << "\t---- protocol=" << int(protocol) << endl;

    EncryptionStream enc(session1, protocol);
    DecryptionStream dec(session2, protocol);

    static constexpr size_t kBufSize = 1000;
    array<char,kBufSize> cipherBuf, clearBuf;

    CHECK(dec.pull(clearBuf.data(), sizeof(clearBuf)) == 0);

    auto transfer = [&](size_t nBytes) {
        assert(nBytes <= kBufSize);
        nBytes = enc.pull(cipherBuf.data(), nBytes);
        CHECK(dec.push(cipherBuf.data(), nBytes));
    };

    static constexpr size_t kMessageSize = 100000;
    static_assert(kMessageSize > EncryptoBox::kMaxMessageSize);
    auto message = vector<char>(kMessageSize);
    monocypher::randomize(message.data(), message.size());
    size_t messagePos = 0;

    // Encrypt a 30,000-byte message:
    enc.pushPartial(&message[messagePos], 20000); messagePos += 20000;
    CHECK(enc.bytesAvailable() == 0);
    enc.pushPartial(&message[messagePos], 10000); messagePos += 10000;
    CHECK(enc.bytesAvailable() == 0);
    enc.flush();
    CHECK(enc.bytesAvailable() == 30000 + kEncOverhead);

    // Transfer it in two parts:
    for (int i = 0; i < 31; ++i)
        transfer(1000);
    CHECK(enc.bytesAvailable() == 0);
    CHECK(dec.bytesAvailable() == 30000);

    // Read it:
    auto gotMessage = vector<char>(100000);
    size_t bytesRead = dec.pull(gotMessage.data(), gotMessage.size());
    CHECK(bytesRead == 30000);
    CHECK(memcmp(gotMessage.data(), message.data(), bytesRead) == 0);

    // Encrypt the remaining 70,000 bytes at once, exceeding the max box size:
    static_assert(40000 + 30000 > EncryptoBox::kMaxMessageSize);
    enc.pushPartial(&message[messagePos], 40000); messagePos += 40000;
    CHECK(enc.bytesAvailable() == 0);
    enc.pushPartial(&message[messagePos], 30000); messagePos += 30000;
    REQUIRE(messagePos == message.size());
    //CHECK(enc.bytesAvailable() == 0);
    enc.flush();
    CHECK(enc.bytesAvailable() == 70000 + 2 * kEncOverhead);

    // Transfer it in parts:
    for (int i = 0; i < 71; ++i)
        transfer(1000);
    CHECK(enc.bytesAvailable() == 0);
    CHECK(dec.bytesAvailable() == 70000);

    // Read it:
    bytesRead = dec.pull(gotMessage.data(), gotMessage.size());
    CHECK(bytesRead == 70000);
    CHECK(memcmp(gotMessage.data(), &message[30000], bytesRead) == 0);
}
