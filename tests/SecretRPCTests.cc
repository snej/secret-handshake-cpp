//
// SecretRPCTests.cc
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

// NOTE: This tests the Cap'n Proto support code. The build scripts in this repo do not build
// or run this code, to avoid dragging in more dependencies that many users won't need.

#include "SecretConnection.hh"
#include "SecretRPC.hh"
#include <kj/async-io.h>
#include <iostream>

#include "catch.hpp"

using namespace std;
using namespace snej::shs;


class TestExceptionCallback : public kj::ExceptionCallback {
    virtual void onFatalException(kj::Exception&& exception) override {
        cerr << "FATAL: " << exception.getDescription().cStr() << endl;
    }
};


TEST_CASE("SecretConnection", "[SecretHandshake]") {
    bool successfulTest = GENERATE(true, false);
    cerr << (successfulTest ? "---- Successful connection\n" : "---- Failed connection\n");

    kj::_::Debug::setLogLevel(kj::LogSeverity::INFO);
    TestExceptionCallback xcb;

    static AppID kAppID = Context::appIDFromString("SecretRPCTests");
    Context clientContext{kAppID, KeyPair::generate()};
    Context serverContext{kAppID, KeyPair::generate()};
    auto serverKey = serverContext.keyPair.publicKey;
    if (!successfulTest)
        serverKey[8] ^= 0x40;
    ClientWrapper clientWrapper(clientContext, serverKey);
    ServerWrapper serverWrapper(serverContext, nullptr);
    clientWrapper.setIsSocket(false);
    serverWrapper.setIsSocket(false);

    kj::EventLoop loop;
    kj::WaitScope waitScope(loop);
    kj::TwoWayPipe pipe = kj::newTwoWayPipe();

    kj::Own<kj::AsyncIoStream> clientStream, serverStream;
    auto clientConn = clientWrapper.wrap(kj::mv(pipe.ends[0])).then([&](auto &&stream) {
        clientStream = kj::mv(stream);
        cerr << "Writing!\n";
        return clientStream->write("HELLO", 5);
    });

    char readBuf[100] = {};

    auto serverConn = serverWrapper.wrap(kj::mv(pipe.ends[1])).then([&](auto &&stream) {
        serverStream = kj::mv(stream);
        cerr<< "Reading...\n";
        return serverStream->read(readBuf, 5, 5);
    }) .then([&](size_t len) {
        CHECK(len == 5);
        CHECK(string(readBuf) == "HELLO");
    });

    if (successfulTest) {
        clientConn.wait(waitScope);
        serverConn.wait(waitScope);
        CHECK(string(readBuf) == "HELLO");
    } else {
        auto result = clientConn.then([] {return true;}, [](kj::Exception) {return false;});
        CHECK( result.wait(waitScope) == false );
        result = serverConn.then([] {return true;}, [](kj::Exception) {return false;});
        CHECK( result.wait(waitScope) == false );
    }
}
