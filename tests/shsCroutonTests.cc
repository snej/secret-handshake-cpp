//
// shsCroutonTests.cc
//
// Copyright © 2023 Jens Alfke. All rights reserved.
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

#include "SecretHandshakeStream.hh"
#include "crouton/Crouton.hh"
#include <iostream>

#include "catch.hpp"

using namespace std;
using namespace snej::shs;
using namespace ::crouton;


template <typename FN>
static void RunCoroutine(FN test) {
    Future<void> f = test();
    Scheduler::current().runUntil([&]{return f.hasResult();});
    f.result(); // check exception
}


TEST_CASE("SecretHandshakeStream", "[SecretHandshake]") {
    using SecretHandshakeStream = snej::shs::crouton::SecretHandshakeStream;

    RunCoroutine([&]() -> Future<void> {
        AppID app          = Context::appIDFromString("SecretHandshakeStream");
        KeyPair clientKeys = KeyPair::generate();
        KeyPair serverKeys = KeyPair::generate();
        Context clientCtx {app, clientKeys};
        Context serverCtx {app, serverKeys};
        auto [clientSock, serverSock] = io::LocalSocket::createPair();

        SecretHandshakeStream clientStream(clientSock, clientCtx, &serverKeys.publicKey);
        SecretHandshakeStream serverStream(serverSock, serverCtx, nullptr);

        auto f1 = clientStream.open();
        auto f2 = serverStream.open();
        AWAIT f1;
        AWAIT f2;

        CHECK(clientStream.peerPublicKey() == serverKeys.publicKey);
        CHECK(serverStream.peerPublicKey() == clientKeys.publicKey);

        AWAIT clientStream.write(ConstBytes("Howdy neighbor"));
        string gotString = AWAIT serverStream.readString(14);
        CHECK(gotString == "Howdy neighbor");

        AWAIT clientStream.close();
        AWAIT serverStream.close();
        RETURN noerror;
    });
}
