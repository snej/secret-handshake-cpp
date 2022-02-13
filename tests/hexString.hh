// hexString.hh
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

#include <array>
#include <string>


static inline std::string hexString(const void *buf, size_t size, bool spaces =false) {
    std::string hex;
    hex.resize(size * 2 + size / 4);
    char *dst = hex.data();
    for (size_t i = 0; i < size; i++) {
        if (spaces && i > 0 && (i % 4) == 0) 
        	*dst++ = ' ';
        dst += sprintf(dst, "%02X", ((const uint8_t*)buf)[i]);
    }
    hex.resize(dst - hex.data());
    return hex;
}


template <size_t Size>
static std::string hexString(const void *buf) {
    return hexString(buf, Size);
}


template <size_t Size>
static std::string hexString(const std::array<uint8_t,Size> &a) {
    return hexString<Size>(a.data());
}


