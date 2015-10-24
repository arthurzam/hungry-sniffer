/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef HTTPPACKET_H_
#define HTTPPACKET_H_

#include <hs_advanced_packets.h>

using namespace hungry_sniffer;

class HTTPPacket : public PacketTextHeaders {
    private:
        enum FLAGS {
            FLAGS_REQUEST = 0x1,
            FLAGS_DATA_START = 0x2,
            FLAGS_DATA_END = 0x4
        };

        HTTPPacket* prevData;
        HTTPPacket* nextData;
        uint8_t flags;

        bool parseContinuesData(headers_t& headers, const std::vector<char>& data);
    public:
        HTTPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        ~HTTPPacket() {}
        virtual const headers_t& getHeaders() const;
};

#endif /* HTTPPACKET_H_ */
