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

#include "VRRPPacket.h"
#include <arpa/inet.h>

VRRPPacket::VRRPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    this->headers.push_back({"Type", std::to_string(this->value->type)});
    this->headers.push_back({"Version", std::to_string(this->value->version)});
    this->headers.push_back({"Virtual Router ID", std::to_string(this->value->vrid)});
    this->headers.push_back({"Priority", std::to_string(this->value->priority)});
    this->headers.push_back({"Address Count", std::to_string(this->value->naddr)});
    this->headers.push_back({"Authenticate Type", std::to_string(this->value->auth_type)});
    this->headers.push_back({"Advertisement Interval", std::to_string(this->value->adver_int)});

    const uint8_t* ip = (const uint8_t*)data + sizeof(this->value);
    char str[INET_ADDRSTRLEN];
    for(int i = 0; i < this->value->naddr; i++)
    {
        inet_ntop(AF_INET, ip, str, INET_ADDRSTRLEN);
        this->headers.push_back({"IP Address", str});
        ip += 4;
    }
}

unsigned VRRPPacket::getLength() const
{
    return sizeof(*value) + (this->value->naddr * 4);
}
