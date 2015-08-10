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

#include "ICMPPacket.h"
#if defined(Q_OS_WIN)
    #include <winsock2.h>
#elif defined(Q_OS_UNIX)
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

using namespace std;

ICMPPacket::ICMPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
            : PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    int type = (int)this->value->type,
        code = (int)this->value->code;

    this->headers.push_back({"Type", std::to_string(type)});
    this->headers.push_back({"Code", std::to_string(code)});

    this->setByTypes(type, code);
}

void ICMPPacket::setByTypes(int type, int code)
{
    switch(type)
    {
        case 0:
            this->info = "Echo Reply (Ping Reply)";
            break;
        case 3:
            switch(code)
            {

            }
            break;
        case 5:
        {
            this->info = "Redirect";
            switch(code)
            {
                case 0: this->info.append(" for Network"); break;
                case 1: this->info.append(" for Host"); break;
                case 2: this->info.append(" for Type of Service and Network"); break;
                case 3: this->info.append(" for Type of Service and Host"); break;
            }
            struct in_addr addr;
            addr.s_addr = this->value->un.gateway;
            this->headers.push_back({"Redirect to IP", inet_ntoa(addr)});
        }
            break;
        case 8:
            this->info = "Echo Request (Ping Request)";
            break;
        case 11:
            this->info = "Time exceeded";
            switch(code)
            {
                case 0: this->info.append(" - TTL exceeded in transit"); break;
                case 1: this->info.append(" - Fragment reassembly time exceeded"); break;
            }
            break;
    }
    this->headers.push_back({"ICMP Type", this->info});
}
