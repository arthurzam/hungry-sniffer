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

#include "ArpPacket.h"

#if defined(Q_OS_WIN)
    #include <winsock2.h>
    #include <Ws2tcpip.h>

    char *ether_ntoa (const uint8_t* n)
    {
        int i;
        static char a [18];

        i = sprintf (a, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
        if (i <11)
            return (NULL);
        return ((char *) &a);
    }
    typedef uint8_t ether_addr;

    #ifdef Q_CC_MINGW
    const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
    {
        if (af == AF_INET)
        {
            struct sockaddr_in in;
            memset(&in, 0, sizeof(in));
            in.sin_family = AF_INET;
            memcpy(&in.sin_addr, src, sizeof(struct in_addr));
            getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
            return dst;
        }
        else if (af == AF_INET6)
        {
            struct sockaddr_in6 in;
            memset(&in, 0, sizeof(in));
            in.sin6_family = AF_INET6;
            memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
            getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
            return dst;
        }
        return NULL;
    }

    #endif

#elif defined(Q_OS_UNIX)
    #include <arpa/inet.h>
    #include <netinet/ether.h>
#endif

ArpPacket::ArpPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    uint16_t arp_protocol = ntohs(this->value->ar_pro);
    uint16_t arp_format = ntohs(this->value->ar_hrd);
    this->headers.push_back({"Hardware Type", std::to_string(arp_format), 0, 2});
    this->headers.push_back({"Protocol Type", std::to_string(arp_protocol), 2, 2});
    this->headers.push_back({"Hardware Size", std::to_string(this->value->ar_hln), 4, 1});
    this->headers.push_back({"Protocol Size", std::to_string(this->value->ar_pln), 5, 1});

    if(ntohs(this->value->ar_op) == 1)
    {
        this->headers.push_back({"Type", "Request", 6, 2});
        this->info = "ARP Request";
    }
    else
    {
        this->headers.push_back({"Type", "Reply", 6, 2});
        this->info = "ARP Reply";
    }

    if(arp_format == 1 && (arp_protocol == 0x0800 || arp_protocol == 0x86dd))
    {
        size = (arp_protocol == 0x0800 ? sizeof(this->data.eth_ip) : sizeof(this->data.eth_ipv6));
        memcpy(&this->data, (const char*)data + sizeof(*value), size);
        size += sizeof(*value);

        char str[INET6_ADDRSTRLEN];
        if(arp_protocol == 0x0800)
        {
            this->headers.push_back({"Sender MAC Address", ether_ntoa((ether_addr*) this->data.eth_ip.arp_sha), 8, 6});
            this->headers.push_back({"Target MAC Address", ether_ntoa((ether_addr*) this->data.eth_ip.arp_tha), 18, 6});

            inet_ntop(AF_INET, &this->data.eth_ip.arp_sip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Sender IP Address" , str, 14, 4});
            inet_ntop(AF_INET, &this->data.eth_ip.arp_tip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Target IP Address" , str, 24, 4});
        }
        else
        {
            this->headers.push_back({"Sender MAC Address", ether_ntoa((ether_addr*) this->data.eth_ipv6.arp_sha), 8, 6});
            this->headers.push_back({"Target MAC Address", ether_ntoa((ether_addr*) this->data.eth_ipv6.arp_tha), 30, 6});

            inet_ntop(AF_INET6, &this->data.eth_ipv6.arp_sip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Sender IPv6 Address" , str, 14, 16});
            inet_ntop(AF_INET6, &this->data.eth_ipv6.arp_tip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Target IPv6 Address" , str, 36, 16});
        }
    }
}
