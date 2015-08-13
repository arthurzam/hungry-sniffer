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

#ifndef IPV6PACKET_H_
#define IPV6PACKET_H_

#include <hs_advanced_packets.h>

#if defined(Q_OS_WIN)
    #include <winsock2.h>
    #include <Ws2tcpip.h>
#elif defined(Q_OS_UNIX)
    #include <netinet/ip6.h>
#endif

#pragma pack(push,1)
struct ip6hdr
{
    union
    {
        struct ip6hdrctl
        {
            uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                       20 bits flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};
#pragma pack(pop)
static_assert(sizeof(struct ip6hdr) == 40, "check struct");

using namespace hungry_sniffer;

class IPv6Packet : public PacketStructed<struct ip6hdr> {
    public:
        IPv6Packet(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~IPv6Packet() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();

        static bool filter_dstIP(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_srcIP(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_follow(const Packet* packet, const std::vector<std::string>* res);

#ifdef Q_OS_UNIX
        static int drop_srcIP(const Packet* packet, Option::disabled_options_t& options);
        static int drop_dstIP(const Packet* packet, Option::disabled_options_t& options);
        static bool undrop_IP(const void* data);
#endif
};

#endif /* IPV6PACKET_H_ */
