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

#ifndef IPPACKET_H_
#define IPPACKET_H_

#include <hs_advanced_packets.h>

#if defined(Q_OS_WIN)
    #include <winsock2.h>
#elif defined(Q_OS_UNIX)
    #include <netinet/in.h>
#endif

#pragma pack(push,1)
struct ip_hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t  ip_hl:4;	/* header length */
    uint8_t  ip_v:4;		/* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t  ip_v:4;		/* version */
    uint8_t  ip_hl:4;	/* header length */
#endif
    uint8_t  ip_tos;		/* type of service */
    uint16_t ip_len;	/* total length */
    uint16_t ip_id;		/* identification */
    uint16_t ip_off;	/* fragment offset field */
    uint8_t  ip_ttl;		/* time to live */
    uint8_t  ip_p;		/* protocol */
    uint16_t ip_sum;	/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};
#pragma pack(pop)

static_assert(sizeof(struct ip_hdr) == 20, "check struct");

using namespace hungry_sniffer;

class IPPacket : public PacketStructed<struct ip_hdr> {
    public:
        IPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~IPPacket() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();

#ifdef Q_OS_UNIX
        static int drop_srcIP(const Packet* packet, Option::disabled_options_t& options);
        static int drop_dstIP(const Packet* packet, Option::disabled_options_t& options);
        static bool undrop_IP(const void* data);
#endif
};

#endif /* IPPACKET_H_ */
