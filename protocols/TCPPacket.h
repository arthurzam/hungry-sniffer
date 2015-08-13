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

#ifndef TCPPACKET_H_
#define TCPPACKET_H_

#include <hs_advanced_packets.h>

#pragma pack(push,1)
struct __attribute__((packed)) tcp_hdr
{
    uint16_t th_sport;		/* source port */
    uint16_t th_dport;		/* destination port */
    uint32_t th_seq;		/* sequence number */
    uint32_t th_ack;		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t th_off:4;		/* data offset */
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t th_off:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
    uint16_t th_win;		/* window */
    uint16_t th_sum;		/* checksum */
    uint16_t th_urp;		/* urgent pointer */
};
#pragma pack(pop)
static_assert(sizeof(struct tcp_hdr) == 20, "check struct");

using namespace hungry_sniffer;

class TCPPacket: public PacketStructed<struct tcp_hdr> {
    public:
        TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~TCPPacket() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();
        virtual unsigned getLength() const;

        static bool filter_dstPort(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_srcPort(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_follow(const Packet* packet, const std::vector<std::string>* res);
};

#endif /* TCPPACKET_H_ */
