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

#ifndef UDPPACKET_H_
#define UDPPACKET_H_

#include <hs_advanced_packets.h>

#pragma pack(push,1)
struct udp_hdr
{
    uint16_t uh_sport; /* source port */
    uint16_t uh_dport; /* destination port */
    uint16_t uh_ulen;  /* udp length */
    uint16_t uh_sum;   /* udp checksum */
};
#pragma pack(pop)
static_assert(sizeof(struct udp_hdr) == 8, "check struct");

using namespace hungry_sniffer;

class UDPPacket: public PacketStructed<struct udp_hdr> {
    public:
        UDPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~UDPPacket() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();

        static bool filter_dstPort(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_srcPort(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_follow(const Packet* packet, const std::vector<std::string>* res);
};

#endif /* UDPPACKET_H_ */
