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

#ifndef ICMPPACKET_H_
#define ICMPPACKET_H_

#include "Protocol.h"

#pragma pack(push,1)
struct icmp_hdr
{
    uint8_t type;		/* message type */
    uint8_t code;		/* type sub-code */
    uint16_t checksum;
    union
    {
        struct
        {
            uint16_t	id;
            uint16_t	sequence;
        } echo;			/* echo datagram */
        uint32_t	gateway;	/* gateway address */
        struct
        {
            uint16_t	__glibc_reserved;
            uint16_t	mtu;
        } frag;			/* path mtu discovery */
    } un;
};
#pragma pack(pop)
static_assert(sizeof(struct icmp_hdr) == 8, "check struct");

using namespace hungry_sniffer;

class ICMPPacket: public PacketStructed<struct icmp_hdr> {
    private:
        void setByTypes(int type, int code);
    public:
        ICMPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~ICMPPacket() {}
};

#endif /* ICMPPACKET_H_ */
