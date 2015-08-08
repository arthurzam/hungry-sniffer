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

#ifndef VRRPPACKET_H_
#define VRRPPACKET_H_

#include "Protocol.h"

using namespace hungry_sniffer;

struct  __attribute__((packed)) vrrphdr {
#if BYTE_ORDER == BIG_ENDIAN
    unsigned char version :4; // type
    unsigned char type    :4; // version
#else
    unsigned char type    :4; // type
    unsigned char version :4; // version
#endif

    uint8_t  vrid;       /* virtual router id */
    uint8_t  priority;   /* router priority */
    uint8_t  naddr;      /* address counter */
    uint8_t  auth_type;  /* authentification type */
    uint8_t  adver_int;  /* advertisement interval(in sec) */
    uint16_t chksum;     /* checksum (ip-like one) */
    /* here <naddr> ip addresses */
    /* here authentification infos */
};

class VRRPPacket : public PacketStructed<struct vrrphdr> {
    public:
        VRRPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~VRRPPacket() {}
        virtual unsigned getLength() const;
};

#endif /* VRRPPACKET_H_ */
