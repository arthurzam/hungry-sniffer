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

#ifndef ARPPACKET_H_
#define ARPPACKET_H_

#include <hs_advanced_packets.h>

#pragma pack(push,1)
struct arp_hdr
{
    uint16_t ar_hrd;	/* Format of hardware address.  */
    uint16_t ar_pro;	/* Format of protocol address.  */
    uint8_t ar_hln;		/* Length of hardware address.  */
    uint8_t ar_pln;		/* Length of protocol address.  */
    uint16_t ar_op;		/* ARP opcode (command).  */
};
#pragma pack(pop)

static_assert(sizeof(struct arp_hdr) == 8, "check struct");

using namespace hungry_sniffer;

class ArpPacket : public PacketStructed<struct arp_hdr> {
    private:
        #pragma pack(push,1)
        union {
            struct {
                uint8_t arp_sha[6]; /* Sender hardware address.  */
                uint8_t arp_sip[4]; /* Sender IP address.  */
                uint8_t arp_tha[6]; /* Target hardware address.  */
                uint8_t arp_tip[4]; /* Target IP address.  */
            } eth_ip;

            struct {
                uint8_t arp_sha[6]; /* Sender hardware address.  */
                uint8_t arp_sip[16];/* Sender IP address.  */
                uint8_t arp_tha[6]; /* Target hardware address.  */
                uint8_t arp_tip[16];/* Target IP address.  */
            } eth_ipv6;
        } data;
        #pragma pack(pop)
        unsigned size;

    public:
        ArpPacket(const void* data, size_t len, const Protocol* protocol,
                const Packet* prev);

        virtual ~ArpPacket() {}

        virtual unsigned getLength() const
        {
            return size;
        }
};

#endif /* ARPPACKET_H_ */
