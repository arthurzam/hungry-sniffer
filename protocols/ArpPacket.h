#ifndef ARPPACKET_H_
#define ARPPACKET_H_

#include "Protocol.h"
#include <net/if_arp.h>
#include <iostream>

using namespace hungry_sniffer;

class ArpPacket : public PacketStructed<struct arphdr> {
    public:
        ArpPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);

        virtual ~ArpPacket() {}
};

#endif /* ARPPACKET_H_ */
