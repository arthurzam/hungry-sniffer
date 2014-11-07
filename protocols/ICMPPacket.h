/*
 * ICMPPacket.h
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#ifndef ICMPPACKET_H_
#define ICMPPACKET_H_

#include "Protocol.h"
#include <netinet/ip_icmp.h>

using namespace hungry_sniffer;

class ICMPPacket: public PacketStructed<struct icmphdr> {
    public:
        ICMPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev = nullptr)
            : PacketStructed(data, len, protocol, prev) {}
        virtual void getLocalHeaders(headers_t& headers) const;
        virtual ~ICMPPacket() {}
};

#endif /* ICMPPACKET_H_ */
