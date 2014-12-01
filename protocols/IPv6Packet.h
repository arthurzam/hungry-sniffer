/*
 * IPv6Packet.h
 *
 *  Created on: Nov 12, 2014
 *      Author: arthur
 */

#ifndef IPV6PACKET_H_
#define IPV6PACKET_H_

#include "Protocol.h"
#include <netinet/ip6.h>

using namespace hungry_sniffer;

class IPv6Packet : public PacketStructed<struct ip6_hdr> {
    public:
        IPv6Packet(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~IPv6Packet() {}
};

#endif /* IPV6PACKET_H_ */
