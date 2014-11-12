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
    protected:
        virtual std::string source() const;
        virtual std::string destination() const;
    public:
        IPv6Packet(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual void getLocalHeaders(headers_t& headers) const;
        virtual ~IPv6Packet() {}
};

#endif /* IPV6PACKET_H_ */
