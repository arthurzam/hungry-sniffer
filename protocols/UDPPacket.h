/*
 * UDPPacket.h
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#ifndef UDPPACKET_H_
#define UDPPACKET_H_

#include "Protocol.h"
#include <netinet/udp.h>

using namespace hungry_sniffer;

class UDPPacket: public PacketStructed<struct udphdr> {
    protected:
        virtual std::string source() const;
        virtual std::string destination() const;
    public:
        UDPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~UDPPacket() {}
        virtual void getLocalHeaders(headers_t& headers) const;

        static bool filter_dstPort(const Packet* packet, const std::vector<std::string>&);
};

#endif /* UDPPACKET_H_ */
