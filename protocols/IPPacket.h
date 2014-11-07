/*
 * IPPacket.h
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#ifndef IPPACKET_H_
#define IPPACKET_H_

#include "Protocol.h"
#include <netinet/ip.h>

using namespace hungry_sniffer;

class IPPacket : public PacketStructed<struct ip> {
    protected:
        virtual std::string source() const;
        virtual std::string destination() const;
    public:
        IPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev = nullptr);
        virtual void getLocalHeaders(headers_t& headers) const;
        virtual ~IPPacket() {}
};

#endif /* IPPACKET_H_ */
