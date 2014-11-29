#ifndef ETHERNETPACKET_H_
#define ETHERNETPACKET_H_

#include <netinet/ether.h>
#include "Protocol.h"

using namespace hungry_sniffer;

class EthernetPacket : public PacketStructed<struct ether_header> {
    protected:
        virtual std::string source() const;
        virtual std::string destination() const;
    public:
        EthernetPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev = nullptr);

        virtual ~EthernetPacket() {}

        static bool filter_dstMac(const Packet* packet, const std::vector<std::string>&);

        virtual void getLocalHeaders(headers_t& headers) const;
};

#endif /* ETHERNETPACKET_H_ */
