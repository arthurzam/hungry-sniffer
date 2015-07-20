#ifndef UDPPACKET_H_
#define UDPPACKET_H_

#include "Protocol.h"
#include <netinet/udp.h>

using namespace hungry_sniffer;

class UDPPacket: public PacketStructed<struct udphdr> {
    public:
        UDPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~UDPPacket() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();

        static bool filter_dstPort(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_srcPort(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_follow(const Packet* packet, const std::vector<std::string>* res);
};

#endif /* UDPPACKET_H_ */
