#ifndef TCPPACKET_H_
#define TCPPACKET_H_

#include "Protocol.h"
#include <netinet/tcp.h>

using namespace hungry_sniffer;

class TCPPacket: public PacketStructed<struct tcphdr> {
    public:
        TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~TCPPacket() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();

        static bool filter_dstPort(const Packet* packet, const std::vector<std::string>& res);
        static bool filter_srcPort(const Packet* packet, const std::vector<std::string>& res);
        static bool filter_follow(const Packet* packet, const std::vector<std::string>& res);
};

#endif /* TCPPACKET_H_ */
