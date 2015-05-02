#ifndef IPPACKET_H_
#define IPPACKET_H_

#include "Protocol.h"
#include <netinet/ip.h>

using namespace hungry_sniffer;

class IPPacket : public PacketStructed<struct ip> {
    public:
        IPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~IPPacket() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();

        static bool filter_dstIP(const Packet* packet, const std::vector<std::string>& res);
        static bool filter_srcIP(const Packet* packet, const std::vector<std::string>& res);
        static bool filter_follow(const Packet* packet, const std::vector<std::string>& res);

        static bool drop_srcIP(const Packet* packet, std::list<struct enabledOption>& options);
        static bool undrop_srcIP(const Packet* packet);
};

#endif /* IPPACKET_H_ */
