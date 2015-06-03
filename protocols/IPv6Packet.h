#ifndef IPV6PACKET_H_
#define IPV6PACKET_H_

#include "Protocol.h"
#include <netinet/ip6.h>

using namespace hungry_sniffer;

class IPv6Packet : public PacketStructed<struct ip6_hdr> {
    public:
        IPv6Packet(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~IPv6Packet() {}
        virtual std::string getConversationFilterText() const;
        virtual void updateNameAssociation();

        static bool filter_dstIP(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_srcIP(const Packet* packet, const std::vector<std::string>* res);
        static bool filter_follow(const Packet* packet, const std::vector<std::string>* res);

        static int drop_srcIP(const Packet* packet, Option::disabled_options_t& options);
        static int drop_dstIP(const Packet* packet, Option::disabled_options_t& options);
        static bool undrop_IP(const void* data);

};

#endif /* IPV6PACKET_H_ */
