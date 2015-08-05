#ifndef ETHERNETPACKET_H_
#define ETHERNETPACKET_H_

#include <netinet/ether.h>
#include "Protocol.h"

namespace hungry_sniffer {

    class EthernetPacket final : public PacketStructed<struct ether_header> {
        public:
            EthernetPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev = nullptr);

            virtual ~EthernetPacket() {}
            virtual std::string getConversationFilterText() const;
            virtual void updateNameAssociation();

            static bool filter_dstMac(const Packet* packet, const std::vector<std::string>* res);
            static bool filter_srcMac(const Packet* packet, const std::vector<std::string>* res);
    };

}

#endif /* ETHERNETPACKET_H_ */