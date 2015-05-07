#ifndef ICMPPACKET_H_
#define ICMPPACKET_H_

#include "Protocol.h"
#include <netinet/ip_icmp.h>

using namespace hungry_sniffer;

class ICMPPacket: public PacketStructed<struct icmphdr> {
    private:
        void setByTypes(int type, int code);
    public:
        ICMPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~ICMPPacket() {}
};

#endif /* ICMPPACKET_H_ */
