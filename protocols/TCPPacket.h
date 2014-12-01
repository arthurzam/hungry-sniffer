#ifndef TCPPACKET_H_
#define TCPPACKET_H_

#include "Protocol.h"
#include <netinet/tcp.h>

using namespace hungry_sniffer;

class TCPPacket: public PacketStructed<struct tcphdr> {
    public:
        TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~TCPPacket() {}
};

#endif /* TCPPACKET_H_ */
