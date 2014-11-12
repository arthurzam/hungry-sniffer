#ifndef TCPPACKET_H_
#define TCPPACKET_H_

#include "Protocol.h"
#include <netinet/tcp.h>

using namespace hungry_sniffer;

class TCPPacket: public PacketStructed<struct tcphdr> {
    protected:
        virtual std::string source() const;
        virtual std::string destination() const;
    public:
        TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~TCPPacket() {}
        virtual void getLocalHeaders(headers_t& headers) const;};

#endif /* TCPPACKET_H_ */
