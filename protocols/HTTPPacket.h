#ifndef HTTPPACKET_H_
#define HTTPPACKET_H_

#include "Protocol.h"

using namespace hungry_sniffer;

class HTTPPacket : public PacketTextHeaders {
    private:
        bool isRequest;
    public:
        HTTPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        ~HTTPPacket() {};
};

#endif /* HTTPPACKET_H_ */
