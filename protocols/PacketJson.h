/*
 * PacketJson.h
 *
 *  Created on: Dec 1, 2014
 *      Author: arthur
 */

#ifndef PACKETJSON_H_
#define PACKETJSON_H_

#include "Protocol.h"

using namespace hungry_sniffer;

class PacketJson : public PacketTextHeaders {
    public:
        PacketJson(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~PacketJson() {}
};

#endif /* PACKETJSON_H_ */
