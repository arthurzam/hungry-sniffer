/*
 * ICMPPacket.cpp
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#include "ICMPPacket.h"
#include <netinet/in.h>

using namespace std;

ICMPPacket::ICMPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
            : PacketStructed(data, len, protocol, prev)
{
    this->headers.push_back({"Code", std::to_string((int)this->value.code)});
    this->headers.push_back({"Type", std::to_string((int)this->value.type)});
}
