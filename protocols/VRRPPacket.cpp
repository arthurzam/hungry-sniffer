/*
 * VRRPPacket.cpp
 *
 *  Created on: Nov 23, 2014
 *      Author: arthur
 */

#include "VRRPPacket.h"

VRRPPacket::VRRPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    this->headers.push_back({"Type", std::to_string(this->value.vers_type.vers_type_t.type)});
    this->headers.push_back({"Version", std::to_string(this->value.vers_type.vers_type_t.version)});
    this->headers.push_back({"Virtual Router ID", std::to_string(this->value.vrid)});
}
