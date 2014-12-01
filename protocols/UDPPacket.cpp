/*
 * UDPPacket.cpp
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#include "UDPPacket.h"
#include <netinet/in.h>

using namespace std;

UDPPacket::UDPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
      PacketStructed(data, len, protocol, prev)
{
    if(!Packet::setNext(ntohs(this->value.uh_sport), (const char*)data + sizeof(value), len - sizeof(value)))
        Packet::setNext(ntohs(this->value.uh_dport), (const char*)data + sizeof(value), len - sizeof(value));

    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(std::to_string(ntohs(this->value.uh_sport)));

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(std::to_string(ntohs(this->value.uh_dport)));

    this->headers.push_back({"Source Port", std::to_string(ntohs(this->value.uh_sport))});
    this->headers.push_back({"Destination Port", std::to_string(ntohs(this->value.uh_dport))});
}

bool UDPPacket::filter_dstPort(const Packet* packet, const std::vector<std::string>& res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    return res[1] == std::to_string(ntohs(udp->value.uh_dport));
}
