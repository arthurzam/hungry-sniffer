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
      PacketStructed(data, len, protocol, prev),
      sport(std::to_string(ntohs(this->value.uh_sport))),
      dport(std::to_string(ntohs(this->value.uh_dport)))
{
    if(!Packet::setNext(ntohs(this->value.uh_sport), (const char*)data + sizeof(value), len - sizeof(value)))
        Packet::setNext(ntohs(this->value.uh_dport), (const char*)data + sizeof(value), len - sizeof(value));

    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(this->sport);

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(this->dport);

    this->headers.push_back({"Source Port", this->sport});
    this->headers.push_back({"Destination Port", this->dport});
}

std::string UDPPacket::getConversationFilterText() const
{
    std::string res("UDP.follow==");
    res.append(this->sport);
    res.append(",");
    res.append(this->dport);
    return res;
}

bool UDPPacket::filter_dstPort(const Packet* packet, const std::vector<std::string>& res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    return res[1] == udp->dport;
}

bool UDPPacket::filter_srcPort(const Packet* packet, const std::vector<std::string>& res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    return res[1] == udp->sport;
}

bool UDPPacket::filter_follow(const Packet* packet, const std::vector<std::string>& res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    if(res[1] == udp->sport)
        return res[2] == udp->dport;
    if(res[1] == udp->dport)
        return res[2] == udp->sport;
    return false;
}
