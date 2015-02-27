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
    this->_realSource = std::to_string(ntohs(this->value.uh_sport));
    this->_realDestination = std::to_string(ntohs(this->value.uh_dport));

    this->updateNameAssociation();

    if(!Packet::setNext(ntohs(this->value.uh_sport), (const char*)data + sizeof(value), len - sizeof(value)))
        Packet::setNext(ntohs(this->value.uh_dport), (const char*)data + sizeof(value), len - sizeof(value));
}

std::string UDPPacket::getConversationFilterText() const
{
    std::string res("UDP.follow==");
    res.append(this->source);
    res.append(",");
    res.append(this->destination);
    return res;
}

void UDPPacket::updateNameAssociation()
{
    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(this->protocol->getNameAssociated(this->_realSource));

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(this->protocol->getNameAssociated(this->_realDestination));

    this->headers.clear();
    this->headers.push_back({"Source Port", this->_realSource});
    this->headers.push_back({"Destination Port", this->_realDestination});
    this->headers.push_back({"Length", std::to_string(this->value.uh_ulen)});
}

bool UDPPacket::filter_dstPort(const Packet* packet, const std::vector<std::string>& res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    return res[1] == udp->_realDestination || res[1] == udp->destination;
}

bool UDPPacket::filter_srcPort(const Packet* packet, const std::vector<std::string>& res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    return res[1] == udp->_realSource || res[1] == udp->source;
}

bool UDPPacket::filter_follow(const Packet* packet, const std::vector<std::string>& res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    if(res[1] == udp->_realSource || res[1] == udp->source)
        return res[2] == udp->_realDestination || res[2] == udp->destination;
    if(res[1] == udp->_realDestination || res[1] == udp->destination)
        return res[2] == udp->_realSource || res[2] == udp->source;
    return false;
}
