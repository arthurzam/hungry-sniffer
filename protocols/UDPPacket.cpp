/*
 * UDPPacket.cpp
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#include "UDPPacket.h"
#include <netinet/in.h>

using namespace std;

UDPPacket::UDPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    if(!Packet::setNext(ntohs(this->value.uh_sport), (const char*)data + sizeof(value), len - sizeof(value)))
        Packet::setNext(ntohs(this->value.uh_dport), (const char*)data + sizeof(value), len - sizeof(value));
}

void UDPPacket::getLocalHeaders(
        headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"Source Port", std::to_string(ntohs(this->value.uh_sport))});
    map.push_back({"Destination Port", std::to_string(ntohs(this->value.uh_dport))});
    headers.push_back({"UDP", map});
}


std::string UDPPacket::source() const
{
    if(!this->prev)
        return "";
    std::string r = this->prev->source();
    r.append(":");
    r.append(std::to_string(ntohs(this->value.uh_sport)));
    return r;
}

std::string UDPPacket::destination() const
{
    if(!this->prev)
        return "";
    std::string r = this->prev->destination();
    r.append(":");
    r.append(std::to_string(ntohs(this->value.uh_dport)));
    return r;
}
