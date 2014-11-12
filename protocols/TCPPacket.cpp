/*
 * TCPPacket.cpp
 *
 *  Created on: Sep 1, 2014
 *      Author: root
 */

#include "TCPPacket.h"
#include <netinet/in.h>

using namespace std;

TCPPacket::TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    if(!Packet::setNext(ntohs(this->value.th_sport), (const char*)data + sizeof(value), len - sizeof(value)))
        Packet::setNext(ntohs(this->value.th_dport), (const char*)data + sizeof(value), len - sizeof(value));
}

std::string TCPPacket::source() const
{
    if(!this->prev)
        return "";
    std::string r = this->prev->source();
    r.append(":");
    r.append(std::to_string(ntohs(this->value.th_sport)));
    return r;
}

std::string TCPPacket::destination() const
{
    if(!this->prev)
        return "";
    std::string r = this->prev->destination();
    r.append(":");
    r.append(std::to_string(ntohs(this->value.th_dport)));
    return r;
}

void TCPPacket::getLocalHeaders(headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"Source Port", std::to_string(ntohs(this->value.th_sport))});
    map.push_back({"Destination Port", std::to_string(ntohs(this->value.th_dport))});
    headers.push_back({"TCP", map});
}
