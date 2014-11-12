/*
 * IPv6Packet.cpp
 *
 *  Created on: Nov 12, 2014
 *      Author: arthur
 */

#include "IPv6Packet.h"
#include <arpa/inet.h>

IPv6Packet::IPv6Packet(const void* data, size_t len, const Protocol* protocol,
        const Packet* prev) : PacketStructed(data, len, protocol, prev)
{
    this->setNext(this->value.ip6_ctlun.ip6_un1.ip6_un1_nxt, (const char*)data + sizeof(value), len - sizeof(value));
}

std::string IPv6Packet::source() const
{
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &this->value.ip6_src, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

std::string IPv6Packet::destination() const
{
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &this->value.ip6_dst, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

void IPv6Packet::getLocalHeaders(headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"Source IP", source()});
    map.push_back({"Destination IP", destination()});
    map.push_back({"Next Protocol (number)", std::to_string(this->value.ip6_ctlun.ip6_un1.ip6_un1_nxt)});
    headers.push_back({"IPv6", map});
}
