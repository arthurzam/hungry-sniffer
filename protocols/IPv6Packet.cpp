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
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &this->value.ip6_src, str, INET6_ADDRSTRLEN);
    this->source = str;
    inet_ntop(AF_INET6, &this->value.ip6_dst, str, INET6_ADDRSTRLEN);
    this->destination = str;

    this->headers.push_back({"Source IP", this->source});
    this->headers.push_back({"Destination IP", this->destination});
    this->headers.push_back({"Next Protocol (number)", std::to_string(this->value.ip6_ctlun.ip6_un1.ip6_un1_nxt)});

    this->setNext(this->value.ip6_ctlun.ip6_un1.ip6_un1_nxt, (const char*)data + sizeof(value), len - sizeof(value));
}

std::string IPv6Packet::getConversationFilterText() const
{
    std::string res("IPv6.src==");
    res.append(this->source);
    res.append(" & IPv6.dst==");
    res.append(this->destination);
    return res;
}

bool IPv6Packet::filter_dstIP(const Packet* packet, const std::vector<std::string>& res)
{
    const IPv6Packet* eth = static_cast<const IPv6Packet*>(packet);
    return res[1] == eth->destination;
}

bool IPv6Packet::filter_srcIP(const Packet* packet, const std::vector<std::string>& res)
{
    const IPv6Packet* eth = static_cast<const IPv6Packet*>(packet);
    return res[1] == eth->source;
}
