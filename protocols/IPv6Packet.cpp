/*
 * ipv6v6Packet.cpp
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
    this->_realSource = str;
    inet_ntop(AF_INET6, &this->value.ip6_dst, str, INET6_ADDRSTRLEN);
    this->_realDestination = str;

    this->updateNameAssociation();

    this->setNext(this->value.ip6_ctlun.ip6_un1.ip6_un1_nxt, (const char*)data + sizeof(value), len - sizeof(value));
}

std::string IPv6Packet::getConversationFilterText() const
{
    std::string res("IPv6.follow==");
    res.append(this->source);
    res.append(",");
    res.append(this->destination);
    return res;
}

void IPv6Packet::updateNameAssociation()
{
    this->source = this->protocol->getNameAssociated(this->_realSource);
    this->destination = this->protocol->getNameAssociated(this->_realDestination);

    this->headers.clear();
    this->headers.push_back({"Source ipv6", this->source});
    this->headers.push_back({"Destination ipv6", this->destination});
    this->headers.push_back({"Payload Length", std::to_string(ntohs(this->value.ip6_ctlun.ip6_un1.ip6_un1_plen))});
    this->headers.push_back({"Next Protocol (number)", std::to_string(this->value.ip6_ctlun.ip6_un1.ip6_un1_nxt)});
    this->headers.push_back({"Hop Limit", std::to_string(this->value.ip6_ctlun.ip6_un1.ip6_un1_hlim)});

    if(this->next)
        this->next->updateNameAssociation();
}

bool IPv6Packet::filter_dstIP(const Packet* packet, const std::vector<std::string>& res)
{
    const IPv6Packet* ipv6 = static_cast<const IPv6Packet*>(packet);
    return res[1] == ipv6->_realDestination || res[1] == ipv6->destination;
}

bool IPv6Packet::filter_srcIP(const Packet* packet, const std::vector<std::string>& res)
{
    const IPv6Packet* ipv6 = static_cast<const IPv6Packet*>(packet);
    return res[1] == ipv6->_realSource || res[1] == ipv6->source;
}

bool IPv6Packet::filter_follow(const Packet* packet, const std::vector<std::string>& res)
{
    const IPv6Packet* ipv6 = static_cast<const IPv6Packet*>(packet);
    if(res[1] == ipv6->_realSource || res[1] == ipv6->source)
        return res[2] == ipv6->_realDestination || res[2] == ipv6->destination;
    if(res[1] == ipv6->_realDestination || res[1] == ipv6->destination)
        return res[2] == ipv6->_realSource || res[2] == ipv6->source;
    return false;
}
