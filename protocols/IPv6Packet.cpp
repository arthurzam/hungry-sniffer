/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "IPv6Packet.h"
#if defined(Q_OS_WIN)
    const char* inet_ntop(int af, const void* src, char* dst, int cnt);
#elif defined(Q_OS_UNIX)
    #include <arpa/inet.h>
    #include "iptc.h"
#endif

IPv6Packet::IPv6Packet(const void* data, size_t len, const Protocol* protocol,
        const Packet* prev) : PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &this->value->ip6_src, str, INET6_ADDRSTRLEN);
    this->_realSource = str;
    inet_ntop(AF_INET6, &this->value->ip6_dst, str, INET6_ADDRSTRLEN);
    this->_realDestination = str;

    this->headers.push_back({"Source ipv6", "", 8, 16});
    this->headers.push_back({"Destination ipv6", "", 24, 16});
    this->headers.push_back({"Payload Length", std::to_string(ntohs(this->value->ip6_ctlun.ip6_un1.ip6_un1_plen)), 4, 2});
    this->headers.push_back({"Next Protocol (number)", std::to_string(this->value->ip6_ctlun.ip6_un1.ip6_un1_nxt), 6, 1});
    this->headers.push_back({"Hop Limit", std::to_string(this->value->ip6_ctlun.ip6_un1.ip6_un1_hlim), 7, 1});
    this->updateNameAssociation();

    this->setNext(this->value->ip6_ctlun.ip6_un1.ip6_un1_nxt, (const char*)data + sizeof(*value), len - sizeof(*value));
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

    this->headers[0].value = this->source;
    this->headers[1].value = this->destination;

    if(this->next)
        this->next->updateNameAssociation();
}

bool IPv6Packet::filter_dstIP(const Packet* packet, const std::vector<std::string>* res)
{
    const IPv6Packet* ipv6 = static_cast<const IPv6Packet*>(packet);
    return res->at(1) == ipv6->_realDestination || res->at(1) == ipv6->destination;
}

bool IPv6Packet::filter_srcIP(const Packet* packet, const std::vector<std::string>* res)
{
    const IPv6Packet* ipv6 = static_cast<const IPv6Packet*>(packet);
    return res->at(1) == ipv6->_realSource || res->at(1) == ipv6->source;
}

bool IPv6Packet::filter_follow(const Packet* packet, const std::vector<std::string>* res)
{
    const IPv6Packet* ipv6 = static_cast<const IPv6Packet*>(packet);
    if(res->at(1) == ipv6->_realSource || res->at(1) == ipv6->source)
        return res->at(2) == ipv6->_realDestination || res->at(2) == ipv6->destination;
    if(res->at(1) == ipv6->_realDestination || res->at(1) == ipv6->destination)
        return res->at(2) == ipv6->_realSource || res->at(2) == ipv6->source;
    return false;
}

#ifdef Q_OS_UNIX
int IPv6Packet::drop_srcIP(const Packet* packet, Option::disabled_options_t& options)
{
    const IPv6Packet* ip = static_cast<const IPv6Packet*>(packet->getNext());
    bool res = dropIP(ip->_realSource.c_str(), false);
    if(!res)
        return 0;
    Option::enabledOption e = {"Drop from ", ip->_realSource.c_str(), IPv6Packet::undrop_IP};
    e.name.append(ip->_realSource.c_str());
    options.push_back(std::move(e));
    return Option::ENABLE_OPTION_RETURN_ADDED_DISABLE;
}

int IPv6Packet::drop_dstIP(const Packet* packet, Option::disabled_options_t& options)
{
    const IPv6Packet* ip = static_cast<const IPv6Packet*>(packet->getNext());
    bool res = dropIP(ip->_realDestination.c_str(), false);
    if(!res)
        return 0;
    Option::enabledOption e = {"Drop from ", ip->_realDestination.c_str(), IPv6Packet::undrop_IP};
    e.name.append(ip->_realDestination.c_str());
    options.push_back(std::move(e));
    return Option::ENABLE_OPTION_RETURN_ADDED_DISABLE;
}

bool IPv6Packet::undrop_IP(const void* data)
{
    return removeDropIP(static_cast<const char*>(data), false);
}
#endif
