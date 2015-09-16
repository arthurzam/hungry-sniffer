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
#ifdef Q_CC_MINGW
    const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
#endif
#if defined(Q_OS_UNIX)
    #include <arpa/inet.h>
    #include "iptc.h"
#endif

IPv6Packet::IPv6Packet(const void* data, size_t len, const Protocol* protocol,
        const Packet* prev) : PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (void*)&this->value->ip6_src, str, INET6_ADDRSTRLEN);
    this->_realSource = str;
    inet_ntop(AF_INET6, (void*)&this->value->ip6_dst, str, INET6_ADDRSTRLEN);
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
    char res[256];
    snprintf(res, sizeof(res), "IPv6.follow==%s,%s", this->source.c_str(), this->destination.c_str());
    return std::string(res);
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

size_t _getHash(const struct in6_addr& ip6)
{
    size_t hash;
    const size_t* ptr = (const size_t*)&ip6;
    for(unsigned i = 0; i < (sizeof(struct in6_addr) / sizeof(size_t)); ++i)
    {
        hash = (hash ^ (*ptr << 1)) >> 1;
        ptr++;
    }
    return hash;
}

size_t IPv6Packet::getHash() const
{
    return _getHash(this->value->ip6_src) ^ _getHash(this->value->ip6_dst);
}

bool IPv6Packet::compare(const Packet* other) const
{
#define COMPARE_IP6(ptr1, part1, ptr2, part2) memcmp(ptr1->value->part1.s6_addr, ptr2->value->part2.s6_addr, sizeof(struct in6_addr))
    const IPv6Packet* ip6 = static_cast<const IPv6Packet*>(other);
    if(COMPARE_IP6(this, ip6_src, ip6, ip6_src))
        return !(COMPARE_IP6(this, ip6_dst, ip6, ip6_src) || COMPARE_IP6(ip6, ip6_dst, this, ip6_src));
    return !COMPARE_IP6(this, ip6_dst, ip6, ip6_dst);
#undef COMPARE_IP6
}
