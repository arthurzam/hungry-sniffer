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

#include "IPPacket.h"
#if defined(Q_OS_WIN)
#elif defined(Q_OS_UNIX)
    #include <arpa/inet.h>
    #include "iptc.h"
#endif
using namespace std;

IPPacket::IPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) : PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    this->_realSource = inet_ntoa(this->value->ip_src);
    this->_realDestination = inet_ntoa(this->value->ip_dst);

    this->headers.push_back({"Source IP", "", 12, 4});
    this->headers.push_back({"Destination IP", "", 16, 4});
    this->headers.push_back({"Type of Service", std::to_string(this->value->ip_tos), 1, 1});
    this->headers.push_back({"Total Length", std::to_string(ntohs(this->value->ip_len)), 2, 2});
    this->headers.push_back({"Identification", std::to_string(ntohs(this->value->ip_id)), 4, 2});
    this->headers.push_back({"Fragment Offset Field", std::to_string(ntohs(this->value->ip_off)), 6, 2});
    this->headers.push_back({"TTL", std::to_string(this->value->ip_ttl), 8, 1});
    this->headers.push_back({"Protocol", std::to_string(this->value->ip_p), 9, 1});
    this->headers.push_back({"Checksum", std::to_string(ntohs(this->value->ip_sum)), 10, 2});
    this->updateNameAssociation();

    this->setNext(this->value->ip_p, (const char*)data + sizeof(*value), len - sizeof(*value));
}

std::string IPPacket::getConversationFilterText() const
{
    std::string res("IP.follow==");
    res.append(this->source);
    res.append(",");
    res.append(this->destination);
    return res;
}

void IPPacket::updateNameAssociation()
{
    this->source = this->protocol->getNameAssociated(this->_realSource);
    this->destination = this->protocol->getNameAssociated(this->_realDestination);

    this->headers[0].value = this->source;
    this->headers[1].value = this->destination;

    if(this->next)
        this->next->updateNameAssociation();
}

#ifdef Q_OS_UNIX
int IPPacket::drop_srcIP(const Packet* packet, Option::disabled_options_t& options)
{
    const IPPacket* ip = static_cast<const IPPacket*>(packet->getNext());
    bool res = dropIP(ip->_realSource.c_str(), true);
    if(!res)
        return 0;

    Option::enabledOption e = {"Drop from ", ip->_realSource.c_str(), IPPacket::undrop_IP};
    e.name.append(ip->_realSource.c_str());
    options.push_back(std::move(e));
    return Option::ENABLE_OPTION_RETURN_ADDED_DISABLE;
}

int IPPacket::drop_dstIP(const Packet* packet, Option::disabled_options_t& options)
{
    const IPPacket* ip = static_cast<const IPPacket*>(packet->getNext());
    bool res = dropIP(ip->_realDestination.c_str(), true);
    if(!res)
        return 0;
    Option::enabledOption e = {"Drop from ", ip->_realDestination.c_str(), IPPacket::undrop_IP};
    e.name.append(ip->_realDestination.c_str());
    options.push_back(std::move(e));
    return Option::ENABLE_OPTION_RETURN_ADDED_DISABLE;
}

bool IPPacket::undrop_IP(const void* data)
{
    return removeDropIP(static_cast<const char*>(data), true);
}
#endif
