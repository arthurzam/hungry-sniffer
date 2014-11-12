/*
 * IPPacket.cpp
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#include "IPPacket.h"
#include <arpa/inet.h>

using namespace std;

IPPacket::IPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) : PacketStructed(data, len, protocol, prev)
{
    this->setNext(this->value.ip_p, (const char*)data + sizeof(value), len - sizeof(value));
}

std::string IPPacket::source() const
{
    return inet_ntoa(this->value.ip_src);
}

std::string IPPacket::destination() const
{
    return inet_ntoa(this->value.ip_dst);
}

void IPPacket::getLocalHeaders(headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"Source IP", inet_ntoa(this->value.ip_src)});
    map.push_back({"Destination IP", inet_ntoa(this->value.ip_dst)});
    headers.push_back({"IP", map});
}
