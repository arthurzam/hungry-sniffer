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
    this->source = inet_ntoa(this->value.ip_src);
    this->destination = inet_ntoa(this->value.ip_dst);

    this->headers.push_back({"Source IP", this->source});
    this->headers.push_back({"Destination IP", this->destination});
    this->headers.push_back({"TTL", std::to_string(this->value.ip_ttl)});

    this->setNext(this->value.ip_p, (const char*)data + sizeof(value), len - sizeof(value));
}
