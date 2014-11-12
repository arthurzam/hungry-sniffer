/*
 * DNSPacket.cpp
 *
 *  Created on: Nov 8, 2014
 *      Author: arthur
 */

#include "DNSPacket.h"
#include <netinet/in.h>

DNSPacket::DNSPacket(const void* data, size_t len, const Protocol* protocol,
        const Packet* prev) :
        PacketStructed(data, len, protocol, prev)
{
    this->queries.reserve(ntohs(this->value.q_count));
}

void DNSPacket::getLocalHeaders(headers_t& headers) const
{
    char hexWord[8];
    headers_category_t map;
    map.push_back({"Transaction ID", std::to_string(ntohs(this->value.id))});
    map.push_back({"Questions", std::to_string(ntohs(this->value.q_count))});
    sprintf(hexWord, "0x%04x", ntohs(this->value.flags.flags));
    map.push_back({"Flags", hexWord});
    headers.push_back({(this->value.flags.flags_t.qr == 1 ? "DNS Response" : "DNS Query"), map});
}
