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
    headers_category_t map;
    map.push_back({"Transaction ID", std::to_string(ntohs(this->value.id))});

    map.push_back({"Authoritive answer", (this->value.aa ? "Yes" : "No")});
    map.push_back({"truncated message", (this->value.tc ? "Yes" : "No")});
    map.push_back({"Recursion desired", (this->value.rd ? "Yes" : "No")});

    map.push_back({"Questions Count", std::to_string(ntohs(this->value.q_count))});
    map.push_back({"Answers Count", std::to_string(ntohs(this->value.ans_count))});
    map.push_back({"Authorities Count", std::to_string(ntohs(this->value.auth_count))});
    map.push_back({"Resources Count", std::to_string(ntohs(this->value.add_count))});

    headers.push_back({(this->value.qr == 1 ? "DNS Response" : "DNS Query"), std::move(map)});
}
