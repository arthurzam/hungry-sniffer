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

    this->headers.push_back({"Transaction ID", std::to_string(ntohs(this->value.id))});
    this->headers.push_back({"Authoritive answer", (this->value.aa ? "Yes" : "No")});
    this->headers.push_back({"truncated message", (this->value.tc ? "Yes" : "No")});
    this->headers.push_back({"Recursion desired", (this->value.rd ? "Yes" : "No")});
    this->headers.push_back({"Questions Count", std::to_string(ntohs(this->value.q_count))});
    this->headers.push_back({"Answers Count", std::to_string(ntohs(this->value.ans_count))});
    this->headers.push_back({"Authorities Count", std::to_string(ntohs(this->value.auth_count))});
    this->headers.push_back({"Resources Count", std::to_string(ntohs(this->value.add_count))});

}
