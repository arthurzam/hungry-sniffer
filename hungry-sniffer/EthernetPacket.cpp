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

#include "EthernetPacket.h"
#include <net/ethernet.h>
#include <netinet/in.h>

using namespace std;
using namespace hungry_sniffer;

EthernetPacket::EthernetPacket(const void* data, size_t len,
        const Protocol* protocol, const Packet* prev) :
        PacketStructed(data, len, protocol, prev)
{
    this->_realSource = ether_ntoa((struct ether_addr*) this->value->ether_shost);
    this->_realDestination = ether_ntoa((struct ether_addr*) this->value->ether_dhost);

    this->updateNameAssociation();

    this->setNext(ntohs(this->value->ether_type), (const char*) data + sizeof(*value), len - sizeof(*value));
}

std::string EthernetPacket::getConversationFilterText() const
{
    std::string res("Ethernet.src==");
    res.append(this->_realSource);
    res.append(" & Ethernet.dst==");
    res.append(this->_realDestination);
    return res;
}

void EthernetPacket::updateNameAssociation()
{
    this->source = this->protocol->getNameAssociated(this->_realSource);
    this->destination = this->protocol->getNameAssociated(this->_realDestination);

    this->headers.clear();
    this->headers.push_back({"Source MAC", this->source, 6, 6});
    this->headers.push_back({"Destination MAC", this->destination, 0, 6});
    this->headers.push_back({"Next Protocol (Number)", std::to_string(ntohs(this->value->ether_type)), 12, 2});
}

bool EthernetPacket::filter_dstMac(const Packet* packet, const std::vector<std::string>* res)
{
    const EthernetPacket* eth = static_cast<const EthernetPacket*>(packet);
    return res->at(1) == eth->_realDestination || res->at(1) == eth->destination;
}

bool EthernetPacket::filter_srcMac(const Packet* packet, const std::vector<string>* res)
{
    const EthernetPacket* eth = static_cast<const EthernetPacket*>(packet);
    return res->at(1) == eth->_realSource || res->at(1) == eth->source;
}
