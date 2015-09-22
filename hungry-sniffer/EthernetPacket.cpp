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
#include <QtGlobal>
#if defined(Q_OS_WIN)
    #include <winsock2.h>
    char *ether_ntoa (const uint8_t* n)
    {
        int i;
        static char a [18];

        i = sprintf (a, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
        if (i <11)
            return (NULL);
        return ((char *) &a);
    }
    typedef uint8_t ether_addr;
#elif defined(Q_OS_UNIX)
    #include <netinet/ether.h>
    #include <netinet/in.h>
#endif

using namespace std;
using namespace hungry_sniffer;

EthernetPacket::EthernetPacket(const void* data, size_t len,
        const Protocol* protocol, const Packet* prev) :
        PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    this->_realSource = ether_ntoa((ether_addr*) this->value->ether_shost);
    this->_realDestination = ether_ntoa((ether_addr*) this->value->ether_dhost);

    this->headers.push_back({"Source MAC", "", 6, 6});
    this->headers.push_back({"Destination MAC", "", 0, 6});
    this->headers.push_back({"Next Protocol (Number)", std::to_string(ntohs(this->value->ether_type)), 12, 2});
    this->updateNameAssociation();

    this->setNext(ntohs(this->value->ether_type), (const char*) data + sizeof(*value), len - sizeof(*value));
}

std::string EthernetPacket::getConversationFilterText() const
{
    char res[64];
    snprintf(res, sizeof(res), "Ethernet.follow==%s,%s", _realSource.c_str(), _realDestination.c_str());
    return std::string(res);
}

void EthernetPacket::updateNameAssociation()
{
    this->source = this->protocol->getNameAssociated(this->_realSource);
    this->destination = this->protocol->getNameAssociated(this->_realDestination);

    this->headers[0].value = this->source;
    this->headers[1].value = this->destination;
}

bool EthernetPacket::filter_dstMac(const Packet* packet, const std::vector<std::string>* res)
{
    return res->at(1) == packet->realDestination() || res->at(1) == packet->localDestination();
}

bool EthernetPacket::filter_srcMac(const Packet* packet, const std::vector<string>* res)
{
    return res->at(1) == packet->realSource() || res->at(1) == packet->localSource();
}

bool EthernetPacket::filter_follow(const Packet* packet, const std::vector<std::string>* res)
{
    if(res->at(1) == packet->realSource() || res->at(1) == packet->localSource())
        return res->at(2) == packet->realDestination() || res->at(2) == packet->localDestination();
    if(res->at(1) == packet->realDestination() || res->at(1) == packet->localDestination())
        return res->at(2) == packet->realSource() || res->at(2) == packet->localSource();
    return false;
}
