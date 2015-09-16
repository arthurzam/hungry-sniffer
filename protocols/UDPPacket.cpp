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

#include "UDPPacket.h"
#if defined(Q_OS_WIN)
    #include <winsock2.h>
#elif defined(Q_OS_UNIX)
    #include <netinet/in.h>
#endif

extern Protocol dataProtocol;

UDPPacket::UDPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
      PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    this->_realSource = std::to_string(ntohs(this->value->uh_sport));
    this->_realDestination = std::to_string(ntohs(this->value->uh_dport));

    this->headers.push_back({"Source Port", this->_realSource, 0, 2});
    this->headers.push_back({"Destination Port", this->_realDestination, 2, 2});
    this->headers.push_back({"Length", std::to_string(ntohs(this->value->uh_ulen)), 4, 2});
    this->updateNameAssociation();

    const void* __data = (const char*)data + sizeof(*value);
    size_t __data_len = len - sizeof(*value);

    if(!Packet::setNext(ntohs(this->value->uh_sport), __data, __data_len))
        Packet::setNext(ntohs(this->value->uh_dport), __data, __data_len);
    if(this->next == nullptr)
    {
        this->next = dataProtocol.getFunction()(__data, __data_len, &dataProtocol, this);
        this->next->updateNameAssociation();
    }
}

std::string UDPPacket::getConversationFilterText() const
{
    char res[256];
    snprintf(res, sizeof(res), "UDP.follow==%s,%s", this->source.c_str(), this->destination.c_str());
    return std::string(res);
}

void UDPPacket::updateNameAssociation()
{
    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(this->protocol->getNameAssociated(this->_realSource));

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(this->protocol->getNameAssociated(this->_realDestination));
}

size_t UDPPacket::getHash() const
{
    return this->prev->getHash() ^ (std::hash<uint16_t>()(value->uh_sport ^ value->uh_dport) << 1);
}

bool UDPPacket::compare(const Packet* other) const
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(other);
    uint16_t t1 = this->value->uh_sport ^ this->value->uh_dport;
    uint16_t t2 = udp->value->uh_sport ^ udp->value->uh_dport;
    if (t1 == 0 ? (udp->value->uh_sport ^ this->value->uh_sport) != 0 : t1 != t2)
        return false;
    return this->prev->compare(udp->prev);
}
