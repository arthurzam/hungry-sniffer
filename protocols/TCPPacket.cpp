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

#include "TCPPacket.h"

#if defined(Q_OS_WIN)
    #include <winsock2.h>
#elif defined(Q_OS_UNIX)
    #include <netinet/in.h>
#endif

extern Protocol dataProtocol;

TCPPacket::TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
      PacketStructed(data, len, protocol, prev)
{
    if(!value) return;
    this->_realSource = std::to_string(ntohs(this->value->th_sport));
    this->_realDestination = std::to_string(ntohs(this->value->th_dport));

    this->headers.push_back({"Source Port", this->_realSource, 0, 2});
    this->headers.push_back({"Destination Port", this->_realDestination, 2, 2});
    this->headers.push_back({"Sequence Number", std::to_string(ntohl(this->value->th_seq)), 4, 4});
    this->headers.push_back({"Acknowledgement Number", std::to_string(ntohl(this->value->th_ack)), 8, 4});
    this->headers.push_back({"Data Offset", std::to_string(this->value->th_off), 12, 1});

    header_t flags("Flags", "", 12, 2);
#define PUSH_FLAG_TEXT(str, flag) flags.subHeaders.push_back({str, (flag ? "ON" : "OFF"), 12, 2})
    PUSH_FLAG_TEXT("SYN flag", this->value->syn);
    PUSH_FLAG_TEXT("ACK flag", this->value->ack);
    PUSH_FLAG_TEXT("RST flag", this->value->rst);
    PUSH_FLAG_TEXT("FIN flag", this->value->fin);
    PUSH_FLAG_TEXT("PSH flag", this->value->psh);
    PUSH_FLAG_TEXT("URG flag", this->value->urg);
#undef PUSH_FLAG_TEXT
    this->headers.push_back(std::move(flags));

    this->updateNameAssociation();

    size_t tcpLen = this->value->th_off * 4;
    if(len - tcpLen > 0)
    {
        const void* __data = (const char*)data + tcpLen;
        size_t __data_len = len - tcpLen;
        if(!Packet::setNext(ntohs(this->value->th_sport), __data, __data_len))
            Packet::setNext(ntohs(this->value->th_dport), __data, __data_len);
        if(this->next == nullptr)
        {
            this->next = dataProtocol.getFunction()(__data, __data_len, &dataProtocol, this);
            this->next->updateNameAssociation();
        }
    }
}

std::string TCPPacket::getConversationFilterText() const
{
    char res[256];
    snprintf(res, sizeof(res), "TCP.follow==%s,%s", this->source.c_str(), this->destination.c_str());
    return std::string(res);
}

void TCPPacket::updateNameAssociation()
{
    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(this->protocol->getNameAssociated(this->_realSource));

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(this->protocol->getNameAssociated(this->_realDestination));
}

unsigned TCPPacket::getLength() const
{
    return (this->value->th_off * 4);
}

size_t TCPPacket::getHash() const
{
    return this->prev->getHash() ^ (std::hash<uint16_t>()(value->th_sport ^ value->th_dport) << 1);
}

bool TCPPacket::compare(const Packet* other) const
{
    const TCPPacket* tcp = static_cast<const TCPPacket*>(other);
    uint16_t t1 = this->value->th_sport ^ this->value->th_dport;
    uint16_t t2 = tcp->value->th_sport ^ tcp->value->th_dport;
    if (t1 == 0 ? (tcp->value->th_sport ^ this->value->th_sport) != 0 : t1 != t2)
        return false;\
    return this->prev->compare(tcp->prev);
}
