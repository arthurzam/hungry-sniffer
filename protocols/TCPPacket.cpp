#include "TCPPacket.h"
#include <netinet/in.h>

extern Protocol dataProtocol;

TCPPacket::TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
      PacketStructed(data, len, protocol, prev)
{
    this->_realSource = std::to_string(ntohs(this->value.th_sport));
    this->_realDestination = std::to_string(ntohs(this->value.th_dport));

    this->updateNameAssociation();

    size_t tcpLen = this->value.th_off * 4;
    if(len - tcpLen > 0)
    {
        const void* __data = (const char*)data + tcpLen;
        size_t __data_len = len - tcpLen;
        if(!Packet::setNext(ntohs(this->value.th_sport), __data, __data_len))
            Packet::setNext(ntohs(this->value.th_dport), __data, __data_len);
        if(this->next == nullptr)
        {
            this->next = dataProtocol.getFunction()(__data, __data_len, &dataProtocol, this);
        }
    }
}

std::string TCPPacket::getConversationFilterText() const
{
    std::string res("TCP.follow==");
    res.append(this->source);
    res.append(",");
    res.append(this->destination);
    return res;
}

void TCPPacket::updateNameAssociation()
{
    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(this->protocol->getNameAssociated(this->_realSource));

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(this->protocol->getNameAssociated(this->_realDestination));

    this->headers.clear();
    this->headers.push_back({"Source Port", this->_realSource});
    this->headers.push_back({"Destination Port", this->_realDestination});
    this->headers.push_back({"Data Offset", std::to_string(this->value.th_off)});

#define PUSH_FLAG_TEXT(str, flag) this->headers.push_back({str, (flag ? "ON" : "OFF")})
    PUSH_FLAG_TEXT("SYN flag", this->value.syn);
    PUSH_FLAG_TEXT("ACK flag", this->value.ack);
    PUSH_FLAG_TEXT("RST flag", this->value.rst);
    PUSH_FLAG_TEXT("FIN flag", this->value.fin);
    PUSH_FLAG_TEXT("PSH flag", this->value.psh);
    PUSH_FLAG_TEXT("URG flag", this->value.urg);
#undef PUSH_FLAG_TEXT
}

bool TCPPacket::filter_dstPort(const Packet* packet, const std::vector<std::string>& res)
{
    const TCPPacket* tcp = static_cast<const TCPPacket*>(packet);
    return res[1] == tcp->_realDestination || res[1] == tcp->destination;
}

bool TCPPacket::filter_srcPort(const Packet* packet, const std::vector<std::string>& res)
{
    const TCPPacket* tcp = static_cast<const TCPPacket*>(packet);
    return res[1] == tcp->_realSource || res[1] == tcp->source;
}

bool TCPPacket::filter_follow(const Packet* packet, const std::vector<std::string>& res)
{
    const TCPPacket* tcp = static_cast<const TCPPacket*>(packet);
    if(res[1] == tcp->_realSource || res[1] == tcp->source)
        return res[2] == tcp->_realDestination || res[2] == tcp->destination;
    if(res[1] == tcp->_realDestination || res[1] == tcp->destination)
        return res[2] == tcp->_realSource || res[2] == tcp->source;
    return false;
}
