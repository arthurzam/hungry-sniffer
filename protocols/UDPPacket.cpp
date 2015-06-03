#include "UDPPacket.h"
#include <netinet/in.h>

extern Protocol dataProtocol;

UDPPacket::UDPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
      PacketStructed(data, len, protocol, prev)
{
    this->_realSource = std::to_string(ntohs(this->value.uh_sport));
    this->_realDestination = std::to_string(ntohs(this->value.uh_dport));

    this->updateNameAssociation();

    const void* __data = (const char*)data + sizeof(value);
    size_t __data_len = len - sizeof(value);
    if(!Packet::setNext(ntohs(this->value.uh_sport), __data, __data_len))
        Packet::setNext(ntohs(this->value.uh_dport), __data, __data_len);
    if(this->next == nullptr)
    {
        this->next = dataProtocol.getFunction()(__data, __data_len, &dataProtocol, this);
        this->next->updateNameAssociation();
    }
}

std::string UDPPacket::getConversationFilterText() const
{
    std::string res("UDP.follow==");
    res.append(this->source);
    res.append(",");
    res.append(this->destination);
    return res;
}

void UDPPacket::updateNameAssociation()
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
    this->headers.push_back({"Length", std::to_string(this->value.uh_ulen)});
}

bool UDPPacket::filter_dstPort(const Packet* packet, const std::vector<std::string>* res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    return res->at(1) == udp->_realDestination || res->at(1) == udp->destination;
}

bool UDPPacket::filter_srcPort(const Packet* packet, const std::vector<std::string>* res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    return res->at(1) == udp->_realSource || res->at(1) == udp->source;
}

bool UDPPacket::filter_follow(const Packet* packet, const std::vector<std::string>* res)
{
    const UDPPacket* udp = static_cast<const UDPPacket*>(packet);
    if(res->at(1) == udp->_realSource || res->at(1) == udp->source)
        return res->at(2) == udp->_realDestination || res->at(2) == udp->destination;
    if(res->at(1) == udp->_realDestination || res->at(1) == udp->destination)
        return res->at(2) == udp->_realSource || res->at(2) == udp->source;
    return false;
}
