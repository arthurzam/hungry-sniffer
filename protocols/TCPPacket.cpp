#include "TCPPacket.h"
#include <netinet/in.h>

using namespace std;

TCPPacket::TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
      PacketStructed(data, len, protocol, prev),
      sport(std::to_string(ntohs(this->value.th_sport))),
      dport(std::to_string(ntohs(this->value.th_dport)))
{
    if(!Packet::setNext(ntohs(this->value.th_sport), (const char*)data + sizeof(value), len - sizeof(value)))
        Packet::setNext(ntohs(this->value.th_dport), (const char*)data + sizeof(value), len - sizeof(value));

    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(this->sport);

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(this->dport);

    this->headers.push_back({"Source Port", this->sport});
    this->headers.push_back({"Destination Port", this->dport});
}

std::string TCPPacket::getConversationFilterText() const
{
    std::string res("TCP.follow==");
    res.append(this->sport);
    res.append(",");
    res.append(this->dport);
    return res;
}

bool TCPPacket::filter_dstPort(const Packet* packet, const std::vector<std::string>& res)
{
    const TCPPacket* tcp = static_cast<const TCPPacket*>(packet);
    return res[1] == tcp->dport;
}

bool TCPPacket::filter_srcPort(const Packet* packet, const std::vector<std::string>& res)
{
    const TCPPacket* tcp = static_cast<const TCPPacket*>(packet);
    return res[1] == tcp->sport;
}

bool TCPPacket::filter_follow(const Packet* packet, const std::vector<std::string>& res)
{
    const TCPPacket* tcp = static_cast<const TCPPacket*>(packet);
    if(res[1] == tcp->sport)
        return res[2] == tcp->dport;
    if(res[1] == tcp->dport)
        return res[2] == tcp->sport;
    return false;
}
