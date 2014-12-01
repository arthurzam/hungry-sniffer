#include "TCPPacket.h"
#include <netinet/in.h>

using namespace std;

TCPPacket::TCPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
      PacketStructed(data, len, protocol, prev)
{
    if(!Packet::setNext(ntohs(this->value.th_sport), (const char*)data + sizeof(value), len - sizeof(value)))
        Packet::setNext(ntohs(this->value.th_dport), (const char*)data + sizeof(value), len - sizeof(value));

    this->source = this->prev->localSource();
    this->source.append(":");
    this->source.append(std::to_string(ntohs(this->value.th_sport)));

    this->destination = this->prev->localDestination();
    this->destination.append(":");
    this->destination.append(std::to_string(ntohs(this->value.th_dport)));

    this->headers.push_back({"Source Port", std::to_string(ntohs(this->value.th_sport))});
    this->headers.push_back({"Destination Port", std::to_string(ntohs(this->value.th_dport))});
}
