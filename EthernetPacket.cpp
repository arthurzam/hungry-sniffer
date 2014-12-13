#include "EthernetPacket.h"
#include <net/ethernet.h>
#include <netinet/in.h>

using namespace std;

EthernetPacket::EthernetPacket(const void* data, size_t len,
        const Protocol* protocol, const Packet* prev) :
        PacketStructed(data, len, protocol, prev)
{
    this->source = this->protocol->getNameAssociated(ether_ntoa((struct ether_addr*) this->value.ether_shost));
    this->destination = this->protocol->getNameAssociated(ether_ntoa((struct ether_addr*) this->value.ether_dhost));

    this->headers.push_back({"Source MAC", this->source});
    this->headers.push_back({"Destination MAC", this->destination});
    this->headers.push_back({"Next Protocol (Number)", std::to_string(ntohs(this->value.ether_type))});

    this->setNext(ntohs(this->value.ether_type), (const char*) data + sizeof(value), len - sizeof(value));
}

std::string EthernetPacket::getConversationFilterText() const
{
    std::string res("Ethernet.src==");
    res.append(this->source);
    res.append(" & Ethernet.dst==");
    res.append(this->destination);
    return res;
}

void EthernetPacket::updateNameAssociation()
{
    this->source = this->protocol->getNameAssociated(ether_ntoa((struct ether_addr*) this->value.ether_shost));
    this->destination = this->protocol->getNameAssociated(ether_ntoa((struct ether_addr*) this->value.ether_dhost));

    this->headers.clear();
    this->headers.push_back({"Source MAC", this->source});
    this->headers.push_back({"Destination MAC", this->destination});
    this->headers.push_back({"Next Protocol (Number)", std::to_string(ntohs(this->value.ether_type))});
}

bool EthernetPacket::filter_dstMac(const Packet* packet, const std::vector<std::string>& res)
{
    const EthernetPacket* eth = static_cast<const EthernetPacket*>(packet);
    return res[1] == eth->destination;
}

bool EthernetPacket::filter_srcMac(const Packet* packet, const std::vector<string>& res)
{
    const EthernetPacket* eth = static_cast<const EthernetPacket*>(packet);
    return res[1] == eth->source;
}
