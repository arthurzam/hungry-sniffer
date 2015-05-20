#include "EthernetPacket.h"
#include <net/ethernet.h>
#include <netinet/in.h>

using namespace std;
using namespace hungry_sniffer;

EthernetPacket::EthernetPacket(const void* data, size_t len,
        const Protocol* protocol, const Packet* prev) :
        PacketStructed(data, len, protocol, prev)
{
    this->_realSource = ether_ntoa((struct ether_addr*) this->value.ether_shost);
    this->_realDestination = ether_ntoa((struct ether_addr*) this->value.ether_dhost);

    this->updateNameAssociation();

    this->setNext(ntohs(this->value.ether_type), (const char*) data + sizeof(value), len - sizeof(value));
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
    this->headers.push_back({"Source MAC", this->source});
    this->headers.push_back({"Destination MAC", this->destination});
    this->headers.push_back({"Next Protocol (Number)", std::to_string(ntohs(this->value.ether_type))});
}

bool EthernetPacket::filter_dstMac(const Packet* packet, const std::vector<std::string>& res)
{
    const EthernetPacket* eth = static_cast<const EthernetPacket*>(packet);
    return res[1] == eth->_realDestination || res[1] == eth->destination;
}

bool EthernetPacket::filter_srcMac(const Packet* packet, const std::vector<string>& res)
{
    const EthernetPacket* eth = static_cast<const EthernetPacket*>(packet);
    return res[1] == eth->_realSource || res[1] == eth->source;
}
