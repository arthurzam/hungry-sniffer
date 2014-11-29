#include "EthernetPacket.h"
#include <net/ethernet.h>
#include <netinet/in.h>

using namespace std;

EthernetPacket::EthernetPacket(const void* data, size_t len,
        const Protocol* protocol, const Packet* prev) :
        PacketStructed(data, len, protocol, prev)
{
    this->setNext(ntohs(this->value.ether_type),
            (const char*) data + sizeof(value), len - sizeof(value));
}

std::string EthernetPacket::source() const
{
    return std::string(ether_ntoa((struct ether_addr*) this->value.ether_shost));
}

std::string EthernetPacket::destination() const
{
    return std::string(ether_ntoa((struct ether_addr*) this->value.ether_dhost));
}

bool EthernetPacket::filter_dstMac(const Packet* packet, const std::vector<std::string>& res)
{
    const EthernetPacket* eth = static_cast<const EthernetPacket*>(packet);
    return res[1] == ether_ntoa((struct ether_addr*) eth->value.ether_dhost);
}

void EthernetPacket::getLocalHeaders(headers_t &headers) const
{
    headers_category_t map;
    map.push_back({"Source Mac", ether_ntoa((struct ether_addr*) this->value.ether_shost)});
    map.push_back({"Destination Mac", ether_ntoa((struct ether_addr*) this->value.ether_dhost)});
    map.push_back({"Next Protocol (Number)", std::to_string(ntohs(this->value.ether_type))});
    headers.push_back({this->protocol->getName(), std::move(map)});
}
