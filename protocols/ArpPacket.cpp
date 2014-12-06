#include "ArpPacket.h"

using namespace std;


ArpPacket::ArpPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    this->headers.push_back({"Hardware Type", std::to_string(ntohs(this->value.ar_hrd))});
    this->headers.push_back({"Protocol Type", std::to_string(ntohs(this->value.ar_pro))});
    this->headers.push_back({"Hardware Size", std::to_string(this->value.ar_hln)});
    this->headers.push_back({"Protocol Size", std::to_string(this->value.ar_pln)});

    this->headers.push_back({"Type", (ntohs(this->value.ar_op) == ARPOP_REQUEST ? "Request" : "Reply")});

    if(ntohs(this->value.ar_hrd) == 1 && (ntohs(this->value.ar_pro) == 0x0800 || ntohs(this->value.ar_pro) == 0x86dd))
    {
        memcpy(&this->data, (const char*)data + sizeof(value),
                (ntohs(this->value.ar_pro) == 0x0800 ? sizeof(this->data.eth_ip) : sizeof(this->data.eth_ipv6)));

        this->headers.push_back({"Sender MAC Address", ether_ntoa((struct ether_addr*) this->data.eth_ip.arp_sha)});

        char str[INET6_ADDRSTRLEN];
        if(ntohs(this->value.ar_pro) == 0x0800)
            inet_ntop(AF_INET, &this->data.eth_ip.arp_sip, str, INET6_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, &this->data.eth_ipv6.arp_sip, str, INET6_ADDRSTRLEN);
        this->headers.push_back({"Sender IP Address" , str});

        this->headers.push_back({"Target MAC Address", ether_ntoa((struct ether_addr*) this->data.eth_ip.arp_tha)});

        if(ntohs(this->value.ar_pro) == 0x0800)
            inet_ntop(AF_INET, &this->data.eth_ip.arp_tip, str, INET6_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, &this->data.eth_ipv6.arp_tip, str, INET6_ADDRSTRLEN);
        this->headers.push_back({"Target IP Address" , str});
    }
}
