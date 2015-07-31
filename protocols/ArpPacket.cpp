#include "ArpPacket.h"

ArpPacket::ArpPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    uint16_t arp_protocol = ntohs(this->value.ar_pro);
    uint16_t arp_format = ntohs(this->value.ar_hrd);
    this->headers.push_back({"Hardware Type", std::to_string(arp_format), 0, 2});
    this->headers.push_back({"Protocol Type", std::to_string(arp_protocol), 2, 2});
    this->headers.push_back({"Hardware Size", std::to_string(this->value.ar_hln), 4, 1});
    this->headers.push_back({"Protocol Size", std::to_string(this->value.ar_pln), 5, 1});

    if(ntohs(this->value.ar_op) == ARPOP_REQUEST)
    {
        this->headers.push_back({"Type", "Request", 6, 2});
        this->info = "ARP Request";
    }
    else
    {
        this->headers.push_back({"Type", "Reply", 6, 2});
        this->info = "ARP Reply";
    }

    if(arp_format == 1 && (arp_protocol == 0x0800 || arp_protocol == 0x86dd))
    {
        size = (arp_protocol == 0x0800 ? sizeof(this->data.eth_ip) : sizeof(this->data.eth_ipv6));
        memcpy(&this->data, (const char*)data + sizeof(value),
                (size));
        size += sizeof(value);

        char str[INET6_ADDRSTRLEN];
        if(arp_protocol == 0x0800)
        {
            this->headers.push_back({"Sender MAC Address", ether_ntoa((struct ether_addr*) this->data.eth_ip.arp_sha), 8, 6});
            this->headers.push_back({"Target MAC Address", ether_ntoa((struct ether_addr*) this->data.eth_ip.arp_tha), 18, 6});

            inet_ntop(AF_INET, &this->data.eth_ip.arp_sip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Sender IP Address" , str, 14, 4});
            inet_ntop(AF_INET, &this->data.eth_ip.arp_tip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Target IP Address" , str, 24, 4});
        }
        else
        {
            this->headers.push_back({"Sender MAC Address", ether_ntoa((struct ether_addr*) this->data.eth_ipv6.arp_sha), 8, 6});
            this->headers.push_back({"Target MAC Address", ether_ntoa((struct ether_addr*) this->data.eth_ipv6.arp_tha)});

            inet_ntop(AF_INET6, &this->data.eth_ipv6.arp_sip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Sender IPv6 Address" , str, 14, 16});
            inet_ntop(AF_INET6, &this->data.eth_ipv6.arp_tip, str, INET6_ADDRSTRLEN);
            this->headers.push_back({"Target IPv6 Address" , str});
        }
    }
}
