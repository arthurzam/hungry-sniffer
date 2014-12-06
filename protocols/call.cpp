#include "Protocol.h"
#include "TCPPacket.h"
#include "ArpPacket.h"
#include "IPPacket.h"
#include "IPv6Packet.h"
#include "ICMPPacket.h"
#include "UDPPacket.h"
#include "DNSPacket.h"
#include "VRRPPacket.h"
#include "PacketJson.h"
#include <netinet/ether.h>

extern "C" void add(Protocol& base)
{
    Protocol& ip = base.addProtocol(ETHERTYPE_IP, init<IPPacket>, true, "IP", true, true);
    base.addProtocol(ETHERTYPE_IPV6, ip, init<IPv6Packet>, "IPv6");
    base.addProtocol(ETHERTYPE_ARP, init<ArpPacket>, true, "ARP", false, false);

    Protocol& tcp = ip.addProtocol(6, init<TCPPacket>, true, "TCP", false, true);
    Protocol& udp = ip.addProtocol(17, init<UDPPacket>, true, "UDP", false, true);
    ip.addProtocol(1, init<ICMPPacket>, true, "ICMP", false, false);
    ip.addProtocol(112, init<VRRPPacket>, true, "VRRP", false, false);

    tcp.addProtocol(80, init<PacketEmpty>, true, "HTTP", false, false);
    tcp.addProtocol(443, init<PacketEmpty>, true, "HTTPS", false, false);
    tcp.addProtocol(25, init<PacketText>, true, "SMTP", false, false);
    tcp.addProtocol(587, init<PacketText>, true, "SMTP", false, false);

    udp.addFilter("^dst *== *([^ ]+)$", UDPPacket::filter_dstPort);

    {
        Protocol& dns = udp.addProtocol(53, init<DNSPacket>, true, "DNS", false, true);
        dns.addFilter("^id *== *([^ ]+)$", DNSPacket::filter_id);
    }
    udp.addProtocol(1900, init<PacketEmpty>, true, "SSDP", false, false);
    udp.addProtocol(17500, init<PacketJson>, true, "Dropbox LAN sync", false, false);
}
