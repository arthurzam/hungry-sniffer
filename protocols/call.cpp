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
    Protocol& ipv4 = base.addProtocol(ETHERTYPE_IP, init<IPPacket>, true, "IP", true, true);
    Protocol& ipv6 = base.addProtocol(ETHERTYPE_IPV6, ipv4, init<IPv6Packet>, "IPv6");
    base.addProtocol(ETHERTYPE_ARP, init<ArpPacket>, true, "ARP", false, false);

    ipv4.addFilter("^dst *== *([^ ]+)$", IPPacket::filter_dstIP);
    ipv4.addFilter("^src *== *([^ ]+)$", IPPacket::filter_srcIP);

    ipv6.addFilter("^dst *== *([^ ]+)$", IPv6Packet::filter_dstIP);
    ipv6.addFilter("^src *== *([^ ]+)$", IPv6Packet::filter_srcIP);

    Protocol& tcp = ipv4.addProtocol(6, init<TCPPacket>, true, "TCP", false, true);
    Protocol& udp = ipv4.addProtocol(17, init<UDPPacket>, true, "UDP", false, true);
    ipv4.addProtocol(1, init<ICMPPacket>, true, "ICMP", false, false);
    ipv4.addProtocol(112, init<VRRPPacket>, true, "VRRP", false, false);

    tcp.addFilter("^dst *== *([^ ]+)$", TCPPacket::filter_dstPort);
    tcp.addFilter("^src *== *([^ ]+)$", TCPPacket::filter_srcPort);
    tcp.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", TCPPacket::filter_follow);

    tcp.addProtocol(80, init<PacketEmpty>, true, "HTTP", false, false);
    tcp.addProtocol(443, init<PacketEmpty>, true, "HTTPS", false, false);
    tcp.addProtocol(25, init<PacketText>, true, "SMTP", false, false);
    tcp.addProtocol(587, init<PacketText>, true, "SMTP", false, false);

    udp.addFilter("^dst *== *([^ ]+)$", UDPPacket::filter_dstPort);
    udp.addFilter("^src *== *([^ ]+)$", UDPPacket::filter_srcPort);
    udp.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", UDPPacket::filter_follow);

    {
        Protocol& dns = udp.addProtocol(53, init<DNSPacket>, true, "DNS", false, true);
        dns.addFilter("^id *== *([^ ]+)$", DNSPacket::filter_id);
    }
    udp.addProtocol(1900, init<PacketEmpty>, true, "SSDP", false, false);
    udp.addProtocol(17500, init<PacketJson>, true, "Dropbox LAN sync", false, false);
}
