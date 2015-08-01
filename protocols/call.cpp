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
#include "HTTPPacket.h"
#include <netinet/ether.h>

Protocol dataProtocol(init<PacketText>, "Data");

extern "C" void add(HungrySniffer_Core& core)
{
    Protocol& ipv4 = core.base.addProtocol(ETHERTYPE_IP, init<IPPacket>, "IP", Protocol::getFlags(true, true));
    Protocol& ipv6 = core.base.addProtocol(ETHERTYPE_IPV6, ipv4, init<IPv6Packet>, "IPv6");
    core.base.addProtocol(ETHERTYPE_ARP, init<ArpPacket>, "ARP");

    ipv4.addFilter("^dst *== *([^ ]+)$", IPPacket::filter_dstIP);
    ipv4.addFilter("^src *== *([^ ]+)$", IPPacket::filter_srcIP);
    ipv4.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", IPPacket::filter_follow);

    ipv4.addOption("Drop From Source", IPPacket::drop_srcIP, true);
    ipv4.addOption("Drop From Destination", IPPacket::drop_dstIP, true);

    ipv6.addFilter("^dst *== *([^ ]+)$", IPv6Packet::filter_dstIP);
    ipv6.addFilter("^src *== *([^ ]+)$", IPv6Packet::filter_srcIP);
    ipv6.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", IPv6Packet::filter_follow);

    ipv6.addOption("Drop From Source", IPv6Packet::drop_srcIP, true);
    ipv6.addOption("Drop From Destination", IPv6Packet::drop_dstIP, true);

    Protocol& tcp = ipv4.addProtocol(IPPROTO_TCP, init<TCPPacket>, "TCP", Protocol::getFlags(true, true));
    Protocol& udp = ipv4.addProtocol(IPPROTO_UDP, init<UDPPacket>, "UDP", Protocol::getFlags(true, true));
    ipv4.addProtocol(IPPROTO_ICMP, init<ICMPPacket>, "ICMP");
    ipv4.addProtocol(112, init<VRRPPacket>, "VRRP");

    tcp.addFilter("^dst *== *([^ ]+)$", TCPPacket::filter_dstPort);
    tcp.addFilter("^src *== *([^ ]+)$", TCPPacket::filter_srcPort);
    tcp.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", TCPPacket::filter_follow);

    tcp.addProtocol(80, init<HTTPPacket>, "HTTP");
    tcp.addProtocol(443, init<PacketEmpty>, "HTTPS");
    tcp.addProtocol(25, init<PacketText>, "SMTP");
    tcp.addProtocol(587, init<PacketText>, "SMTP");

    udp.addFilter("^dst *== *([^ ]+)$", UDPPacket::filter_dstPort);
    udp.addFilter("^src *== *([^ ]+)$", UDPPacket::filter_srcPort);
    udp.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", UDPPacket::filter_follow);

    {
        Protocol& dns = udp.addProtocol(53, init<DNSPacket>, "DNS", Protocol::getFlags(false, true));
        dns.addFilter("^id *== *([^ ]+)$", DNSPacket::filter_id);
    }
    udp.addProtocol(1900, init<HTTPPacket>, "SSDP");
    udp.addProtocol(17500, init<PacketJson>, "Dropbox LAN sync");
}
