#include "Protocol.h"
#include "TCPPacket.h"
#include "ArpPacket.h"
#include "IPPacket.h"
#include "IPv6Packet.h"
#include "ICMPPacket.h"
#include "UDPPacket.h"
#include "DNSPacket.h"
#include "VRRPPacket.h"
#include <netinet/ether.h>

extern "C" void add(Protocol& base)
{
    Protocol& ip = base.addProtocol(ETHERTYPE_IP, init<IPPacket>, true, "IP", true);
    base.addProtocol(ETHERTYPE_IPV6, ip, init<IPv6Packet>, "IPv6");
    base.addProtocol(ETHERTYPE_ARP, init<ArpPacket>, true, "ARP", false);

    Protocol& tcp = ip.addProtocol(6, init<TCPPacket>, true, "TCP", false);
    Protocol& udp = ip.addProtocol(17, init<UDPPacket>, true, "UDP", false);
    ip.addProtocol(1, init<ICMPPacket>, true, "ICMP", false);
    ip.addProtocol(112, init<VRRPPacket>, true, "VRRP", false);

    tcp.addProtocol(80, init<PacketEmpty>, true, "HTTP", false);
    tcp.addProtocol(443, init<PacketEmpty>, true, "HTTPS", false);
    tcp.addProtocol(25, init<PacketEmpty>, true, "SMTP", false);
    tcp.addProtocol(587, init<PacketEmpty>, true, "SMTP", false);

    udp.addFilter("^dst *== *([^ ]+)$", UDPPacket::filter_dstPort);

    udp.addProtocol(53, init<DNSPacket>, true, "DNS", false);
    udp.addProtocol(1900, init<PacketEmpty>, true, "SSDP", false);
}
