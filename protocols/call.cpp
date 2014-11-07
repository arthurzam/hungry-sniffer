#include "Protocol.h"
#include "TCPPacket.h"
#include "ArpPacket.h"
#include "IPPacket.h"
#include "ICMPPacket.h"
#include "UDPPacket.h"
#include <netinet/ether.h>

extern "C" void add(Protocol& base)
{
    base.addProtocol(ETHERTYPE_IP, init<IPPacket>, true, "IP", true);
    base.addProtocol(ETHERTYPE_ARP, init<ArpPacket>, true, "ARP", false);
    Protocol& ip = base[ETHERTYPE_IP];
    ip.addProtocol(6, init<TCPPacket>, true, "TCP", false);
    ip.addProtocol(17, init<UDPPacket>, true, "UDP", false);
    ip.addProtocol(1, init<ICMPPacket>, true, "ICMP", false);
    Protocol& tcp = ip[6];
    tcp.addProtocol(80, init<PacketEmpty>, false, "HTTP", false);
    tcp.addProtocol(443, init<PacketEmpty>, false, "HTTPS", false);
}
