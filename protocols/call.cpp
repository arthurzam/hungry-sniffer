/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <hs_plugin.h>

#include "TCPPacket.h"
#include "ArpPacket.h"
#include "IPPacket.h"
#include "IPv6Packet.h"
#include "ICMPPacket.h"
#include "UDPPacket.h"
#include "DNSPacket.h"
#include "VRRPPacket.h"
#ifdef Q_OS_UNIX
#include "PacketJson.h"
#endif
#include "HTTPPacket.h"

Protocol dataProtocol(init<PacketText>, "Data");

bool filter_dst(const Packet* packet, const std::vector<std::string>* res)
{
    return res->at(1) == packet->realDestination() || res->at(1) == packet->localDestination();
}

bool filter_src(const Packet* packet, const std::vector<std::string>* res)
{
    return res->at(1) == packet->realSource() || res->at(1) == packet->localSource();
}

bool filter_follow(const Packet* packet, const std::vector<std::string>* res)
{
    if(res->at(1) == packet->realSource() || res->at(1) == packet->localSource())
        return res->at(2) == packet->realDestination() || res->at(2) == packet->localDestination();
    if(res->at(1) == packet->realDestination() || res->at(1) == packet->localDestination())
        return res->at(2) == packet->realSource() || res->at(2) == packet->localSource();
    return false;
}

EXPORT_FUNCTION void add(HungrySniffer_Core& core)
{
    Protocol& ipv4 = core.base.addProtocol(0x0800, init<IPPacket>, "IP", Protocol::getFlags(true, true));
    Protocol& ipv6 = core.base.addProtocol(0x86dd, ipv4, init<IPv6Packet>, "IPv6");
    core.base.addProtocol(0x0806, init<ArpPacket>, "ARP");

    ipv4.addFilter("^dst *== *([^ ]+)$", filter_dst);
    ipv4.addFilter("^src *== *([^ ]+)$", filter_src);
    ipv4.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", filter_follow);

#ifdef Q_OS_UNIX
    ipv4.addOption("Drop From Source", IPPacket::drop_srcIP, true);
    ipv4.addOption("Drop From Destination", IPPacket::drop_dstIP, true);
#endif

    ipv6.addFilter("^dst *== *([^ ]+)$", filter_dst);
    ipv6.addFilter("^src *== *([^ ]+)$", filter_src);
    ipv6.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", filter_follow);

#ifdef Q_OS_UNIX
    ipv6.addOption("Drop From Source", IPv6Packet::drop_srcIP, true);
    ipv6.addOption("Drop From Destination", IPv6Packet::drop_dstIP, true);
#endif

    Protocol& tcp = ipv4.addProtocol(6, init<TCPPacket>, "TCP", Protocol::getFlags(true, true));
    Protocol& udp = ipv4.addProtocol(17, init<UDPPacket>, "UDP", Protocol::getFlags(true, true));
    ipv4.addProtocol(1, init<ICMPPacket>, "ICMP");
    ipv4.addProtocol(112, init<VRRPPacket>, "VRRP");

    tcp.addFilter("^dst *== *([^ ]+)$", filter_dst);
    tcp.addFilter("^src *== *([^ ]+)$", filter_src);
    tcp.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", filter_follow);

    tcp.addProtocol(80, init<HTTPPacket>, "HTTP");
    tcp.addProtocol(443, init<PacketEmpty>, "HTTPS");
    tcp.addProtocol(25, init<PacketText>, "SMTP");
    tcp.addProtocol(587, init<PacketText>, "SMTP");

    udp.addFilter("^dst *== *([^ ]+)$", filter_dst);
    udp.addFilter("^src *== *([^ ]+)$", filter_src);
    udp.addFilter("^follow *== *([^ ]+) *, *([^ ]+)$", filter_follow);

    {
        Protocol& dns = udp.addProtocol(53, init<DNSPacket>, "DNS", Protocol::getFlags(false, true));
        dns.addFilter("^id *== *([^ ]+)$", DNSPacket::filter_id);
    }
    udp.addProtocol(1900, init<HTTPPacket>, "SSDP");
#ifdef Q_OS_UNIX
    udp.addProtocol(17500, init<PacketJson>, "Dropbox LAN sync");
#endif
}

EXPORT_COPYRIGHT("Arthur Zamarin")
EXPORT_VERSION
EXPORT_WEBSITE("https://github.com/arthurzam/hungry-sniffer")
