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

#include "options.h"
#include "stats_endpoints.h"
#include "stats_length.h"

using namespace hungry_sniffer;
using hungry_sniffer::Stats::StatWindow;

#include <hs_plugin.h>

static StatWindow* initEndpointIPv4()
{
    return new StatsEndpoints(&HungrySniffer_Core::core->base[0x0800]);
}

static StatWindow* initEndpointIPv6()
{
    return new StatsEndpoints(&HungrySniffer_Core::core->base[0x86dd]);
}

static StatWindow* initEndpointEthernet()
{
    return new StatsEndpoints(&HungrySniffer_Core::core->base);
}

EXPORT_FUNCTION void add()
{
    HungrySniffer_Core& core = *HungrySniffer_Core::core;
    Protocol& ipv4 = core.base[0x0800];
#ifdef Q_OS_UNIX
    ipv4.addOption("ARPspoof between IP-s", start_arpspoof, true);
#endif
    ipv4.addOption("Find hostname of Source", resolve_srcIP, false);
    ipv4.addOption("Find hostname of Destination", resolve_dstIP, false);

#ifdef Q_OS_UNIX
    Protocol& tcp = ipv4[6];
    tcp.addOption("Redirect Source Port", start_srcPortRedirect, true);
#endif

    core.addStatWindow({"Packet &Length", StatsLength::init});
    auto& endpoints = core.addStatWindow({"&Endpoints List"});
    endpoints.add({"&Ethernet", initEndpointEthernet});
    endpoints.add({"&IP", initEndpointIPv4});
    endpoints.add({"&IPv6", initEndpointIPv6});
}

EXPORT_COPYRIGHT("Arthur Zamarin")
EXPORT_VERSION
EXPORT_WEBSITE("https://github.com/arthurzam/hungry-sniffer")
