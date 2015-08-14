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
#include "stats_ips.h"
#include "stats_length.h"
using namespace hungry_sniffer;

#include <hs_core.h>

extern "C" void add(HungrySniffer_Core& core)
{
    Protocol& ipv4 = core.base[0x0800];
#ifdef Q_OS_UNIX
    ipv4.addOption("ARPspoof between IP-s", start_arpspoof, true);
#endif
    ipv4.addOption("Find hostname of Source", resolve_srcIP, false);
    ipv4.addOption("Find hostname of Destination", resolve_dstIP, false);

    Protocol& tcp = ipv4[6];

#ifdef Q_OS_UNIX
    tcp.addOption("Redirect Source Port", start_srcPortRedirect, true);
#endif

    core.addStatWindow({"Packet &Length", Stats::create<StatsLength>});
    auto& ip = core.addStatWindow({"IP"});
    ip.add({"&Address Distribution", Stats::create<StatsIps>});
}
