#include <netinet/ether.h>

#include "options.h"
#include "stats_ips.h"
using namespace hungry_sniffer;

extern "C" void add(HungrySniffer_Core& core)
{
    Protocol& ipv4 = core.base[ETHERTYPE_IP];
    ipv4.addOption("ARPspoof between IP-s", start_arpspoof, true);
    ipv4.addOption("Find hostname of Source", resolve_srcIP, false);
    ipv4.addOption("Find hostname of Destination", resolve_dstIP, false);
    ipv4.addStatsWindow("&Stats", StatWindow::create<StatsIps>);

    Protocol& tcp = ipv4[6];
    //Protocol& udp = ipv4[17];

    tcp.addOption("Redirect Source Port", start_srcPortRedirect, true);
    //udp.addOption("Redirect Source Port", start_srcPortRedirect, true);
}
