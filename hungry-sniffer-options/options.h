#ifndef OPTIONS_H
#define OPTIONS_H

#include "Protocol.h"
using namespace hungry_sniffer;

extern "C" {
    int start_arpspoof(const Packet* packet, Option::disabled_options_t& options);

    int start_srcPortRedirect(const Packet* packet, Option::disabled_options_t& options);

    int resolve_srcIP(const Packet* packet, Option::disabled_options_t&);
    int resolve_dstIP(const Packet* packet, Option::disabled_options_t&);
}

#endif // OPTIONS_H

