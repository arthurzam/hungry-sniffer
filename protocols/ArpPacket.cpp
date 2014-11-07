#include "ArpPacket.h"
#include <arpa/inet.h>

using namespace std;

void ArpPacket::getLocalHeaders(headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"type", (ntohs(this->value.ar_op) == ARPOP_REQUEST ? "Request" : "Reply")});
    headers.push_back({"ARP", map});
}
