#include "ArpPacket.h"
#include <arpa/inet.h>

using namespace std;


ArpPacket::ArpPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    this->headers.push_back({"type", (ntohs(this->value.ar_op) == ARPOP_REQUEST ? "Request" : "Reply")});
}
