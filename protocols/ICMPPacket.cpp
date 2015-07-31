#include "ICMPPacket.h"
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

ICMPPacket::ICMPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
            : PacketStructed(data, len, protocol, prev)
{
    int type = (int)this->value->type,
        code = (int)this->value->code;

    this->headers.push_back({"Type", std::to_string(type)});
    this->headers.push_back({"Code", std::to_string(code)});

    this->setByTypes(type, code);
}

void ICMPPacket::setByTypes(int type, int code)
{
    switch(type)
    {
        case 0:
            this->info = "Echo Reply (Ping Reply)";
            break;
        case 3:
            switch(code)
            {

            }
            break;
        case 5:
        {
            this->info = "Redirect";
            switch(code)
            {
                case 0: this->info.append(" for Network"); break;
                case 1: this->info.append(" for Host"); break;
                case 2: this->info.append(" for Type of Service and Network"); break;
                case 3: this->info.append(" for Type of Service and Host"); break;
            }
            struct in_addr addr;
            addr.s_addr = this->value->un.gateway;
            this->headers.push_back({"Redirect to IP", inet_ntoa(addr)});
        }
            break;
        case 8:
            this->info = "Echo Request (Ping Request)";
            break;
        case 11:
            this->info = "Time exceeded";
            switch(code)
            {
                case 0: this->info.append(" - TTL exceeded in transit"); break;
                case 1: this->info.append(" - Fragment reassembly time exceeded"); break;
            }
            break;
    }
    this->headers.push_back({"ICMP Type", this->info});
}
