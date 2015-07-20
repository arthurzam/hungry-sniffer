#include "VRRPPacket.h"
#include <arpa/inet.h>

VRRPPacket::VRRPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketStructed(data, len, protocol, prev)
{
    this->headers.push_back({"Type", std::to_string(this->value.type)});
    this->headers.push_back({"Version", std::to_string(this->value.version)});
    this->headers.push_back({"Virtual Router ID", std::to_string(this->value.vrid)});
    this->headers.push_back({"Priority", std::to_string(this->value.priority)});
    this->headers.push_back({"Address Count", std::to_string(this->value.naddr)});
    this->headers.push_back({"Authenticate Type", std::to_string(this->value.auth_type)});
    this->headers.push_back({"Advertisement Interval", std::to_string(this->value.adver_int)});

    const uint8_t* ip = (const uint8_t*)data + sizeof(this->value);
    char str[INET_ADDRSTRLEN];
    for(int i = 0; i < this->value.naddr; i++)
    {
        inet_ntop(AF_INET, ip, str, INET_ADDRSTRLEN);
        this->headers.push_back({"IP Address", str});
        ip += 4;
    }
}

unsigned VRRPPacket::getLength() const
{
    return sizeof(value) + (this->value.naddr * 4);
}
