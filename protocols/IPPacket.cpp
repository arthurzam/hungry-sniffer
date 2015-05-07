#include "IPPacket.h"
#include <arpa/inet.h>
#include "iptc.h"

using namespace std;

IPPacket::IPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev) : PacketStructed(data, len, protocol, prev)
{
    this->_realSource = inet_ntoa(this->value.ip_src);
    this->_realDestination = inet_ntoa(this->value.ip_dst);

    this->updateNameAssociation();

    this->setNext(this->value.ip_p, (const char*)data + sizeof(value), len - sizeof(value));
}

std::string IPPacket::getConversationFilterText() const
{
    std::string res("IP.follow==");
    res.append(this->source);
    res.append(",");
    res.append(this->destination);
    return res;
}

void IPPacket::updateNameAssociation()
{
    this->source = this->protocol->getNameAssociated(this->_realSource);
    this->destination = this->protocol->getNameAssociated(this->_realDestination);

    this->headers.clear();
    this->headers.push_back({"Source IP", this->source});
    this->headers.push_back({"Destination IP", this->destination});
    this->headers.push_back({"TTL", std::to_string(this->value.ip_ttl)});

    if(this->next)
        this->next->updateNameAssociation();
}

bool IPPacket::filter_dstIP(const Packet* packet, const std::vector<std::string>& res)
{
    const IPPacket* ip = static_cast<const IPPacket*>(packet);
    return res[1] == ip->_realDestination || res[1] == ip->destination;
}

bool IPPacket::filter_srcIP(const Packet* packet, const std::vector<std::string>& res)
{
    const IPPacket* ip = static_cast<const IPPacket*>(packet);
    return res[1] == ip->_realSource || res[1] == ip->source;
}

bool IPPacket::filter_follow(const Packet* packet, const std::vector<std::string>& res)
{
    const IPPacket* ip = static_cast<const IPPacket*>(packet);
    if(res[1] == ip->_realSource || res[1] == ip->source)
        return res[2] == ip->_realDestination || res[2] == ip->destination;
    if(res[1] == ip->_realDestination || res[1] == ip->destination)
        return res[2] == ip->_realSource || res[2] == ip->source;
    return false;
}

int IPPacket::drop_srcIP(const Packet* packet, Option::disabled_options_t& options)
{
    const IPPacket* ip = static_cast<const IPPacket*>(packet->getNext());
    bool res = dropIP(ip->_realSource.c_str(), true);
    if(!res)
        return 0;

    Option::enabledOption e = {"Drop from ", ip->_realSource.c_str(), IPPacket::undrop_IP};
    e.name.append(ip->_realSource.c_str());
    options.push_back(std::move(e));
    return Option::ENABLE_OPTION_RETURN_ADDED_DISABLE;
}

int IPPacket::drop_dstIP(const Packet* packet, Option::disabled_options_t& options)
{
    const IPPacket* ip = static_cast<const IPPacket*>(packet->getNext());
    bool res = dropIP(ip->_realDestination.c_str(), true);
    if(!res)
        return 0;
    Option::enabledOption e = {"Drop from ", ip->_realDestination.c_str(), IPPacket::undrop_IP};
    e.name.append(ip->_realDestination.c_str());
    options.push_back(std::move(e));
    return Option::ENABLE_OPTION_RETURN_ADDED_DISABLE;
}

bool IPPacket::undrop_IP(const void* data)
{
    return removeDropIP(static_cast<const char*>(data), true);
}
