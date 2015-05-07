#include <netdb.h>
#include <arpa/inet.h>

#include "options.h"

static int resolve(const Packet* packet, const char* ipStr)
{
    struct in_addr ip;
    struct hostent* hp;

    if (!inet_aton(ipStr, &ip))
        return 0;

    if ((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == nullptr)
        return 0;

    const_cast<Protocol*>(packet->getProtocol())->associateName(std::string(ipStr), std::string(hp->h_name));

    return (Option::ENABLE_OPTION_RETURN_RELOAD_TABLE);
}

int resolve_srcIP(const Packet* packet, Option::disabled_options_t&)
{
    packet = packet->getNext();
    return resolve(packet, packet->realSource().c_str());
}

int resolve_dstIP(const Packet* packet, Option::disabled_options_t&)
{
    packet = packet->getNext();
    return resolve(packet, packet->realDestination().c_str());
}
