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
#if defined(Q_OS_WIN)
    #include <winsock2.h>
    #include <Ws2tcpip.h>
#elif defined(Q_OS_UNIX)
    #include <netdb.h>
    #include <arpa/inet.h>
#endif

static int resolve(const Packet* packet, const char* ipStr)
{
    struct in_addr ip;
    struct hostent* hp;

#if defined(Q_OS_WIN)
    ip.S_un.S_addr = inet_addr(ipStr);
    if(ip.S_un.S_addr == INADDR_NONE)
        return 0;
#elif defined(Q_OS_UNIX)
    if (!inet_aton(ipStr, &ip))
        return 0;
#endif

    if ((hp = gethostbyaddr((const char *)&ip, sizeof ip, AF_INET)) == nullptr)
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
