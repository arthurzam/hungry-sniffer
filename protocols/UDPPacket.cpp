/*
 * UDPPacket.cpp
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#include "UDPPacket.h"
#include <netinet/in.h>

using namespace std;

void UDPPacket::getLocalHeaders(
        headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"Source Port", std::to_string(ntohs(this->value.uh_sport))});
    map.push_back({"Destination Port", std::to_string(ntohs(this->value.uh_dport))});
    headers.push_back({"UDP", map});
}
