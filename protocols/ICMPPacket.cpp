/*
 * ICMPPacket.cpp
 *
 *  Created on: Sep 2, 2014
 *      Author: arthur
 */

#include "ICMPPacket.h"
#include <netinet/in.h>

using namespace std;

void ICMPPacket::getLocalHeaders(headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"Code", std::to_string((int)this->value.code)});
    map.push_back({"Type", std::to_string((int)this->value.type)});
    headers.push_back({"ICMP", map});
}
