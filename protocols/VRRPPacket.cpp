/*
 * VRRPPacket.cpp
 *
 *  Created on: Nov 23, 2014
 *      Author: arthur
 */

#include "VRRPPacket.h"

void VRRPPacket::getLocalHeaders(headers_t& headers) const
{
    headers_category_t map;
    map.push_back({"Type", std::to_string(this->value.vers_type.vers_type_t.type)});
    map.push_back({"Version", std::to_string(this->value.vers_type.vers_type_t.version)});
    headers.push_back({"VRRP", std::move(map)});
}
