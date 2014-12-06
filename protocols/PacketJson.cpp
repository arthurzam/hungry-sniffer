/*
 * PacketJson.cpp
 *
 *  Created on: Dec 1, 2014
 *      Author: arthur
 */

#include "PacketJson.h"
#include <jsoncpp/json/json.h>
PacketJson::PacketJson(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketTextHeaders(protocol, prev)
{
    Json::Value root;
    Json::Reader reader;
    if(!reader.parse((char*)data, (char*)data + len, root))
    {
        this->isGood = false;
        return;
    }
    auto members = root.getMemberNames();
    for(auto& i : members)
    {
        std::string r(root[i].toStyledString());
        r.pop_back();
        this->headers.push_back({i, std::move(r)});
    }
}
