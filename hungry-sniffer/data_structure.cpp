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

#include "packetstable_model.h"
#include "EthernetPacket.h"
#include "sniff_window.h"

DataStructure::RawPacketData::RawPacketData(const DataStructure::RawPacketData& other) :
    time(other.time)
{
    setData(other.data, other.len);
}

DataStructure::RawPacketData::RawPacketData(DataStructure::RawPacketData&& other) :
    len(other.len),
    time(other.time),
    data(other.data)
{
    other.data = nullptr;
}

DataStructure::RawPacketData& DataStructure::RawPacketData::operator=(const RawPacketData& other)
{
    if(this != &other)
    {
        this->time = other.time;
        setData(other.data, other.len);
    }
    return *this;
}

DataStructure::RawPacketData& DataStructure::RawPacketData::operator=(RawPacketData&& other)
{
    if(this != &other)
    {
        this->len = other.len;
        this->time = other.time;
        this->data = other.data;
        other.data = nullptr;
    }
    return *this;
}

DataStructure::RawPacketData::~RawPacketData()
{
    if(this->data)
        free(this->data);
}

void DataStructure::RawPacketData::setData(const void* data, uint32_t len)
{
    this->len = len;
    this->data = (char*)malloc(len);
    memcpy(this->data, data, len);
}

DataStructure::localPacket::localPacket(DataStructure::RawPacketData&& raw) :
    rawPacket(std::move(raw)), isShown(false)
{
    this->decodedPacket = new hungry_sniffer::EthernetPacket(rawPacket.data, rawPacket.len, &SniffWindow::core->base);
}

DataStructure::localPacket& DataStructure::localPacket::operator=(DataStructure::localPacket&& other)
{
    if(this != &other)
    {
        this->rawPacket = std::move(other.rawPacket);
        this->isShown = other.isShown;
        this->decodedPacket = other.decodedPacket;
        other.decodedPacket = nullptr;
    }
    return *this;
}

DataStructure::localPacket::~localPacket()
{
    if(decodedPacket)
        delete decodedPacket;
}

