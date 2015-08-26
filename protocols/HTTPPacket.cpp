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

#include "HTTPPacket.h"

extern Protocol dataProtocol;

static std::string trimSpaces(const std::string& str)
{
    auto start = str.cbegin(), end = str.cend();
    while(*start == ' ' && start != end)
        ++start;
    while(*(end - 1) == ' ' && start != end)
        --end;
    return std::string(start, end);
}

static bool cmpEncoding(const HTTPPacket::headers_t::value_type& i)
{
    return i.key == "Content-Encoding";
}

HTTPPacket::HTTPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketTextHeaders(data, len, protocol, prev),
      isRequest(prev->realDestination() == "80")
{
    static CONSTEXPR int MAX_FIELD_LEN = 256;
    // parse first line

    auto start = this->data.begin(),
         end = this->data.end(),
         temp = this->data.begin();

    if((temp = std::find(start, end, ' ')) == end)
    {
        return;
    }
    if(temp - start <= MAX_FIELD_LEN)
        this->headers.push_back({(isRequest ? "Method" : "Version"), std::string(start, temp), start - this->data.begin(), temp - start});
    else
        return;
    start = temp + 1;

    if((temp = std::find(start, end, ' ')) == end)
    {
        return;
    }
    if(temp - start <= MAX_FIELD_LEN)
        this->headers.push_back({(isRequest ? "URI" : "Status Code"), std::string(start, temp), start - this->data.begin(), temp - start});
    else
        return;
    start = temp + 1;

    if((temp = std::find(start, end, '\n')) == end)
    {
        return;
    }
    int ____len = (int)(temp - start);
    if((____len <= MAX_FIELD_LEN) & (____len > 0))
        this->headers.push_back({(isRequest ? "Version" : "Phrase"), std::string(start, temp - 1), start - this->data.begin(), temp - 1 - start});
    else
        return;
    start = temp + 1;

    // parse headers block
    static const char blockDivide[] = "\r\n\r\n";
    auto startOfData = std::search(start, end, blockDivide, blockDivide + 4);
    this->extractTextHeaders(start, startOfData, (int)(start - this->data.begin()));

    startOfData += 4;

    if(!isRequest)
    {
        auto encoding = std::find_if(this->headers.cbegin(), this->headers.cend(), cmpEncoding);

        const char* dataStarting = (const char*)data + (startOfData - start);
        size_t nextDataLen = len - (startOfData - start);

        if(encoding != this->headers.cend())
        {
            std::hash<std::string> hasher;
            this->setNext(hasher(trimSpaces(encoding->value)), dataStarting, nextDataLen);
        }
        if(this->next == nullptr)
        {
            this->next = dataProtocol.getFunction()(dataStarting, nextDataLen, &dataProtocol, this);
            this->next->updateNameAssociation();
        }
    }
}
