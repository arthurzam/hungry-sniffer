#include "HTTPPacket.h"
#include <iostream>
using namespace std;

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

static bool cmpEncoding(const HTTPPacket::headers_category_t::value_type& i)
{
    return i.first == "Content-Encoding";
}

HTTPPacket::HTTPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
    : PacketTextHeaders(data, len, protocol, prev),
      isRequest(prev->realDestination() == "80")
{
    // parse first line

    std::string::const_iterator start = this->data.cbegin()
            , end = this->data.cend()
            , temp;

    if((temp = std::find(start, end, ' ')) == end)
    {
        isGood = false;
        return;
    }
    this->headers.push_back({(isRequest ? "Method" : "Version"), std::string(start, temp)});
    start = temp + 1;

    if((temp = std::find(start, end, ' ')) == end)
    {
        isGood = false;
        return;
    }
    this->headers.push_back({(isRequest ? "URI" : "Status Code"), std::string(start, temp)});
    start = temp + 1;

    if((temp = std::find(start, end, '\n')) == end)
    {
        isGood = false;
        return;
    }
    this->headers.push_back({(isRequest ? "Version" : "Phrase"), std::string(start, temp - 1)});
    start = temp + 1;

    // parse headers block
    int startOfData = this->data.find("\r\n\r\n", start - this->data.cbegin());
    this->extractTextHeaders(start - this->data.cbegin(), startOfData);

    startOfData += 4;

    if(!isRequest)
    {
        auto encoding = std::find_if(this->headers.cbegin(), this->headers.cend(), cmpEncoding);
        if(encoding != this->headers.cend())
        {
            std::hash<std::string> hasher;
            this->setNext(hasher(trimSpaces(encoding->second)), (const char*)data + startOfData, len - startOfData);
        }
        if(this->next == nullptr)
        {
            this->next = dataProtocol.getFunction()((const char*)data + startOfData, len - startOfData, &dataProtocol, this);
            this->next->updateNameAssociation();
        }
    }
}
