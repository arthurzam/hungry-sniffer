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
    static constexpr int MAX_FIELD_LEN = 256;
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
    int ____len = (temp - start);
    if((____len <= MAX_FIELD_LEN) & (____len > 0))
        this->headers.push_back({(isRequest ? "Version" : "Phrase"), std::string(start, temp - 1), start - this->data.begin(), temp - 1 - start});
    else
        return;
    start = temp + 1;

    // parse headers block
    static const char blockDivide[] = "\r\n\r\n";
    auto startOfData = std::search(start, end, blockDivide, blockDivide + 4);
    this->extractTextHeaders(start, startOfData, start - this->data.begin());

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
