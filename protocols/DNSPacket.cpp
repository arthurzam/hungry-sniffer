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

#include "DNSPacket.h"
#if defined(Q_OS_WIN)
    #include <winsock2.h>
#elif defined(Q_OS_UNIX)
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

static std::string getTypeStr(uint16_t type)
{
    switch(type)
    {
        case 1: return "A (Host Address)";
        case 5: return "CNAME (Canonical NAME for an alias)";
        case 28: return "AAAA";
        default: return "Unknown";
    }
}

DNSPacket::DNSPacket(const void* _data, size_t len, const Protocol* protocol,
        const Packet* prev) :
        PacketStructed(_data, len, protocol, prev),
        id(std::to_string(ntohs(this->value->id)))
{
    if(!value) return;
    size = (unsigned)len;

    this->headers.push_back({"Transaction ID", id, 0, 2});

    this->headers.push_back({"Authoritive answer", (this->value->aa ? "Yes" : "No"), 2, 2});
    this->headers.push_back({"Truncated message", (this->value->tc ? "Yes" : "No"), 2, 2});
    this->headers.push_back({"Recursion desired", (this->value->rd ? "Yes" : "No"), 2, 2});

    uint16_t questionsCount = ntohs(this->value->q_count);
    uint16_t answersCount = ntohs(this->value->ans_count);
    this->headers.push_back({"Questions Count", std::to_string(questionsCount), 4, 2});
    this->headers.push_back({"Answers Count", std::to_string(answersCount), 6, 2});
    this->headers.push_back({"Authorities Count", std::to_string(ntohs(this->value->auth_count)), 8, 2});
    this->headers.push_back({"Resources Count", std::to_string(ntohs(this->value->add_count)), 10, 2});

    const char* data = (const char*)_data + sizeof(*value);
    for(int i = 0; i < questionsCount; ++i)
    {
        header_t q("Query " + std::to_string(i + 1), "");
        q.pos = (long)(data - (const char*)_data);

        uint8_t len;
        std::string name;
        do {
            if((len = *((uint8_t*)(data++))) != 0)
            {
                name += std::string(data, len);
                name.push_back('.');
                data += len;
            }
        }while(len != 0);
        q.subHeaders.push_back({"Name", std::move(name), q.pos, (long)name.length() + 1});

        uint16_t temp;
        memcpy(&temp, data, 2);
        q.subHeaders.push_back({"Type", std::to_string(ntohs(temp)), data - (const char*)_data, 2});
        q.subHeaders.push_back({"Type", getTypeStr(ntohs(temp)), data - (const char*)_data, 2});
        data += 2;

        memcpy(&temp, data, 2);
        q.subHeaders.push_back({"Class", std::to_string(ntohs(temp)), data - (const char*)_data, 2});
        data += 2;

        q.len = (unsigned)name.length() + 5;
        this->headers.push_back(std::move(q));
    }
#pragma pack(push,1)
    const struct answer_t{
        uint16_t _magicNumber;
        uint16_t _type;
        uint16_t _class;
        uint32_t _ttl;
        uint16_t _dataLen;
    }* answer;
    static_assert(sizeof(struct answer_t) == 12, "check struct");
#pragma pack(pop)

    for(int i = 0; i < answersCount; ++i)
    {
        header_t q("Answer " + std::to_string(i + 1), "");
        q.pos = (long)(data - (const char*)_data);
        q.len = sizeof(answer_t);

        answer = (const answer_t*)data;
        data += sizeof(answer_t);

        q.subHeaders.push_back({"Type", std::to_string(ntohs(answer->_type)), q.pos + 2, 2});
        q.subHeaders.push_back({"Type", getTypeStr(ntohs(answer->_type)), q.pos + 2, 2});
        q.subHeaders.push_back({"Class", std::to_string(ntohs(answer->_class)), q.pos + 4, 2});
        q.subHeaders.push_back({"Time to Live", std::to_string(ntohl(answer->_ttl)), q.pos + 6, 4});

        long dataLen = ntohs(answer->_dataLen);
        q.len += dataLen;
        long dataPos = q.pos + sizeof(answer_t);

        switch(ntohs(answer->_type))
        {
            case 1:
                q.subHeaders.push_back({"IP Address", inet_ntoa(*((in_addr*)data)), dataPos, 4});
                break;
            case 5:
                q.subHeaders.push_back({"CNAME", std::string(data, dataLen), dataPos, dataLen});
                break;
        }
        data += dataLen;
        this->headers.push_back(std::move(q));
    }
}

std::string DNSPacket::getConversationFilterText() const
{
    std::string res("DNS.id==");
    res.append(id);
    return res;
}

bool DNSPacket::filter_id(const Packet* packet, const std::vector<std::string>* res)
{
    const DNSPacket* dns = static_cast<const DNSPacket*>(packet);
    return res->at(1) == dns->id;
}
