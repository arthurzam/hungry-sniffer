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

#ifndef DNSPACKET_H_
#define DNSPACKET_H_

#include "Protocol.h"

using namespace hungry_sniffer;

#pragma pack(push,1)
struct dnshdr
{
    uint16_t id; // identification number

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t qr: 1;          /* response flag */
    uint8_t opcode: 4;      /* purpose of message */
    uint8_t aa: 1;          /* authoritive answer */
    uint8_t tc: 1;          /* truncated message */
    uint8_t rd: 1;          /* recursion desired */

    uint8_t ra: 1;          /* recursion available */
    uint8_t unused : 3;     /* unused bits (MBZ as of 4.9.3a3) */
    uint8_t rcode : 4;      /* response code */
#else
    uint8_t rd : 1;         /* recursion desired */
    uint8_t tc : 1;         /* truncated message */
    uint8_t aa : 1;         /* authoritive answer */
    uint8_t opcode : 4;     /* purpose of message */
    uint8_t qr : 1;         /* response flag */

    uint8_t rcode : 4;      /* response code */
    uint8_t unused : 3;     /* unused bits (MBZ as of 4.9.3a3) */
    uint8_t ra : 1;         /* recursion available */
#endif

    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
};
#pragma pack(pop)

static_assert(sizeof(struct dnshdr) == 12, "check struct");

class DNSPacket : public PacketStructed<struct dnshdr>
{
    private:
        std::string id;
        unsigned size;
    public:
        DNSPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual ~DNSPacket() {}
        virtual std::string getConversationFilterText() const;
        virtual unsigned getLength() const
        {
            return this->size;
        }

        static bool filter_id(const Packet* packet, const std::vector<std::string>* res);
};

#endif /* DNSPACKET_H_ */
