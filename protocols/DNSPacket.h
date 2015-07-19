#ifndef DNSPACKET_H_
#define DNSPACKET_H_

#include "Protocol.h"

using namespace hungry_sniffer;

struct dnshdr {
        unsigned short id; // identification number

#if BYTE_ORDER == BIG_ENDIAN
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritive answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */

        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        rcode :4;       /* response code */
#else
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */

        unsigned        rcode :4;       /* response code */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif

        unsigned short q_count; // number of question entries
        unsigned short ans_count; // number of answer entries
        unsigned short auth_count; // number of authority entries
        unsigned short add_count; // number of resource entries
};


class DNSPacket : public PacketStructed<struct dnshdr> {
    private:
        struct query {
                std::string host;
                unsigned short t1;
                unsigned short t2;
        };

        std::vector<struct query> queries;
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
