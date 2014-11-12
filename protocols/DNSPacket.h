/*
 * DNSPacket.h
 *
 *  Created on: Nov 8, 2014
 *      Author: arthur
 */

#ifndef DNSPACKET_H_
#define DNSPACKET_H_

#include "Protocol.h"

using namespace hungry_sniffer;

struct dnshdr {
        unsigned short id; // identification number
        union {
                unsigned short flags;
                struct {
# if __BYTE_ORDER == __BIG_ENDIAN
                        unsigned char qr :1; // query/response flag
                        unsigned char opcode :4; // purpose of message
                        unsigned char aa :1; // authoritive answer
                        unsigned char tc :1; // truncated message
                        unsigned char rd :1; // recursion desired

                        unsigned char ra :1; // recursion available
                        unsigned char z :1; // its z! reserved
                        unsigned char ad :1; // authenticated data
                        unsigned char cd :1; // checking disabled
                        unsigned char rcode :4; // response code
#else
                        unsigned char rd :1; // recursion desired
                        unsigned char tc :1; // truncated message
                        unsigned char aa :1; // authoritive answer
                        unsigned char opcode :4; // purpose of message
                        unsigned char qr :1; // query/response flag

                        unsigned char rcode :4; // response code
                        unsigned char cd :1; // checking disabled
                        unsigned char ad :1; // authenticated data
                        unsigned char z :1; // its z! reserved
                        unsigned char ra :1; // recursion available
#endif
                } flags_t;
        } flags;

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
    public:
        DNSPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev);
        virtual void getLocalHeaders(headers_t& headers) const;
        virtual ~DNSPacket()
        {
        }
};

#endif /* DNSPACKET_H_ */
