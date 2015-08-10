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

#ifndef ETHERNETPACKET_H_
#define ETHERNETPACKET_H_

#include <QtGlobal>

#if defined(Q_OS_WIN)
struct __attribute__((packed)) ether_header
{
    char  ether_dhost[6];	/* destination eth addr	*/
    char  ether_shost[6];	/* source ether addr	*/
    uint16_t   ether_type;	/* packet type ID field	*/
};
#elif defined(Q_OS_UNIX)
    #include <netinet/ether.h>
#endif
#include "Protocol.h"

namespace hungry_sniffer {

    class EthernetPacket final : public PacketStructed<struct ether_header> {
        public:
            EthernetPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev = nullptr);

            virtual ~EthernetPacket() {}
            virtual std::string getConversationFilterText() const;
            virtual void updateNameAssociation();

            static bool filter_dstMac(const Packet* packet, const std::vector<std::string>* res);
            static bool filter_srcMac(const Packet* packet, const std::vector<std::string>* res);
    };

}

#endif /* ETHERNETPACKET_H_ */
