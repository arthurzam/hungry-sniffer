#ifndef ARPPACKET_H_
#define ARPPACKET_H_

#include "Protocol.h"
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

using namespace hungry_sniffer;

class ArpPacket : public PacketStructed<struct arphdr> {
    private:
        union __attribute__((packed)) {
            struct __attribute__((packed)) {
                uint8_t arp_sha[ETH_ALEN]; /* Sender hardware address.  */
                uint8_t arp_sip[4];        /* Sender IP address.  */
                uint8_t arp_tha[ETH_ALEN]; /* Target hardware address.  */
                uint8_t arp_tip[4];        /* Target IP address.  */
            } eth_ip;

            struct __attribute__((packed)) {
                uint8_t arp_sha[ETH_ALEN]; /* Sender hardware address.  */
                struct in6_addr arp_sip;   /* Sender IP address.  */
                uint8_t arp_tha[ETH_ALEN]; /* Target hardware address.  */
                struct in6_addr arp_tip;   /* Target IP address.  */
            } eth_ipv6;
        } data;
        unsigned size;

    public:
        ArpPacket(const void* data, size_t len, const Protocol* protocol,
                const Packet* prev);

        virtual ~ArpPacket() {}

        virtual unsigned getLength() const
        {
            return size;
        }
};

#endif /* ARPPACKET_H_ */
