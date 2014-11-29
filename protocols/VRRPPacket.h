/*
 * VRRPPacket.h
 *
 *  Created on: Nov 23, 2014
 *      Author: arthur
 */

#ifndef VRRPPACKET_H_
#define VRRPPACKET_H_

#include "Protocol.h"

using namespace hungry_sniffer;

struct vrrphdr {
    union {
        uint8_t vers_type;
        struct {
#if BYTE_ORDER == BIG_ENDIAN
            unsigned char version :4; // type
            unsigned char type    :4; // version
#else
            unsigned char type    :4; // type
            unsigned char version :4; // version
#endif
        } vers_type_t;
    } vers_type;

    uint8_t  vrid;       /* virtual router id */
    uint8_t  priority;   /* router priority */
    uint8_t  naddr;      /* address counter */
    uint8_t  auth_type;  /* authentification type */
    uint8_t  adver_int;  /* advertissement interval(in sec) */
    uint16_t chksum;     /* checksum (ip-like one) */
    /* here <naddr> ip addresses */
    /* here authentification infos */
};

class VRRPPacket : public PacketStructed<struct vrrphdr> {
    public:
        VRRPPacket(const void* data, size_t len, const Protocol* protocol, const Packet* prev)
            : PacketStructed(data, len, protocol, prev) {}
        virtual void getLocalHeaders(headers_t& headers) const;
        virtual ~VRRPPacket() {}
};

#endif /* VRRPPACKET_H_ */
