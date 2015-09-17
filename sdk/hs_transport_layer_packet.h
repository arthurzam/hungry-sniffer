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

#ifndef TRANSPORTLAYERPACKET_H
#define TRANSPORTLAYERPACKET_H

#include <hs_protocol.h>
#include <unordered_map>

/*! \cond docNever */
namespace std {
    template<>
    struct hash<hungry_sniffer::Packet*>
    {
        size_t operator()( const hungry_sniffer::Packet* p) const
        {
            return p->getHash();
        }
    };

    template<>
    struct equal_to<hungry_sniffer::Packet*>
    {
        bool operator()(const hungry_sniffer::Packet* x, const hungry_sniffer::Packet* y) const
        {
            return x->compare(y);
        }
    };
}
/*! \endcond docNever */

namespace hungry_sniffer {
    class TransportLayerConnections
    {
        protected:
            std::unordered_map<Packet*, Packet*> conns;
        public:
            EXPORT TransportLayerConnections();

            EXPORT void addToConns(Packet* packet);

            EXPORT Packet* getConnectionLast(Packet* packet);
    };
}

#endif
