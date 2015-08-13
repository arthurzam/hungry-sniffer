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

#ifndef ADDITIONALHEADERSPACKET_H
#define ADDITIONALHEADERSPACKET_H

#include "hs_protocol.h"

class AdditionalHeadersPacket : public hungry_sniffer::Packet {
    public:
        AdditionalHeadersPacket(const hungry_sniffer::Protocol* protocol)
            : Packet(protocol, nullptr) { }

        void addHeader(const std::string& key, const std::string& value)
        {
            this->headers.push_back({key, value});
        }

        void removeHeader(const std::string& key)
        {
            for(auto i = this->headers.begin(); i != this->headers.end(); ++i)
            {
                if(i->key == key)
                {
                    this->headers.erase(i);
                    return;
                }
            }
        }

        virtual unsigned getLength() const
        {
            return 0;
        }
};

#endif // ADDITIONALHEADERSPACKET_H

