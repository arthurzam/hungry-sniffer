#ifndef ADDITIONALHEADERSPACKET_H
#define ADDITIONALHEADERSPACKET_H

#include "Protocol.h"

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
                if(i->first == key)
                {
                    this->headers.erase(i);
                    return;
                }
            }
        }
};

#endif // ADDITIONALHEADERSPACKET_H

