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

#ifndef HS_ADVANCED_PACKETS
#define HS_ADVANCED_PACKETS

#include <hs_protocol.h>

namespace hungry_sniffer {
    /**
     * @brief Templated Packet for use on structs
     *
     * @note Most useful when the protocol packets are binary and based on a structure.
     */
    template<typename T>
    class PacketStructed : public Packet
    {
        protected:
            const T* value; /*!<the struct*/

            PacketStructed(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
                Packet(protocol, prev)
            {
                if (len < sizeof(*value))
                {
                    this->isGood = false;
                    value = nullptr;
                    return;
                }
                value = (const T*)data;
            }
        public:
            virtual unsigned getLength() const
            {
                return sizeof(*value);
            }
    };

    class PacketText : public Packet
    {
        protected:
            std::vector<char> data;
        public:

            PacketText(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
                Packet(protocol, prev),
                data((const char*)data, (const char*)data + len)
            {
                std::replace(this->data.begin(), this->data.end(), '\r', ' ');
            }

            virtual void updateNameAssociation()
            {
                static CONSTEXPR int MAX_INFO_LEN = 1024;
                auto start = data.cbegin(), end = data.cend();
                while(*start == ' ' && start != end)
                    ++start;
                while(*(end - 1) == ' ' && start != end)
                    --end;
                this->info.clear();
                if(end - start > MAX_INFO_LEN)
                    end = start + MAX_INFO_LEN;
                this->info.append(start, end);

                this->headers.clear();
                this->headers.push_back(header_t("Data", this->info, 0, data.size()));

                auto newL = std::find(info.begin(), info.end(), '\n');
                if(newL != info.end())
                {
                    this->info.erase(newL);
                    this->info.append(" ...");
                }
            }

            virtual unsigned getLength() const
            {
                return (unsigned)data.size();
            }
    };

    class PacketTextHeaders : public PacketText
    {
        protected:
            PacketTextHeaders(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
                PacketText(data, len, protocol, prev) {}

            /**
             * @brief extract headers that are separated by colon or newline
             *
             * @param start the start index
             * @param end the end index
             */
            void extractTextHeaders(std::vector<char>::iterator start, std::vector<char>::iterator end, long startPos)
            {
                std::vector<char>::iterator origStart = start;
                auto colon = start,
                     endLine = start,
                     part = start;
                while(start < end)
                {
                    static const char search1[] = ":\n";
                    colon = std::find_first_of(start, end, search1, search1 + 2);
                    if(colon == end)
                        return;
                    switch(colon[0])
                    {
                        case ':':
                            endLine = std::find(colon, end, '\n');
                            part = colon + 1;
                            while(part[0] == ' ')
                                part++;
                            if(endLine[-1] == '\r')
                                *(endLine - 1) = ' ';
                            break;
                        case '\n':
                            endLine = part = colon;
                            break;
                    }
                    this->headers.push_back({std::string(start, colon),
                                             std::string(part, endLine), startPos + (start - origStart), endLine - start
                                            });
                    start = endLine + 1;
                }
            }
    };

    class PacketEmpty final : public Packet
    {
        public:
            PacketEmpty(const void*, size_t, const Protocol* protocol, const Packet* prev = nullptr)
                : Packet(protocol, prev) { }

            virtual ~PacketEmpty() {}

            virtual std::string getConversationFilterText() const
            {
                return this->protocol->getName();
            }

            virtual unsigned getLength() const
            {
                return 0;
            }
    };
}

#endif // HS_ADVANCED_PACKETS

