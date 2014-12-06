#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <map>
#include <cstring>
#include <regex>
#include <list>

namespace hungry_sniffer {
    class Packet;

    /**
     * @brief class for holding data about protocol
     *
     * This class holds the initialize function to create Packet object and also associated data
     */
    class Protocol {
        public:
            typedef Packet* (*initFunction)(const void* data, size_t len,
                    const Protocol* protocol, const Packet* prev);
            typedef bool (*filterFunction)(const Packet*, const std::vector<std::string>&);

            typedef std::map<int, Protocol> protocols_t;
            typedef std::map<std::string, std::string> names_t;
            typedef std::list<std::pair<std::regex, filterFunction>> filterFunctions_t;
            typedef std::list<std::pair<std::string, const int*>> stats_table_t;
        private:
            std::shared_ptr<protocols_t> subProtocols;
            initFunction function;

            std::string name; /*!<The name for the protocol*/

            bool isStats; /*!<is this Protocol part part of statistics calculations*/
            mutable int countPackets = 0; /*!<The amount of packets sniffed of this Protocol*/

            bool isNameService;
            names_t names;

            filterFunctions_t filters;
            bool isConversationEnabeled;
        public:
            /**
             * @brief basic constructor for creating Protocol from function pointer
             *
             * @param function pointer to function (created by init<>)
             *
             */
            Protocol(initFunction function) :
                    subProtocols(std::make_shared<protocols_t>()),
                    name("unknown"),
                    filters(),
                    isConversationEnabeled(false)
            {
                this->function = function;
                this->isStats = true;
                this->isNameService = false;
            }

            Protocol(initFunction function, bool isStats, const std::string& name,
                    bool isNameService, bool isConversationEnabeled = false) :
                    subProtocols(std::make_shared<protocols_t>()),
                    name(name),
                    filters()
            {
                this->function = function;
                this->isStats = isStats;
                this->isNameService = isNameService;
                this->isConversationEnabeled = isConversationEnabeled;
            }

            Protocol(const Protocol& other) :
                    subProtocols(other.subProtocols),
                    name(other.name), names(other.names),
                    filters(other.filters)
            {
                this->function = other.function;
                this->isStats = other.isStats;
                this->countPackets = other.countPackets;
                this->isNameService = other.isNameService;
                this->isConversationEnabeled = other.isConversationEnabeled;
            }

            Protocol(const Protocol& other, initFunction function, const std::string& name) :
                    subProtocols(other.subProtocols),
                    name(name), names(other.names),
                    filters(other.filters)
            {
                this->function = function;
                this->isStats = other.isStats;
                this->countPackets = other.countPackets;
                this->isNameService = other.isNameService;
                this->isConversationEnabeled = other.isConversationEnabeled;
            }

            Protocol(Protocol&& other) :
                    subProtocols(other.subProtocols),
                    name(std::move(other.name)), names(std::move(other.names)),
                    filters(std::move(other.filters))
            {
                this->function = other.function;
                this->isStats = other.isStats;
                this->countPackets = other.countPackets;
                this->isNameService = other.isNameService;
                this->isConversationEnabeled = other.isConversationEnabeled;
            }

            virtual ~Protocol()
            {
            }

            Protocol& addProtocol(int type, initFunction function, bool isStats = true,
                    const std::string& name = "unknown", bool isNameService = false,
                    bool isConversationEnabeled = false)
            {
                return this->subProtocols->insert({type, Protocol(function, isStats, name, isNameService, isConversationEnabeled)}).first->second;
            }

            /**
             * @brief Add @c protocol to map in @c type
             * @param type the type to which the protocol will be associated
             * @param protocol Protocol object that will be added
             */
            Protocol& addProtocol(int type, Protocol&& protocol)
            {
                return this->subProtocols->insert({type, Protocol(std::move(protocol))}).first->second;
            }

            void addProtocol(int type, const Protocol& protocol, initFunction function, const std::string& name)
            {
                this->subProtocols->insert({type, Protocol(protocol, function, name)});
            }

            /**
             *  @brief  Access to Protocol.
             *
             *  @param  type  The type number of the protocol.
             *  @return  A pointer to the Protocol whose type is equivalent to @a type, if
             *           such a data is present in the protocols. Otherwise returns nullptr
             */
            const Protocol* getProtocol(int type) const
            {
                protocols_t::const_iterator res = subProtocols->find(type);
                if (res != subProtocols->end())
                    return &res->second;
                return nullptr;
            }

            /**
             *  @brief  Access to Protocol.
             *
             *  @param  type  The type number of the protocol.
             *  @return  A reference to the Protocol whose type is equivalent to @a type, if
             *           such a data is present in the protocols.
             *  @throw  std::out_of_range  If no such type is present.
             */
            Protocol& operator[](int type)
            {
                return subProtocols->at(type);
            }

            /**
             *  @brief  Access to const Protocol.
             *
             *  @param  type  The type number of the protocol.
             *  @return  A reference to the const Protocol whose type is equivalent to @a type, if
             *           such a data is present in the protocols.
             *  @throw  std::out_of_range  If no such type is present.
             */
            const Protocol& operator[](int type) const
            {
                return subProtocols->at(type);
            }

            const protocols_t& getProtocolsDB() const
            {
                return *this->subProtocols.get();
            }

            /**
             * @brief get Protocol's function
             *
             * @return Protocol's function
             */
            initFunction getFunction() const
            {
                return this->function;
            }

            /**
             * @brief increment count of packets
             */
            void incPacketCount() const
            {
                ++this->countPackets;
            }

            /**
             * @brief get the count of packet within protocol
             *
             * @return the count of packets if count statistics is true, otherwise 0
             */
            int getPacketsCount() const
            {
                return (this->countPackets & -(this->isStats));
            }

            /**
             * @brief return the raw packets count of this protocol
             * @return the raw packets count of this protocol
             */
            int getRawPacketsCount() const
            {
                int count = this->countPackets;
                for(auto& i : *subProtocols)
                {
                    count -= i.second.getPacketsCount();
                }
                return count;
            }

            /**
             * @brief reset the packet counter of this and evry sub-protocols
             */
            void cleanStats()
            {
                this->countPackets = 0;
                for(auto& i : *subProtocols)
                {
                    i.second.cleanStats();
                }
            }

            /**
             * @brief return the Protocol's name
             */
            const std::string& getName() const
            {
                return this->name;
            }

            /**
             * @brief return statistics table
             *
             * @param stats reference to a holder for the table that the statistics will be hold there.
             *
             * All the values inside the table are references to statistics in the protocols.
             * As a result, there is no need to calculate once again the table.
             */
            void getStats(stats_table_t& stats) const
            {
                if (this->isStats)
                    stats.push_back({name, &countPackets});
                for(auto& i : *subProtocols)
                {
                    i.second.getStats(stats);
                }
            }


            void addFilter(const std::string& filterRegex, filterFunction function)
            {
                this->filters.push_back({std::regex(filterRegex, std::regex_constants::icase), function});
            }

            const filterFunctions_t& getFilters() const
            {
                return this->filters;
            }

            const Protocol* findProtocol(const std::string& name) const
            {
                if(this->name == name)
                    return this;
                const Protocol* res;
                for(auto& i : *subProtocols)
                {
                    if((res = i.second.findProtocol(name)))
                        return res;
                }
                return nullptr;
            }

            const std::string& getNameAssociated(const std::string& key) const
            {
                auto value = this->names.find(key);
                if(value == this->names.end())
                    return key;
                else
                    return value->second;
            }

            void associateName(const std::string& key, const std::string& value)
            {
                this->names.insert({key, value});
            }

            bool getIsConversationEnabeled() const
            {
                return isConversationEnabeled;
            }
    };

    /**
     * @brief Abstract base class for all packets
     *
     * Every object of this type is creted by calling the creting function from Protocol class
     */
    class Packet {
        public:
            typedef std::list<std::pair<std::string, std::string>> headers_category_t;
            typedef std::list<std::pair<std::string, headers_category_t>>  headers_t;
        protected:
            const Protocol* protocol; /*!<The protocol by which this Packet was created*/
            Packet* next; /*!<The next packet*/
            const Packet* prev; /*!<The previous packet*/
            bool isGood = true;

            headers_category_t headers;
            std::string source;
            std::string destination;
            std::string info;
            const std::string* name;

            /**
             * @brief set the next packet
             *
             * A Protocol is chosen from the list with the given type, and sends the data and len to the constructor
             * @param type the type number of the sub Protocol
             * @param data pointer to the start of the next part
             * @param len total len from the start of next packet until end
             *
             * @note after the call to this function the name is set to the coresponding next name
             */
            bool setNext(int type, const void* data, size_t len)
            {
                const Protocol* p = this->protocol->getProtocol(type);
                if (p)
                {
                    this->next = p->getFunction()(data, len, p, this);
                    this->name = &this->next->getName();
                }
                return (p != nullptr);
            }
        public:
            Packet(const Protocol* protocol, const Packet* prev = nullptr)
            {
                this->next = nullptr;
                this->protocol = protocol;
                protocol->incPacketCount();
                this->prev = prev;
                this->name = &protocol->getName();
            }

            Packet(const Packet&) = delete;
            Packet(Packet&&) = delete;

            Packet& operator=(const Packet&) = delete;
            Packet& operator=(Packet&&) = delete;

            virtual ~Packet()
            {
                delete this->next;
            }

            /**
             * @brief get next Packet
             *
             * @return the next Packet
             */
            const Packet* getNext() const
            {
                return next;
            }

            const Protocol* getProtocol() const
            {
                return protocol;
            }

            /**
             * @brief get last Packet
             *
             * @return the highest Packet
             */
            const Packet& getLast() const
            {
                if (this->next)
                    return this->next->getLast();
                return *this;
            }

            /**
             * @brief return highest Packet's name
             *
             * @return highest Packet's name
             */
            const std::string& getName() const
            {
                return *this->name;
            }

            const Packet* hasProtocol(const Protocol* protocol) const
            {
                if(this->protocol == protocol)
                    return this;
                if(this->next)
                    return this->next->hasProtocol(protocol);
                return nullptr;
            }

            const std::string& localSource() const
            {
                return this->source;
            }

            const std::string& localDestination() const
            {
                return this->destination;
            }

            const std::string& getSource() const
            {
                if (this->next)
                {
                    const std::string& nextStr = this->next->getSource();
                    if (nextStr.length() != 0)
                        return nextStr;
                }
                return this->source;
            }

            const std::string& getDestination() const
            {
                if (this->next)
                {
                    const std::string& nextStr = this->next->getDestination();
                    if (nextStr.length() != 0)
                        return nextStr;
                }
                return this->destination;
            }

            void getHeaders(headers_t& headers) const
            {
                if(!this->headers.empty())
                    headers.push_back({this->protocol->getName(), this->headers});
                if(this->next)
                    this->next->getHeaders(headers);
            }

            const std::string& getInfo() const
            {
                return this->info;
            }

            virtual std::string getConversationFilterText() const
            {
                return this->protocol->getName();
            }
    };

    /**
     * @brief Templated Packet for use on structs
     *
     * @note Most useful when the protocol packets are binary and same structure.
     */
    template<typename T>
    class PacketStructed : public Packet {
        protected:
            T value;

            PacketStructed(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
                    Packet(protocol, prev)
            {
                if (len < sizeof(value))
                {
                    this->isGood = false;
                    return;
                }
                memcpy(&value, data, sizeof(value));
            }
    };

    class PacketText : public Packet {
        protected:
            std::string data;
        public:
            virtual std::string getInfo() const
            {
                return this->data;
            }

            PacketText(const void* data, size_t len, const Protocol* protocol, const Packet* prev) :
                Packet(protocol, prev),
                data((const char*)data, len) {}
    };

    class PacketTextHeaders : public Packet {
        protected:
            PacketTextHeaders(const Protocol* protocol, const Packet* prev) :
                Packet(protocol, prev) {}
    };

    class PacketEmpty : public Packet {
        public:
            PacketEmpty(const void*, size_t, const Protocol* protocol, const Packet* prev = nullptr)
                : Packet(protocol, prev) { }

            virtual ~PacketEmpty() {}

            virtual std::string getConversationFilterText() const
            {
                return this->protocol->getName();
            }
    };

    /**
     * @brief template helping function to be sent as initializer to Protocol.
     *
     * @example init<IPPacket>
     */
    template<typename T>
    Packet* init(const void* data, size_t len, const Protocol* protocol, const Packet* prev = nullptr)
    {
        return new T(data, len, protocol, prev);
    }
}
#endif /* PROTOCOL_H_ */
