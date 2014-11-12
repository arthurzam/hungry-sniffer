#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <map>
#include <cstddef>
#include <iostream>
#include <cstring>
#include <functional>
#include <exception>
#include <regex>
#include <list>
#include <utility>

namespace hungry_sniffer {

    /**
     * @brief Exception for Truncated Packet
     */
    class TruncatedPacketException : public std::exception {
            virtual const char* what() const throw ()
            {
                return "Packet was Truncated";
            }
    };

    class Packet;

    /**
     * @brief class for holding data about protocol
     *
     * This class holds the initialize function to create Packet object and also associated data
     */
    class Protocol {
        private:
            typedef Packet* (*initFunction)(const void* data, size_t len,
                    const Protocol* protocol, const Packet* prev);
            typedef bool (*filterFunction)(const Packet*, const std::smatch&);

            typedef std::map<int, Protocol> protocols_t;
            typedef std::map<std::string, std::string> names_t;
            typedef std::map<std::string, filterFunction> filterFunctions_t;

            std::shared_ptr<protocols_t> subProtocols;
            initFunction function;

            std::string name; /*!<The name for the protocol*/

            bool isStats; /*!<is this Protocol part part of statistics calculations*/
            mutable int countPackets = 0; /*!<The amount of packets sniffed of this Protocol*/

            bool isNameService;
            names_t names;

            filterFunctions_t filters;
        public:
            /**
             * @brief basic constructor for creating Protocol from function pointer
             *
             * @param function pointer to function (created by init<>)
             *
             */
            Protocol(initFunction function) :
                    subProtocols(std::make_shared<protocols_t>()),
                    name("unknown")
            {
                this->function = function;
                this->isStats = true;
                this->isNameService = false;
            }

            Protocol(initFunction function, bool isStats, const std::string& name,
                    bool isNameService) :
                    subProtocols(std::make_shared<protocols_t>()),
                    name(name)
            {
                this->function = function;
                this->isStats = isStats;
                this->isNameService = isNameService;
            }

            Protocol(const Protocol& other) :
                    subProtocols(other.subProtocols),
                    name(other.name), names(other.names)
            {
                this->function = other.function;
                this->isStats = other.isStats;
                this->countPackets = other.countPackets;
                this->isNameService = other.isNameService;
            }

            Protocol(const Protocol& other, initFunction function, const std::string& name) :
                    subProtocols(other.subProtocols),
                    name(name), names(other.names)
            {
                this->function = function;
                this->isStats = other.isStats;
                this->countPackets = other.countPackets;
                this->isNameService = other.isNameService;
            }

            Protocol(Protocol&& other) :
                    subProtocols(other.subProtocols),
                    name(std::move(other.name)), names(std::move(other.names))
            {
                this->function = other.function;
                this->isStats = other.isStats;
                this->countPackets = other.countPackets;
                this->isNameService = other.isNameService;
            }

            virtual ~Protocol()
            {
            }

            void addProtocol(int type, initFunction function, bool isStats = true,
                    const std::string& name = "unknown", bool isNameService = false)
            {
                this->subProtocols->insert({type, Protocol(function, isStats, name, isNameService)});
            }

            /**
             * @brief Add @c protocol to map in @c type
             * @param type the type to which the protocol will be associated
             * @param protocol Protocol object that will be added
             */
            // TODO: add return non-const reference to Protocol in map. Use return value of insert.
            void addProtocol(int type, Protocol&& protocol)
            {
                this->subProtocols->insert({type, Protocol(std::move(protocol))});
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
                for (protocols_t::const_iterator i = subProtocols->cbegin();
                        i != subProtocols->cend(); ++i)
                {
                    count -= i->second.getPacketsCount();
                }
                return count;
            }

            /**
             * @brief return the Protocol's name
             */
            const std::string& getName() const
            {
                return this->name;
            }

            typedef std::list<std::pair<std::string, const int*>> stats_table_t;
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
                for (protocols_t::const_iterator i = subProtocols->cbegin();
                        i != subProtocols->cend(); ++i)
                {
                    i->second.getStats(stats);
                }
            }


            void addFilter(const std::string& filterRegex, filterFunction function)
            {
                this->filters.insert({filterRegex, function});
            }

            const filterFunctions_t& getFilters() const
            {
                return this->filters;
            }
    };

    /**
     * @brief Abstract base class for all packets
     *
     * Every object of this type is creted by calling the creting function from Protocol class
     */
    class Packet {
        public:
            typedef std::list<std::pair<std::string, std::string> > headers_category_t;
            typedef std::list<std::pair<std::string, headers_category_t> >  headers_t;
        protected:
            const Protocol* protocol; /*!<The protocol by which this Packet was created*/
            std::shared_ptr<Packet> next; /*!<The next packet*/
            const Packet* prev; /*!<The previous packet*/

            /**
             * @brief set the next packet
             *
             * A Protocol is chosen from the list with the given type, and sends the data and len to the constructor
             * @param type the type number of the sub Protocol
             * @param data pointer to the start of the next part
             * @param len total len from the start of next packet until end
             */
            bool setNext(int type, const void* data, size_t len)
            {
                const Protocol* p = this->protocol->getProtocol(type);
                if (p)
                    this->next = std::shared_ptr<Packet>((p->getFunction()(data, len, p, this)));
                return (p != nullptr);
            }

            virtual void getLocalHeaders(headers_t& headers) const = 0;
        public:
            Packet(const Protocol* protocol, const Packet* prev = nullptr)
            {
                this->next = nullptr;
                this->protocol = protocol;
                protocol->incPacketCount();
                this->prev = prev;
            }

            virtual ~Packet()
            {
                //this->protocol->decPacketCount(); // TODO: think if we really need to decrement
            }

            /**
             * @brief get next Packet
             *
             * @return the next Packet
             * @note Be sure there is a Packet next, or else an exception will be thrown
             */
            const Packet& getNext() const
            {
                return *next;
            }

            void setPrev(const Packet* prev)
            {
                this->prev = prev;
            }

            /**
             * @brief get last Packet
             *
             * @return the highest Packet
             */
            const Packet& getLast() const
            {
                if (this->next.get())
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
                if (this->next.get())
                    return this->next->getName();
                else
                    return this->protocol->getName();
            }

            const Packet* hasProtocol(const Protocol* protocol) const
            {
                if(this->protocol == protocol)
                    return this;
                if(this->next.get())
                    return this->next->hasProtocol(protocol);
                return nullptr;
            }

            virtual std::string source() const
            {
                return "";
            }

            virtual std::string destination() const
            {
                return "";
            }

            std::string getSource() const
            {
                if (this->next.get())
                {
                    std::string nextStr = this->next->getSource();
                    if (nextStr.length() != 0)
                        return nextStr;
                }
                return this->source();
            }

            std::string getDestination() const
            {
                if (this->next.get())
                {
                    std::string nextStr = this->next->getDestination();
                    if (nextStr.length() != 0)
                        return nextStr;
                }
                return this->destination();
            }

            void getHeaders(headers_t& headers) const
            {
                this->getLocalHeaders(headers);
                if(this->next.get())
                    this->next->getHeaders(headers);
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
                    throw TruncatedPacketException();
                memcpy(&value, data, sizeof(value));
            }
    };

    class PacketText : public Packet {
        protected:
            std::string data;
    };

    class PacketTextHeaders : public PacketText {
        protected:
            typedef std::map<std::string, std::string> headers_t;
            headers_t headers;

            /**
             *  @brief  Access to headers.
             *  @param  header  Header name
             *  @return  A reference to header data.
             *  @throw  std::out_of_range  If no such header is present.
             */
            const std::string& operator[](const std::string& header) const
            {
                return this->headers.at(header);
            }
    };

    class PacketEmpty : public Packet {
    protected:
        virtual std::string source() const
        {
            return this->prev->source();
        }

        virtual std::string destination() const
        {
            return this->prev->destination();
        }

        virtual std::ostream& print(std::ostream& out) const
        {
            return out;
        }
    public:
        PacketEmpty(const void*, size_t, const Protocol* protocol, const Packet* prev = nullptr) : Packet(protocol, prev) {}
        virtual ~PacketEmpty() {}
        virtual void getLocalHeaders(headers_t&) const {}

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

    inline size_t hash_combine(size_t seed, size_t part)
    {
        return ((seed ^ part) + 0x9e3779b9 + (seed << 6) + (seed >> 2));
    }
}
#endif /* PROTOCOL_H_ */
