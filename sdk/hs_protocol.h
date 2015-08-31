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

#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <map>
#include <cstring>
#include <regex>
#include <list>
#include <vector>

#ifdef _MSC_VER
    #include <memory>
    #define CONSTEXPR const
#else
    #define CONSTEXPR constexpr
#endif

namespace hungry_sniffer {

    class Packet;

    namespace Preference {
        struct Preference;
    }

    namespace Option {
        typedef bool (*optionDisableFunction)(const void* data);

        struct enabledOption {
            std::string name;
            const void* data;
            optionDisableFunction disable_func;
        };

        /**
         * @brief the return flags that are returned from optionEnableFunction
         */
        enum ENABLE_OPTION_RETURN {
            ENABLE_OPTION_RETURN_ADDED_DISABLE = 0x1, /*!<Disable Rule was added*/
            ENABLE_OPTION_RETURN_RELOAD_TABLE = 0x2, /*!<Reload all the packets on table*/
            ENABLE_OPTION_RETURN_MALLOCED_DATA = 0x4, /*!<The data in disableOption is allocated*/
        };

        typedef std::vector<struct enabledOption> disabled_options_t;

        typedef int (*optionEnableFunction)(const Packet* packet, disabled_options_t& options);
    }

    /**
     * @brief class for holding data about protocol
     *
     * This class holds the initialize function to create Packet object and also associated data
     */
    class Protocol {
        private:
            struct option {
                std::string name;
                Option::optionEnableFunction func;
                bool isRootRequired;
            };

            enum FLAGS {
                FLAG_NAME_SERVICE = 0x1,
                FLAG_CONVERSATION = 0x2
            };

        public:
            typedef Packet* (*initFunction)(const void* data, size_t len,
                    const Protocol* protocol, const Packet* prev);
            typedef bool (*filterFunction)(const Packet*, const std::vector<std::string>*);

            typedef std::map<size_t, Protocol> protocols_t;
            typedef std::map<std::string, std::string> names_t;
            typedef std::vector<struct option> options_t;
            typedef std::vector<std::pair<std::regex, filterFunction>> filterFunctions_t;
        private:
            std::shared_ptr<protocols_t> subProtocols;
            initFunction function;

            std::string name; /*!<The name for the protocol*/

            mutable int countPackets = 0; /*!<The amount of packets sniffed of this Protocol*/

            names_t names; /*!<Name convertion*/
            filterFunctions_t filters;
            options_t options; /*!<Special Options*/

            uint8_t flags;
        public:
            const Preference::Preference* preferencePanel = nullptr;

            std::string websiteUrl;
            std::string fullName;

            static CONSTEXPR uint8_t getFlags(bool isNameService, bool isConversationEnabeled)
            {
                return (isNameService ? FLAGS::FLAG_NAME_SERVICE : 0) |
                       (isConversationEnabeled ? FLAGS::FLAG_CONVERSATION : 0);
            }

            /**
             * @brief basic constructor for creating Protocol from function pointer
             *
             * @param function pointer to function (created by init<>)
             */
            Protocol(initFunction function) :
                    subProtocols(std::make_shared<protocols_t>()),
                    name("unknown"),
                    filters()
            {
                this->function = function;
                this->flags = 0;
            }

            Protocol(initFunction function, const std::string& name, uint8_t flags = 0) :
                    subProtocols(std::make_shared<protocols_t>()),
                    name(name), filters()
            {
                this->function = function;
                this->flags = flags;
            }

            Protocol(const Protocol& other) :
                    subProtocols(other.subProtocols),
                    name(other.name), names(other.names),
                    filters(other.filters)
            {
                this->function = other.function;
                this->countPackets = other.countPackets;
                this->flags = other.flags;
            }

            Protocol(const Protocol& other, initFunction function, const std::string& name) :
                    subProtocols(other.subProtocols),
                    name(name), names(other.names),
                    filters(other.filters)
            {
                this->function = function;
                this->countPackets = other.countPackets;
                this->flags = other.flags;
            }

            Protocol(Protocol&& other) :
                    subProtocols(other.subProtocols),
                    name(std::move(other.name)), names(std::move(other.names)),
                    filters(std::move(other.filters))
            {
                this->function = other.function;
                this->countPackets = other.countPackets;
                this->flags = other.flags;
            }

            virtual ~Protocol()
            {
            }

            Protocol& addProtocol(size_t type, initFunction function,
                    const std::string& name = "unknown", uint8_t flags = 0)
            {
                return this->subProtocols->insert({type, Protocol(function, name, flags)}).first->second;
            }

            /**
             * @brief Add @c protocol to map in @c type
             * @param type the type to which the protocol will be associated
             * @param protocol Protocol object that will be added
             */
            Protocol& addProtocol(size_t type, Protocol&& protocol)
            {
                return this->subProtocols->insert({type, Protocol(std::move(protocol))}).first->second;
            }

            Protocol& addProtocol(size_t type, const Protocol& protocol, initFunction function, const std::string& name)
            {
                return this->subProtocols->insert({type, Protocol(protocol, function, name)}).first->second;
            }

            /**
             *  @brief  Access to Protocol.
             *
             *  @param  type  The type number of the protocol.
             *  @return  A pointer to the Protocol whose type is equivalent to @a type, if
             *           such a data is present in the protocols. Otherwise returns nullptr
             */
            const Protocol* getProtocol(size_t type) const
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
            Protocol& operator[](size_t type)
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
            const Protocol& operator[](size_t type) const
            {
                return subProtocols->at(type);
            }

            /**
             * @brief get the protocols container
             *
             * @return the protocols container
             */
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
             * @brief decrement count of packets
             */
            void decPacketCount() const
            {
                --this->countPackets;
            }

            /**
             * @brief get the count of packet within protocol
             *
             * @return the count of packets if count statistics is true, otherwise 0
             */
            int getPacketsCount() const
            {
                return this->countPackets;
            }

            /**
             * @brief return the Protocol's name
             */
            const std::string& getName() const
            {
                return this->name;
            }

            /**
             * @brief set filter for the regex, and the associated function
             *
             * when filter is searched, if the filter string matches the regex, the functoin will be called
             *
             * @param filterRegex the searching regex
             * @param function the called function
             *
             * @note don't add the protocol name is start of regex, it is added automatically
             */
            void addFilter(const std::string& filterRegex, filterFunction function)
            {
                this->filters.push_back({std::regex(filterRegex, std::regex_constants::icase), function});
            }

            /**
             * @brief get the filters container
             *
             * @return the filters container
             */
            const filterFunctions_t& getFilters() const
            {
                return this->filters;
            }

            /**
             * @brief tries to get protocol with the same name as given
             *
             * @param name the searching name of protocol
             * @return if found, the protocol. otherwise nullptr
             */
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

            /**
             * @brief get the associated name with key
             *
             * @param key the original name
             * @return the new, associated name
             */
            const std::string& getNameAssociated(const std::string& key) const
            {
                auto value = this->names.find(key);
                if(value == this->names.end())
                    return key;
                else
                    return value->second;
            }

            /**
             * @brief set associated name for key
             *
             * @param key the original name
             * @param value the new, associated name
             */
            void associateName(const std::string& key, const std::string& value)
            {
                this->names[key] = value;
            }

            /**
             * @brief remove the association from key
             *
             * @param key the original name
             */
            void removeNameAssociation(const std::string& key)
            {
                this->names.erase(key);
            }

            const names_t getNameService() const
            {
                return this->names;
            }

            /**
             * @brief returns if this protocol has naming association service
             * @return if this protocol has naming association service
             */
            bool getIsNameService() const
            {
                return (flags & FLAGS::FLAG_NAME_SERVICE) == FLAGS::FLAG_NAME_SERVICE;
            }

            bool getIsConversationEnabeled() const
            {
                return (flags & FLAGS::FLAG_CONVERSATION) == FLAGS::FLAG_CONVERSATION;
            }

            void addOption(const std::string& optionName, Option::optionEnableFunction func, bool rootNeeded = false)
            {
                this->options.push_back({optionName, func, rootNeeded});
            }

            const options_t& getOptions() const
            {
                return this->options;
            }
    };

    /**
     * @brief Abstract base class for all packets
     *
     * Every object of this type is creted by calling the creting function from Protocol class
     */
    class Packet {
        public:
            struct header_t{
                std::string key;
                std::string value;
                long pos;
                long len;
                std::vector<header_t> subHeaders;

                header_t() = delete;

                header_t(const std::string& key, const std::string& value) :
                    key(key), value(value), pos(0), len(0) {}

                template<typename T, typename E>
                header_t(const std::string& key, const std::string& value, T pos, E len) :
                    key(key), value(value), pos((long)pos), len((long)len) {}
            };

            typedef std::vector<header_t> headers_t;
        protected:
            const Protocol* protocol; /*!<The protocol by which this Packet was created*/
            Packet* next; /*!<The next packet*/
            const Packet* prev; /*!<The previous packet*/
            bool isGood = true; /*!<Is the packet not corrupted*/

            headers_t headers; /*!<The headers to be add to the tree*/

            std::string source; /*!<The displayed source*/
            std::string destination; /*!<The displayed destination*/

            std::string _realSource; /*!<The real source*/
            std::string _realDestination; /*!<The real destination*/

            std::string info; /*!<Info field*/
            const std::string* name; /*!<Name field*/

            uint32_t color; /*!<ARGB color*/
            static CONSTEXPR uint32_t calcColor(uint8_t red, uint8_t green, uint8_t blue, uint8_t alpha = 0xFF)
            {
                return ((alpha << 24) | (red << 16) | (green << 8) | blue);
            }

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
            bool setNext(size_t type, const void* data, size_t len)
            {
                const Protocol* p = this->protocol->getProtocol(type);
                if (p)
                {
                    this->next = p->getFunction()(data, len, p, this);
                    this->name = &this->next->getName();
                }
                return (p != nullptr);
            }

            Packet(const Packet&) = delete;
            Packet(Packet&&) = delete;

            Packet& operator=(const Packet&) = delete;
            Packet& operator=(Packet&&) = delete;
        public:
            /**
             * @brief basic constructor
             *
             * @param protocol the builder protocol
             * @param prev previous packet
             */
            Packet(const Protocol* protocol, const Packet* prev = nullptr)
            {
                this->next = nullptr;
                this->protocol = protocol;
                protocol->incPacketCount();
                this->prev = prev;
                this->name = &protocol->getName();
                this->color = 0;
            }

            /**
             * @brief delete current packet and next
             */
            virtual ~Packet()
            {
                delete this->next;
                protocol->decPacketCount();
            }

            /**
             * @brief get next Packet
             *
             * @return the next Packet
             */
            const Packet* getNext(int count = 1) const
            {
                const Packet* temp = this;
                for(int i = 0; i < count && temp; ++i)
                    temp = temp->next;
                return temp;
            }

            /**
             * @brief setNext set the next packet
             *
             * @param next the next in chain
             */
            void setNext(Packet* next)
            {
                this->next = next;
            }

            /**
             * @brief get the current protocol
             *
             * @return the current protocol
             */
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

            /**
             * @brief return color
             *
             * @return color
             */
            uint32_t getColor() const
            {
                return this->color;
            }

            virtual unsigned getLength() const = 0;

            /**
             * @brief get the packet (or sub packet) whose protocol is the same as given
             *
             * @param protocol the wanted protocol
             * @return the associated packet, or nullptr if not found
             */
            const Packet* hasProtocol(const Protocol* protocol) const
            {
                if(this->protocol == protocol)
                    return this;
                if(this->next)
                    return this->next->hasProtocol(protocol);
                return nullptr;
            }

            /**
             * @brief get current packet's source
             *
             * @return current packet's source
             * @note this source is after the check for name association
             */
            const std::string& localSource() const
            {
                return this->source;
            }

            /**
             * @brief get current packet's destination
             *
             * @return current packet's destination
             * @note this destination is after the check for name association
             */
            const std::string& localDestination() const
            {
                return this->destination;
            }

            /**
             * @brief get current packet's original source
             *
             * @return current packet's original source
             */
            const std::string& realSource() const
            {
                return this->_realSource;
            }

            /**
             * @brief get current packet's original destination
             *
             * @return current packet's original destination
             */const std::string& realDestination() const
            {
                return this->_realDestination;
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

            const headers_t& getHeaders() const
            {
                return this->headers;
            }

            /**
             * @brief get last packet's info string
             *
             * @return last packet's info string
             */
            const std::string& getInfo() const
            {
                if(this->next)
                {
                    const std::string& str = this->next->getInfo();
                    if(str.length() > 0)
                        return str;
                }
                return this->info;
            }

            virtual std::string getConversationFilterText() const
            {
                return this->protocol->getName();
            }

            /**
             * @brief update the fields that are dependent on naming service
             *
             * this function is called whenever naming service is changed
             * @note implement this function if the packet has naming service
             */
            virtual void updateNameAssociation() {}

            bool isGoodPacket() const
            {
                return this->isGood && (!this->next || this->next->isGoodPacket());
            }

            bool isLocalGood() const
            {
                return this->isGood;
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
