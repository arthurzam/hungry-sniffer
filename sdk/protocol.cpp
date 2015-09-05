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

#include "hs_protocol.h"

using namespace hungry_sniffer;

Protocol::Protocol(initFunction function) :
    subProtocols(std::make_shared<protocols_t>()),
    name("unknown"),
    filters()
{
    this->function = function;
    this->flags = 0;
}

Protocol::Protocol(Protocol::initFunction function, const std::string& name, uint8_t flags) :
    subProtocols(std::make_shared<protocols_t>()),
    name(name), filters()
{
    this->function = function;
    this->flags = flags;
}

Protocol::Protocol(const Protocol& other) :
    subProtocols(other.subProtocols),
    name(other.name), names(other.names),
    filters(other.filters)
{
    this->function = other.function;
    this->countPackets = other.countPackets;
    this->flags = other.flags;
}

Protocol::Protocol(const Protocol& other, Protocol::initFunction function, const std::string& name) :
    subProtocols(other.subProtocols),
    name(name), names(other.names),
    filters(other.filters)
{
    this->function = function;
    this->countPackets = other.countPackets;
    this->flags = other.flags;
}

Protocol::Protocol(Protocol&& other) :
    subProtocols(other.subProtocols),
    name(std::move(other.name)), names(std::move(other.names)),
    filters(std::move(other.filters))
{
    this->function = other.function;
    this->countPackets = other.countPackets;
    this->flags = other.flags;
}

Protocol& Protocol::addProtocol(size_t type, Protocol&& protocol)
{
    return this->subProtocols->insert({type, Protocol(std::move(protocol))}).first->second;
}

Protocol& Protocol::addProtocol(size_t type, Protocol::initFunction function, const std::string& name, uint8_t flags)
{
    return this->subProtocols->insert({type, Protocol(function, name, flags)}).first->second;
}

Protocol& Protocol::addProtocol(size_t type, const Protocol& protocol, Protocol::initFunction function, const std::string& name)
{
    return this->subProtocols->insert({type, Protocol(protocol, function, name)}).first->second;
}

void Protocol::addFilter(const std::string& filterRegex, Protocol::filterFunction function)
{
    this->filters.push_back({std::regex(filterRegex, std::regex_constants::icase | std::regex_constants::optimize), function});
}

const std::string& Protocol::getNameAssociated(const std::string& key) const
{
    auto value = this->names.find(key);
    if(value == this->names.end())
        return key;
    else
        return value->second;
}

void Protocol::addOption(const std::string& optionName, Option::optionEnableFunction func, bool rootNeeded)
{
    this->options.push_back({optionName, func, rootNeeded});
}
