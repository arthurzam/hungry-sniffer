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

#ifndef HS_STATS_H
#define HS_STATS_H

#ifdef _MSC_VER
    #include <WinSock2.h>
#else
    #include <ctime>
#endif
#include <cstdint>
#include <string>
#include <list>

namespace hungry_sniffer {
    class Packet;

    namespace Stats {
        class StatWindow
        {
            public:
                virtual void addPacket(const Packet* packet, const struct timeval& time, const uint8_t* data, size_t length) = 0;
                virtual void showWindow() = 0;

                virtual ~StatWindow() {}
        };
        typedef StatWindow* (*statInitFunction)();

        struct StatsNode {
            std::string name;
            statInitFunction func;

            std::list<struct StatsNode> subNodes;

            StatsNode(const char* name) : name(name), func(nullptr) {}
            StatsNode(const std::string& name, statInitFunction func) : name(name), func(func) {}

            struct StatsNode& add(struct StatsNode&& node)
            {
                subNodes.push_back(std::move(node));
                return subNodes.back();
            }
        };
    }
}

#endif // HS_STATS_H

