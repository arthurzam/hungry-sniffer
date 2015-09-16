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

#ifndef CORE_H
#define CORE_H

#include <hs_protocol.h>
#include <hs_prefs.h>
#include <hs_stats.h>

struct HungrySniffer_Core {
    EXPORT static struct HungrySniffer_Core* core; /*!<Global pointer to the cross module singelton of HungrySniffer_Core*/

    hungry_sniffer::Protocol& base; /*!<The first level Protocol*/

    std::list<hungry_sniffer::Preference::Preference> preferences; /*!<preferences tree*/
    std::list<struct hungry_sniffer::Stats::StatsNode> stats; /*!<stats window tree*/

    HungrySniffer_Core(hungry_sniffer::Protocol& base)
        : base(base) {}

    /**
     * @brief add the preference to the preferences tree on first level
     *
     * @param pref the preference to be added
     * @return reference to the added one in its location in tree
     */
    hungry_sniffer::Preference::Preference& addProtocolPreference(hungry_sniffer::Preference::Preference&& pref)
    {
        preferences.push_back(std::move(pref));
        return preferences.back();
    }

    /**
     * @brief add the stat window to the stats window tree on first level
     *
     * @param node the stat window to be added
     * @return reference to the added one in its location in tree
     */
    struct hungry_sniffer::Stats::StatsNode& addStatWindow(struct hungry_sniffer::Stats::StatsNode&& node)
    {
        stats.push_back(std::move(node));
        return stats.back();
    }
};

#endif // CORE_H
