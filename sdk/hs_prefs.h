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

#ifndef HS_PREFS
#define HS_PREFS

#include <list>

class QSettings;
class QWidget;

class HungrySniffer_Core;

namespace hungry_sniffer {
    namespace Preference {
        class Panel
        {
            public:
                virtual QWidget* get() = 0;
                virtual void save(QSettings& settings) = 0;

                virtual ~Panel() {}
        };

        typedef Panel* (*preferencesFunction_t)(const HungrySniffer_Core& core, QSettings& settings);

        struct Preference
        {
            std::string name;
            preferencesFunction_t func;
            std::list<Preference> subPreferences;

            Preference(const std::string& name, preferencesFunction_t func) :
                name(name), func(func) {}

            Preference(const std::string& name) :
                name(name), func(nullptr) {}

            Preference(const char* name) :
                name(name), func(nullptr) {}

            Preference& add(Preference&& pref)
            {
                subPreferences.push_back(std::move(pref));
                return subPreferences.back();
            }
        };
    }
}

#endif // HS_PREFS

