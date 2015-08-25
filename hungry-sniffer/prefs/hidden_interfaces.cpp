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

#include "hidden_interfaces.h"

#include <QSettings>

using namespace hungry_sniffer::Preference;

hidden_interfaces::hidden_interfaces() : InterfaceSelector(QStringList())
{
}

void hidden_interfaces::save(QSettings& settings)
{
    settings.setValue(QStringLiteral("HiddenInf"), this->getSelected());
}

Panel* hidden_interfaces::init(const HungrySniffer_Core&, QSettings& settings)
{
    hidden_interfaces* hid = new hidden_interfaces();
    hid->select(settings.value(QStringLiteral("HiddenInf")).toStringList());
    return hid;
}