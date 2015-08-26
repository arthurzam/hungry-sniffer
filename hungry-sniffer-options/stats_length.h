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

#ifndef STATSLENGTH_H
#define STATSLENGTH_H

#include <QAbstractItemModel>
#include <QDialog>

#include <hs_stats.h>

namespace hungry_sniffer {
    class Packet;
}

static uint32_t StatsLengthModel_lengths[] = {0, 20, 40, 80, 160, 320, 640, 1280, 2560, UINT32_MAX};

class StatsLengthModel : public QAbstractTableModel
{
        friend class StatsLength;
    private:
        struct stat
        {
            uint32_t count = 0;
            uint32_t min = UINT32_MAX;
            uint32_t max = 0;
        };
        uint32_t totalCount = 0;

        static Q_CONSTEXPR unsigned LENGTH = sizeof(StatsLengthModel_lengths) / sizeof(uint32_t) - 1;
        struct stat parts[LENGTH];

    public:
        StatsLengthModel() {}

        int rowCount(const QModelIndex& = QModelIndex()) const
        {
            return LENGTH;
        }

        int columnCount(const QModelIndex& = QModelIndex()) const
        {
            return 5;
        }

        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const;
};

class StatsLength : public QDialog, public hungry_sniffer::Stats::StatWindow
{
    private:
        StatsLengthModel model;

    public:
        StatsLength();
        ~StatsLength() {}

        virtual void addPacket(const hungry_sniffer::Packet*, const struct timeval&, const uint8_t*, size_t len);
        virtual void showWindow();

        static StatWindow* init(const HungrySniffer_Core&)
        {
            return new StatsLength();
        }
};

#endif // STATS_IPS_H
