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

#ifndef STATS_IPS_H
#define STATS_IPS_H

#include <QAbstractItemModel>
#include <QDialog>

#include <hs_stats.h>

namespace hungry_sniffer {
    class Packet;
    class Protocol;
}

class StatsEndpointsModel : public QAbstractTableModel
{
        friend class StatsEndpoints;
    private:
        struct stat
        {
            int src;
            int dst;
        };
        std::map<std::string, struct stat> endpoints;
    public:
        StatsEndpointsModel() {}

        int rowCount(const QModelIndex& = QModelIndex()) const
        {
            return (int)endpoints.size();
        }

        int columnCount(const QModelIndex& = QModelIndex()) const
        {
            return 4;
        }

        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const;

        void add(const std::string& addr, int role);
};

class StatsEndpoints : public QDialog, public hungry_sniffer::Stats::StatWindow
{
    private:
        StatsEndpointsModel model;
        const hungry_sniffer::Protocol* protocol;

    public:
        StatsEndpoints(const hungry_sniffer::Protocol* protocol);
        ~StatsEndpoints() {}

        virtual void addPacket(const hungry_sniffer::Packet* packet, const struct timeval&, const uint8_t*, size_t);
        virtual void showWindow();
};

#endif // STATS_IPS_H
