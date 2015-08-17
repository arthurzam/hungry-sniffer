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

#ifndef PACKETSTATS_H
#define PACKETSTATS_H

#include <QDialog>

namespace hungry_sniffer {
    class Protocol;
}

class QStandardItem;
class QStandardItemModel;
class QTreeView;

/**
 * @brief Packet Statistics Dialog
 */
class PacketStats : public QDialog
{
    public:
        explicit PacketStats(QWidget *parent = 0);
        ~PacketStats();
    protected:
        void timerEvent(QTimerEvent *);

    private:
        QTreeView* treeView;

        int timerId;
        QStandardItemModel* model;

        struct node {
            int lastValue;
            const hungry_sniffer::Protocol* protocol;
            QStandardItem* itemValue;
        };
        std::vector<node> list;
        void addProtocol(const hungry_sniffer::Protocol* protocol, QStandardItem* father);
};

#endif // PACKETSTATS_H
