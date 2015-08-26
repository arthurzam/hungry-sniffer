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

#include "stats_length.h"
#include <QTableView>
#include <QBoxLayout>
#include <QHeaderView>
#include <hs_protocol.h>

using namespace hungry_sniffer;

StatsLength::StatsLength()
{
    this->resize(400, 250);
    this->setAttribute(Qt::WA_DeleteOnClose);
    this->setWindowTitle(QStringLiteral("packet length"));

    QVBoxLayout* verticalLayout = new QVBoxLayout(this);
    QTableView* tableView = new QTableView(this);
    tableView->setModel(&model);
    tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    tableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    verticalLayout->addWidget(tableView);
}

void StatsLength::addPacket(const Packet*, const timeval&, const uint8_t*, size_t len)
{
    int i = 0;
    for(; StatsLengthModel_lengths[i] <= len; i++);
    struct StatsLengthModel::stat& part = model.parts[i - 1];
    model.totalCount++;
    part.count++;
    if(part.max < len)
        part.max = (uint32_t)len;
    if(part.min > len)
        part.min = (uint32_t)len;
}

void StatsLength::showWindow()
{
    model.beginResetModel();
    model.endResetModel();
    this->show();
}

QVariant StatsLengthModel::data(const QModelIndex& index, int role) const
{
    if(role == Qt::ItemDataRole::DisplayRole)
    {
        int row = index.row();
        switch(index.column())
        {
            case 0:
                return QStringLiteral("%1-%2").arg(StatsLengthModel_lengths[row]).arg(StatsLengthModel_lengths[row + 1]);
            case 1:
                return QVariant(parts[row].count);
            case 2:
                if(parts[row].count == 0)
                    return QStringLiteral("-");
                return QVariant(parts[row].min);
            case 3:
                if(parts[row].count == 0)
                    return QStringLiteral("-");
                return QVariant(parts[row].max);
            case 4:
                if(totalCount == 0)
                    return QStringLiteral("-");
                return QStringLiteral("%1%").arg((float)(parts[row].count * 100) / totalCount, 0, 'f', 2);
        }
    }
    return QVariant();
}

QVariant StatsLengthModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    static const QString headers[] = {QStringLiteral("Range"), QStringLiteral("Count"), QStringLiteral("Min Val"),
                                      QStringLiteral("Max Val"), QStringLiteral("Percent")};
    if ((role == Qt::DisplayRole) & (orientation == Qt::Horizontal))
    {
        return headers[section];
    }

    return QVariant();
}
