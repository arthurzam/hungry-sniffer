#ifndef STATS_IPS_H
#define STATS_IPS_H

#include <QAbstractItemModel>
#include <QDialog>
#include "Protocol.h"

class StatsIpsModel : public QAbstractTableModel
{
    private:
        struct stat {
            int src;
            int dst;
        };
        std::map<std::string, struct stat> ips;
    public:
        explicit StatsIpsModel(QObject* parent = nullptr) : QAbstractTableModel(parent) {}

        int rowCount(const QModelIndex & = QModelIndex()) const
        {
            return ips.size();
        }

        int columnCount(const QModelIndex & = QModelIndex()) const
        {
            return 4;
        }

        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const;

        void add(const std::string& ip, int role);
        void update()
        {
            this->beginResetModel();
            this->endResetModel();
        }
};

class QTableView;
class StatsIps : public QDialog, public hungry_sniffer::StatWindow
{
    private:
        QTableView* tableView;
        StatsIpsModel model;

    public:
        explicit StatsIps(QWidget *parent = 0);
        ~StatsIps() {}

        virtual void addPacket(const hungry_sniffer::Packet* packet, const timeval&);
        virtual void showWindow();
};

#endif // STATS_IPS_H
