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
