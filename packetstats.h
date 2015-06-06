#ifndef PACKETSTATS_H
#define PACKETSTATS_H

#include <QDialog>

namespace Ui {
    class PacketStats;
}

namespace hungry_sniffer {
    class Protocol;
}

class QStandardItem;
class QStandardItemModel;

/**
 * @brief Packet Statistics Dialog
 */
class PacketStats : public QDialog
{
        Q_OBJECT

    public:
        explicit PacketStats(QWidget *parent = 0);
        ~PacketStats();
    protected:
        void timerEvent(QTimerEvent *);
    private slots:
        /**
         * @brief setStats refrash the stats shown in the tree
         */
        void setStats();

    private:
        Ui::PacketStats *ui;
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
