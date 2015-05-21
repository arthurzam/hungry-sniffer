#ifndef PACKETSTATS_H
#define PACKETSTATS_H

#include <QDialog>
#include <QTreeWidgetItem>

namespace Ui {
    class PacketStats;
}

namespace hungry_sniffer {
    class Protocol;
}

/**
 * @brief Packet Statistics Dialog
 */
class PacketStats : public QDialog
{
        Q_OBJECT

    public:
        explicit PacketStats(QWidget *parent = 0);
        ~PacketStats();

    private slots:
        /**
         * @brief setStats refrash the stats shown in the tree
         */
        void setStats();

    private:
        /**
         * @brief setStatsPerProtocol refrash the stats shown in the tree of protocol under current item
         *
         * @param protocol the protocol to add and take from his children protocols
         * @param currentItem item to where add the sub item of tree
         */
        void setStatsPerProtocol(const hungry_sniffer::Protocol* protocol, QTreeWidgetItem* currentItem);

    private:
        Ui::PacketStats *ui;
};

#endif // PACKETSTATS_H
