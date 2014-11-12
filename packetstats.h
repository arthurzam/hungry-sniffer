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

class PacketStats : public QDialog
{
    Q_OBJECT

public:
    explicit PacketStats(QWidget *parent = 0);
    ~PacketStats();

private slots:
    void setStats();

private:
    void setStatsPerProtocol(const hungry_sniffer::Protocol* protocol, QTreeWidgetItem* currentItem);

private:
    Ui::PacketStats *ui;
};

#endif // PACKETSTATS_H
