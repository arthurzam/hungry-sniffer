#ifndef PACKETSTATS_H
#define PACKETSTATS_H

#include <QDialog>
#include "Protocol.h"

namespace Ui {
class PacketStats;
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
    Ui::PacketStats *ui;
    hungry_sniffer::Protocol::stats_table_t table;
};

#endif // PACKETSTATS_H
