#ifndef SNIFF_WINDOW_H
#define SNIFF_WINDOW_H

#include <QMainWindow>
#include <pcap++.h>
#include "ThreadQueue.h"
#include <thread>
#include <QTableWidgetItem>

namespace Ui {
class SniffWindow;
}

namespace hungry_sniffer {
class Protocol;
class Packet;
}

class SniffWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit SniffWindow(QWidget *parent = 0);
    ~SniffWindow();

    static hungry_sniffer::Protocol* baseProtocol;

private slots:
    void on_actionOpen_triggered();

    void on_tb_filter_textEdited(const QString &arg1);

    void on_bt_filter_clear_clicked();

    void on_table_packets_currentItemChanged(QTableWidgetItem *current, QTableWidgetItem *previous);

    void on_actionSave_triggered();

    void on_actionStop_triggered();

    void on_actionSniff_triggered();

private:
    Ui::SniffWindow *ui;

    ThreadSafeQueue<pcappp::Packet> toAdd;
    QList<pcappp::Packet> local;
    QList<std::thread*> threads;
    bool toNotStop;

public:
    void addPacket(const pcappp::Packet& packet);

    void runLivePcap(const std::string& name);
    void runOfflinePcap(const std::string& filename);

    void managePacketsList();

private:
    void runLivePcap_p(const std::string& name);
    void runOfflinePcap_p(const std::string& filename);

private:
    void setCurrentPacket(const pcappp::Packet& packet);
    void addPacketTable(const hungry_sniffer::Packet& packet);
};


#endif // SNIFF_WINDOW_H
