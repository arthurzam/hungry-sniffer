#ifndef SNIFF_WINDOW_H
#define SNIFF_WINDOW_H

#include <QMainWindow>
#include <pcap++.h>
#include "ThreadQueue.h"
#include <thread>
#include <QTableWidgetItem>
#include <ctime>
#include "EthernetPacket.h"
#include "filter_tree.h"
#include "optionsdisabler.h"
#include <atomic>

namespace Ui {
    class SniffWindow;
}

class SniffWindow : public QMainWindow
{
        Q_OBJECT

    public:
        explicit SniffWindow(QWidget *parent = 0);
        ~SniffWindow();

        static HungrySniffer_Core* core;
        static SniffWindow* window;

        static bool isRoot();

    private slots:
        void on_actionOpen_triggered();

        void on_tb_filter_textEdited(const QString &arg1);

        void on_bt_filter_clear_clicked();

        void on_table_packets_currentItemChanged(QTableWidgetItem *current, QTableWidgetItem *previous);

        void on_actionSave_triggered();

        void on_actionStop_triggered();

        void on_actionSniff_triggered();

        void on_actionTable_triggered();

        void on_bt_filter_apply_clicked();

        void on_actionClear_triggered();

        void on_table_packets_customContextMenuRequested(const QPoint &pos);

        void on_actionDisableOptions_triggered();

#ifdef PYTHON_CMD
        void on_tb_command_returnPressed();
#else
        void on_tb_command_returnPressed() {}
#endif
        void on_action_Table_toggled(bool arg1);

        void on_action_Tree_toggled(bool arg1);

        void on_action_Hex_toggled(bool arg1);

        void on_action_Python_toggled(bool arg1);

        void on_splitter_splitterMoved(int, int);

    protected:
        void dragEnterEvent(QDragEnterEvent* event);
        void dropEvent(QDropEvent* event);

    private:
        Ui::SniffWindow *ui;

    public:
        std::shared_ptr<pcappp::Pcap> firstPcap = nullptr;
        struct localPacket {
            pcappp::Packet rawPacket;
            std::shared_ptr<EthernetPacket> decodedPacket;
            time_t _time;
            bool isShown;
        };
        QVector<struct localPacket> local;
    private:

        ThreadSafeQueue<pcappp::Packet> toAdd;

        QList<std::thread*> threads;
        bool toNotStop;
        bool isNotExiting;
        std::thread manageThread;

        std::unique_ptr<FilterTree> filterTree;
        std::atomic<bool> isCalculatingFilter;

        OptionsDisabler optionsDisablerWin;

    public:
        void runLivePcap(const std::string& name);
        void runOfflinePcap(const std::string& filename);

        void managePacketsList();

    private:
        void runLivePcap_p(const std::string& name);
        void runOfflinePcap_p(const std::string& filename);

    private:
        void setCurrentPacket(const struct localPacket& pack);
        void addPacketTable(const struct localPacket &local, int number);
        void updateTableShown();
        void reloadAllPackets(const hungry_sniffer::Protocol* protocol);

        void setTableHeaders();
        void associateName(const hungry_sniffer::Packet* localPacket, const std::string& origText);

        void setOutputFunctions();

        void closeEvent(QCloseEvent *bar);

#ifdef PYTHON_CMD
    private:
        void initPython();
        void stopPython();

        void addPyCommand(const char* pyCommand);
        void execPyCommand();
        bool checkPyCommand(const char* pyCommand);

    private:
        void* pyGlobals;
        void* pyCatcher;

        std::string pyCommand;
        struct {
            int bracketsC = 0; // '(' ')'
            int bracketsS = 0; // '[' ']'
            int bracketsM = 0; // '{' '}'

            bool block = false;// :
        } py_checkCommand;
#endif
};


#endif // SNIFF_WINDOW_H
