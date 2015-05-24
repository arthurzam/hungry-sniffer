#ifndef SNIFF_WINDOW_H
#define SNIFF_WINDOW_H

#include <atomic>
#include <pcap++.h>
#include <QMainWindow>
#include <QTableWidgetItem>
#include <thread>

#include "filter_tree.h"
#include "optionsdisabler.h"
#include "ThreadQueue.h"

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
        static hungry_sniffer::Protocol infoProtocol;

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
        void on_tree_packet_customContextMenuRequested(const QPoint &pos);
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
        void closeEvent(QCloseEvent *bar);

    private:
        Ui::SniffWindow *ui;

    public:
        struct RawPacketData {
            uint32_t len;
            timeval time;
            char* data;

            constexpr RawPacketData() : len(0), time({0,0}), data(nullptr) {}
            RawPacketData(const pcappp::Packet& packet);
            RawPacketData(const RawPacketData& other);
            RawPacketData(RawPacketData&& other);
            RawPacketData& operator=(const RawPacketData& other);
            RawPacketData& operator=(RawPacketData&& other);
            ~RawPacketData();
        };

        struct localPacket {
            RawPacketData rawPacket;
            std::shared_ptr<hungry_sniffer::EthernetPacket> decodedPacket;
            time_t _time;
            bool isShown;
        };
        std::vector<struct localPacket> local;
        struct localPacket* selected = nullptr;
    private:
        ThreadSafeQueue<RawPacketData> toAdd;

        std::vector<std::thread*> threads;
        bool toNotStop;
        bool isNotExiting;
        std::thread manageThread;

        std::unique_ptr<FilterTree> filterTree;
        std::atomic<bool> isCalculatingFilter;

        OptionsDisabler optionsDisablerWin;

    public:
        void runLivePcap(const std::string& name);
        void runOfflineFile(const std::string& filename);

    private:
        void runLivePcap_p(const std::string& name);
        void runOfflineOpen_p(const std::string& filename);
        void managePacketsList();

    private:
        void setCurrentPacket(const struct localPacket& pack);
        void addPacketTable(const struct localPacket &local, int number);
        void updateTableShown();
        void reloadAllPackets(const hungry_sniffer::Protocol* protocol);

        void setTableHeaders();
        void associateName(const hungry_sniffer::Packet* localPacket, const std::string& origText);

        void setOutputFunctions();

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

            void reset()
            {
                block = false;
                bracketsC = 0;
                bracketsS = 0;
                bracketsM = 0;
            }
        } py_checkCommand;
#endif
};

#endif // SNIFF_WINDOW_H
