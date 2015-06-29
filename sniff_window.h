#ifndef SNIFF_WINDOW_H
#define SNIFF_WINDOW_H

#include <atomic>
#include <QMainWindow>

#include "optionsdisabler.h"
#include "ThreadQueue.h"
#include "packetstable_model.h"

namespace Ui {
    class SniffWindow;
}

class PacketStats;
class QSortFilterProxyModel;

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
    signals:
        void sig_showMessageBox(const QString& title, const QString& text);
    public slots:
        void on_actionOpen_triggered();
        void on_tb_filter_textEdited(const QString &arg1);
        void on_bt_filter_clear_clicked();
        void on_action_save_all_triggered();
        void on_action_save_shown_triggered();
        void on_actionStop_triggered();
        void on_actionSniff_triggered();
        void on_actionTable_triggered();
        void on_bt_filter_apply_clicked();
        void on_action_remove_all_triggered();
        void on_action_remove_shown_triggered();
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

        void model_currentRowChanged(QModelIndex newSelection,QModelIndex oldSelection);
        void showMessageBox(const QString& title, const QString& text);

    protected:
        void dragEnterEvent(QDragEnterEvent* event);
        void dropEvent(QDropEvent* event);
        void closeEvent(QCloseEvent *bar);

    public:
        Ui::SniffWindow *ui;
        QSortFilterProxyModel* m_sortFilterProxy;
        PacketsTableModel model;
        PacketStats* statsTable;

        DataStructure::localPacket* selected = nullptr;
        ThreadSafeQueue<DataStructure::RawPacketData> toAdd;
    private:

        std::vector<std::thread*> threads;
        bool toNotStop;
        bool isNotExiting;
        std::thread manageThread;

        std::atomic<FilterTree*> filterTree;

        OptionsDisabler optionsDisablerWin;

    public:
        void runLivePcap(const std::string& name, int maxNumber, QString capture);
        void runOfflineFile(const std::string& filename);

    private:
        void runLivePcap_p(const std::string& name, int maxNumber, QString capture);
        void runOfflineOpen_p(const std::string& filename);
        void managePacketsList();

    public:
        void setCurrentPacket(const DataStructure::localPacket& pack);
        void addPacketTable(const DataStructure::localPacket &local, int number);
        void updateTableShown()
        {
            model.rerunFilter(this->filterTree);
        }

        void associateName(const hungry_sniffer::Packet* localPacket, const std::string& origText);

        void setOutputFunctions();
        void setStatsFunctions(const hungry_sniffer::Protocol& protocol);

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
            int_fast16_t bracketsC = 0; // '(' ')'
            int_fast16_t bracketsS = 0; // '[' ']'
            int_fast16_t bracketsM = 0; // '{' '}'

            bool block = false;         // :

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
