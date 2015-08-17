/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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

class History_Line_Edit;
class PacketStats;
class QAction;
class QLabel;
class QSortFilterProxyModel;
class QPlainTextEdit;
class QTreeWidgetItem;

class HungrySniffer_Core;

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
        QString default_open_location;
        int max_recent_files;
    signals:
        void sig_showMessageBox(const QString& title, const QString& text);
    public slots:
        void on_actionOpen_triggered();
        void on_tb_filter_textEdited(const QString &arg1);
        void on_bt_filter_clear_clicked();
        void on_action_about_triggered();
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
        void on_tree_packet_currentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* previous);
        void on_actionDisableOptions_triggered();
#ifdef PYTHON_CMD
        void tb_command_returnPressed();
#endif
        void on_action_Table_toggled(bool arg1);
        void on_action_Tree_toggled(bool arg1);
        void on_action_Hex_toggled(bool arg1);
        void on_action_Python_toggled(bool arg1);
        void on_splitter_splitterMoved(int, int);

        void model_currentRowChanged(QModelIndex newSelection,QModelIndex oldSelection);
        void showMessageBox(const QString& title, const QString& text);

        void recentFile_triggered();
        void copy_to_clipboard();
        void open_stats_window();
        void tree_add_info_header();
        void tree_remove_info_header();
        void open_preference_window();

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

        std::vector<QAction*> recentFiles_actions;
        QStringList recentFiles_paths;
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

        void updateRecentsMenu();

#ifdef PYTHON_CMD
    public:
        QPlainTextEdit* lb_cmd;
        History_Line_Edit* tb_command;
    private:
        void initPython(QLabel* img_python);
        void stopPython();

        void addPyCommand(const char* pyCommand);
        bool checkPyCommand(const char* pyCommand);

    private:
        void* pyGlobals;

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
