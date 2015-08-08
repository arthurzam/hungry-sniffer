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

#ifndef PREFERENCES_H
#define PREFERENCES_H

#include <QDialog>
#include <vector>

namespace Ui {
    class Preferences;
}

namespace hungry_sniffer {
    class PreferencePanel;
}

class QTreeWidgetItem;
class QSettings;
class QSplitter;
class QTreeWidget;
class QStackedWidget;
class QLineEdit;

class Preferences : public QDialog
{
        Q_OBJECT

    public:
        typedef void (*reloadFunc_t)(QSettings& settings);
        static std::vector<reloadFunc_t> reloadFunctions;

        static QSettings* settings;

        explicit Preferences(QWidget* parent = 0);
        ~Preferences();

    protected:
        void accept();

    private slots:
        void on_tree_select_currentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* previous);
        void on_tb_search_textEdited(const QString& arg1);

    private:
        QSplitter* splitter;
        QLineEdit* tb_search;
        QTreeWidget* tree_select;
        QStackedWidget* stackedWidget;

        std::vector<hungry_sniffer::PreferencePanel*> panels;
};

#endif // PREFERENCES_H
