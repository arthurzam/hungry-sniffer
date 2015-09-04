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

#ifndef GENERAL_UI_H
#define GENERAL_UI_H

#include <QWidget>
#include <hs_prefs.h>

class QCheckBox;
class QLineEdit;
class QSpinBox;

class GeneralUI : public QWidget, public hungry_sniffer::Preference::Panel
{
        Q_OBJECT

    public:
        GeneralUI();
        ~GeneralUI();
        virtual QWidget* get()
        {
            return this;
        }

        virtual void save(QSettings& settings);

        static hungry_sniffer::Preference::Panel* init(QSettings& settings);

    private slots:
        void on_bt_default_dir_clicked();

    private:
        QCheckBox* cb_splitter_sizes;
        QCheckBox* cb_colored;
        QLineEdit* tb_default_dir;
        QSpinBox* tb_recents_num;
};

#endif // GENERAL_UI_H
