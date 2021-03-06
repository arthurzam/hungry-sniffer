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

#ifndef DEVICECHOOSE_H
#define DEVICECHOOSE_H

#include <QDialog>
#include <QAbstractTableModel>

#if defined(Q_OS_WIN)
    #include <winsock2.h>
    #include <windows.h>
#endif
#include <pcap.h>

class InterfaceSelector;
class QSortFilterProxyModel;
class QLineEdit;
class QSpinBox;

/**
 * @brief Choosing Device for Sniffing Dialog
 */
class DeviceChoose : public QDialog
{
        Q_OBJECT
    private:
        InterfaceSelector* tableView;
        QStringList results;
        QSortFilterProxyModel* m_sortFilterProxy;
        QLineEdit* tb_filter;
        QSpinBox* tb_number;
    public:
        explicit DeviceChoose(QWidget* parent = 0);
        ~DeviceChoose() {}

        QStringList::const_iterator end() const
        {
            return results.cend();
        }

        QStringList::const_iterator begin() const
        {
            return results.cbegin();
        }

        QString getCaptureFilter() const;
        int getMaxCaptureNumber() const;

    private slots:

        /**
         * @brief on_buttonBox_accepted in case OK was clicked, save the chosen in results
         */
        void on_buttonBox_accepted();
};

#endif // DEVICECHOOSE_H
