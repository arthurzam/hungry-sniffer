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

#include "statusbar.h"
#include "sniff_window.h"

#include <QHBoxLayout>

StatusBar::StatusBar(QWidget* parent) :
    QStatusBar(parent),
    lb_info(this),
    lb_liveSniffing(this),
    capture_off(QStringLiteral(":/icons/capture_off.png")),
    capture_on(QStringLiteral(":/icons/capture_on.png"))
{
    setLiveSniffing(false);

    QWidget* widget = new QWidget();
    QHBoxLayout* layout = new QHBoxLayout(widget);
    layout->addWidget(&lb_liveSniffing);
    layout->addItem(new QSpacerItem(20, 5, QSizePolicy::Expanding, QSizePolicy::Minimum));
    layout->addWidget(&lb_info);
    this->addWidget(widget, 1);

    updateText();
}

void StatusBar::updateText(int selectedRow)
{
    if(selectedRow != -1)
        this->selectedRow = selectedRow;
    int all = SniffWindow::window->model.local.size();
    int displayed = SniffWindow::window->model.shownPerRow.size();
    this->lb_info.setText(QStringLiteral("Packets:%1 * Displayed:%2 * Selected:%3").arg(all).arg(displayed).arg(this->selectedRow));
}

void StatusBar::setLiveSniffing(bool state)
{
    lb_liveSniffing.setPixmap(state ? capture_on : capture_off);
    lb_liveSniffing.setToolTip(state ? QStringLiteral("Live Capturing") : QStringLiteral("Not Capturing"));
}

