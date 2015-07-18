#include "statusbar.h"
#include "sniff_window.h"

#include <QGridLayout>

StatusBar::StatusBar(QWidget* parent) :
    QStatusBar(parent),
    lb_info(this),
    lb_liveSniffing(this)
{
    this->setStyleSheet(QStringLiteral("QStatusBar::item{border: none;}"));

    QWidget* widget = new QWidget();
    QGridLayout* layout = new QGridLayout(widget);
    layout->addWidget(&lb_liveSniffing, 0, 0, 1, 1, Qt::AlignVCenter | Qt::AlignLeft);
    layout->addWidget(&lb_info, 0, 1, 1, 1, Qt::AlignVCenter | Qt::AlignRight);
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
    this->lb_liveSniffing.setText(state ? QStringLiteral("Live Sniffing") : QStringLiteral(""));
}

