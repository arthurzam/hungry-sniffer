#include "optionsdisabler.h"
#include <QLabel>
#include <QPushButton>
#include <QGridLayout>
#include <QVBoxLayout>

OptionsDisabler::OptionsDisabler(QWidget *parent) :
    QDialog(parent)
{
    this->resize(400, 300);
    QVBoxLayout* verticalLayout = new QVBoxLayout(this);
    grid = new QGridLayout();
    verticalLayout->addLayout(grid);

    this->setWindowTitle(QStringLiteral("Options Disabler"));
    this->setFixedSize(0, 0);
}

OptionsDisabler::~OptionsDisabler()
{
//    for(auto& i : this->enabledOptions)
//    {
//        free(const_cast<void*>(i.data));
//    }
}

void OptionsDisabler::refreshOptions()
{
    // clear the table
    while(grid->count() > 0)
    {
        QWidget* widget = grid->itemAt(0)->widget();
        grid->removeWidget(widget);
        delete widget;
    }
    int row = 0;
    for(const auto& i : this->enabledOptions)
    {
        grid->addWidget(new QLabel(QString::fromStdString(i.name), this), row, 0);
        QPushButton* bt = new QPushButton(QStringLiteral("Disable"), this);

        connect(bt, &QPushButton::clicked, [this, row]() {
            auto iter = this->enabledOptions.begin();
            for(int j = 0; j < row; ++j) ++iter;
            hungry_sniffer::Option::optionDisableFunction disable_func = iter->disable_func;
            if(!disable_func)
                qDebug("disable function NULL for %s", iter->name.c_str());
            else if(disable_func(iter->data))
            {
                this->enabledOptions.erase(iter);
                this->refreshOptions();
            }
        });

        grid->addWidget(bt, row, 1);

        ++row;
    }
    if(row == 0)
    {
        this->hide();
    }
}
