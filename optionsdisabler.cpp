#include "optionsdisabler.h"
#include "ui_optionsdisabler.h"
#include <QLabel>
#include <QPushButton>

OptionsDisabler::OptionsDisabler(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OptionsDisabler)
{
    ui->setupUi(this);
    this->setFixedSize(0, 0);
}

OptionsDisabler::~OptionsDisabler()
{
    delete ui;
//    for(auto& i : this->enabledOptions)
//    {
//        free(const_cast<void*>(i.data));
//    }
}

void OptionsDisabler::refreshOptions()
{
    // clear the table
    while(ui->grid->count() > 0)
    {
        QWidget* widget = ui->grid->itemAt(0)->widget();
        ui->grid->removeWidget(widget);
        delete widget;
    }
    int row = 0;
    for(const auto& i : this->enabledOptions)
    {
        ui->grid->addWidget(new QLabel(QString::fromStdString(i.name), this), row, 0);
        QPushButton* bt = new QPushButton(QLatin1String("Disable"), this);

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

        ui->grid->addWidget(bt, row, 1);

        ++row;
    }
    if(row == 0)
    {
        this->hide();
    }
}
