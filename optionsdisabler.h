#ifndef OPTIONSDISABLER_H
#define OPTIONSDISABLER_H

#include <QDialog>
#include "Protocol.h"
namespace Ui {
class OptionsDisabler;
}

class OptionsDisabler : public QDialog
{
        Q_OBJECT

    public:
        hungry_sniffer::Option::disabled_options_t enabledOptions;

        explicit OptionsDisabler(QWidget *parent = 0);
        ~OptionsDisabler();

    public slots:
        void refreshOptions();
    private:
        Ui::OptionsDisabler *ui;
};

#endif // OPTIONSDISABLER_H
