#ifndef OPTIONSDISABLER_H
#define OPTIONSDISABLER_H

#include <QDialog>
#include "Protocol.h"

class QGridLayout;

class OptionsDisabler : public QDialog
{
    public:
        hungry_sniffer::Option::disabled_options_t enabledOptions;

        explicit OptionsDisabler(QWidget *parent = 0);
        ~OptionsDisabler();

        void refreshOptions();
    private:
        QGridLayout* grid;
};

#endif // OPTIONSDISABLER_H
