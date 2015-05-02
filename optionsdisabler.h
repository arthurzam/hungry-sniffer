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
        std::list<struct hungry_sniffer::enabledOption> enabledOptions;

        explicit OptionsDisabler(QWidget *parent = 0);
        ~OptionsDisabler();

    public slots:
        void refreshOptions();
    private:
        Ui::OptionsDisabler *ui;
};

#endif // OPTIONSDISABLER_H
