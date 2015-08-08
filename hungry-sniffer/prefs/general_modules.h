#ifndef GENERAL_MODULES_H
#define GENERAL_MODULES_H

#include <QWidget>
#include "Protocol.h"

namespace Ui {
    class GeneralModules;
}

class StringListSelector;

class GeneralModules : public QWidget, public hungry_sniffer::PreferencePanel
{
        Q_OBJECT

    public:
        explicit GeneralModules(QWidget* parent = 0);
        ~GeneralModules();
        virtual QWidget* get()
        {
            return this;
        }

        virtual void save(QSettings& settings);

        static hungry_sniffer::PreferencePanel* init(const HungrySniffer_Core& core, QSettings& settings);

    private:
        Ui::GeneralModules* ui;
        StringListSelector* list_plugins;
        StringListSelector* list_python;
};

#endif // GENERAL_MODULES_H
