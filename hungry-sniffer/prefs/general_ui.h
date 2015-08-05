#ifndef GENERAL_UI_H
#define GENERAL_UI_H

#include <QWidget>
#include "Protocol.h"

namespace Ui {
class GeneralUI;
}

class GeneralUI : public QWidget, public hungry_sniffer::PreferencePanel
{
        Q_OBJECT

    public:
        explicit GeneralUI(QWidget *parent = 0);
        ~GeneralUI();
        virtual QWidget* get()
        {
            return this;
        }

        virtual void save(QSettings& settings);

        static hungry_sniffer::PreferencePanel* init(const HungrySniffer_Core& core, QSettings& settings);

    private slots:
        void on_bt_default_dir_clicked();

    private:
        Ui::GeneralUI *ui;
};

#endif // GENERAL_UI_H
