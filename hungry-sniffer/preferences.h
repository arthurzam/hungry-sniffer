#ifndef PREFERENCES_H
#define PREFERENCES_H

#include <QDialog>
#include <vector>

namespace Ui {
    class Preferences;
}

namespace hungry_sniffer {
    class PreferencePanel;
}

class QTreeWidgetItem;
class QSettings;

class Preferences : public QDialog
{
        Q_OBJECT

    public:
        typedef void (*reloadFunc_t)(QSettings& settings);
        static std::vector<reloadFunc_t> reloadFunctions;

        static QSettings* settings;

        explicit Preferences(QWidget *parent = 0);
        ~Preferences();

    protected:
        void accept();

    private slots:
        void on_tree_select_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);

    private:
        Ui::Preferences *ui;
        std::vector<hungry_sniffer::PreferencePanel*> panels;
};

#endif // PREFERENCES_H
