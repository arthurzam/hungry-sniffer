#ifndef STRINGLISTSELECTOR_H
#define STRINGLISTSELECTOR_H

#include <QWidget>

class QVBoxLayout;
class QHBoxLayout;
class QListWidget;
class QPushButton;

class StringListSelector : public QWidget
{
        Q_OBJECT
    public:
        typedef QString (*on_add_function_t)();
        explicit StringListSelector(on_add_function_t func, QWidget *parent = 0);

        QStringList getItems();
        void addItems(const QStringList& items);

    private slots:
        void bt_add_clicked();
        void bt_remove_clicked();
    private:
        on_add_function_t adder;
        QListWidget* list;
};

#endif // STRINGLISTSELECTOR_H
