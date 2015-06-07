#ifndef STATUSBAR_H
#define STATUSBAR_H

#include <QStatusBar>
#include <QLabel>

class StatusBar : public QStatusBar
{
        Q_OBJECT
    public:
        explicit StatusBar(QWidget *parent = 0);

        void updateText(int selectedRow = -1);
        void setLiveSniffing(bool state);

    private:
        QLabel lb_info;
        QLabel lb_liveSniffing;
        int selectedRow = 0;
};

#endif // STATUSBAR_H
