#ifndef HISTORY_LINE_EDIT_HPP
#define HISTORY_LINE_EDIT_HPP

#include <QLineEdit>

class History_Line_Edit : public QLineEdit
{
    Q_OBJECT

    int         current_line;
    QStringList lines;
    QString     unfinished;

public:
    explicit History_Line_Edit(QWidget *parent = 0);

    /**
     * @brief Number of lines
     * @return Number of lines entered
     */
    int lineCount() const { return lines.size(); }
    
private slots:
    void enter_pressed();

signals:
    /**
     * @brief Emitted when some text is executed
     */
    void lineExecuted(QString);

protected:
    void keyPressEvent(QKeyEvent *);
    void wheelEvent(QWheelEvent *);

    void previous_line();
    void next_line();
    
};

#endif // HISTORY_LINE_EDIT_HPP
