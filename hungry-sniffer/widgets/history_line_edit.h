/*
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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
