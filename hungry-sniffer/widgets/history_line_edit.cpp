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

#include "history_line_edit.h"
#include <QKeyEvent>
#include <QWheelEvent>

History_Line_Edit::History_Line_Edit(QWidget* parent) :
    QLineEdit(parent)
{
    connect(this, SIGNAL(returnPressed()), SLOT(enter_pressed()));
}

void History_Line_Edit::enter_pressed()
{
    if(lines.size() == 0 || lines.back() != text())
        lines.append(text());
    current_line = lines.size();
    emit lineExecuted(lines.back());
}

void History_Line_Edit::keyPressEvent(QKeyEvent* ev)
{
    switch(ev->key())
    {
        case Qt::Key_Up:
        case Qt::Key_PageUp:
            previous_line();
            break;
        case Qt::Key_Down:
        case Qt::Key_PageDown:
            next_line();
            break;
        default:
            QLineEdit::keyPressEvent(ev);
            break;
    }
}

void History_Line_Edit::wheelEvent(QWheelEvent* ev )
{
    if (ev->delta() > 0)
        previous_line();
    else
        next_line();
}

void History_Line_Edit::previous_line()
{
    if (lines.empty())
        return;

    if (!text().isEmpty() && (current_line >= lines.size() || text() != lines[current_line]))
        unfinished = text();

    if (current_line > 0)
        current_line--;

    if(lines[current_line] == unfinished)
    {
        if (current_line > 0)
            current_line--;
        else
            return;
    }

    setText(lines[current_line]);
    emit textEdited(text());
}

void History_Line_Edit::next_line()
{
    if (lines.empty())
        return;

    current_line++;

    if (current_line >= lines.size())
    {
        setText(unfinished);
        unfinished = "";
        current_line = lines.size();
    }
    else
    {
        setText(lines[current_line]);
    }
    emit textEdited(text());
}
