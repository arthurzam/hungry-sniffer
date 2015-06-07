#include "history_line_edit.h"
#include <QKeyEvent>
#include <QWheelEvent>

History_Line_Edit::History_Line_Edit(QWidget* parent) :
    QLineEdit(parent), current_line(0)
{
    connect(this, SIGNAL(returnPressed()), SLOT(enter_pressed()));
}

void History_Line_Edit::enter_pressed()
{
    if(lines.size() == 0 || lines[lines.size() - 1] != text())
        lines << text();
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
    if ( lines.empty() )
        return;

    if ( !text().isEmpty() &&
            ( current_line >= lines.size() || text() != lines[current_line] ) )
        unfinished = text();

    if ( current_line > 0 )
        current_line--;

    if(lines[current_line] == unfinished)
    {
        if ( current_line > 0 )
            current_line--;
        else
            return;
    }

    setText(lines[current_line]);
    emit textEdited(text());
}

void History_Line_Edit::next_line()
{
    if ( lines.empty() )
        return;

    current_line++;

    if ( current_line >= lines.size() )
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
