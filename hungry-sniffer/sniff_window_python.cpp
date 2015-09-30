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

#ifdef PYTHON_CMD

#include "sniff_window.h"

#include <QLineEdit>
#include <QPlainTextEdit>

void SniffWindow::tb_command_returnPressed()
{
    QString commandQ = tb_command->text();
    if(commandQ.isEmpty() && !this->py_checkCommand.block)
        return;
    const char* interpreter_prefix = (pyCommand.length() == 0 ? "&gt;&gt;&gt;" : ".  .  .");
    tb_command->clear();

    // start check if command needs continuation or is finished
    const char* command = commandQ.toLatin1().constData();

    bool lineDelimeter = true;
    bool posibleBlock = !py_checkCommand.block;
    bool isFinished = true;

    const char* c = strrchr(command, '#');
    if(!c)
        c = command + strlen(command) - 1;
    else
        c--;

    for (; isFinished && c >= command; --c)
    {
        if (*c != ' ' && *c != '\\')
            lineDelimeter = false;
        if (*c != ' ' && *c != ':')
            posibleBlock = false;
        switch (*c)
        {
            case ')': py_checkCommand.bracketsC++; break;
            case '(': py_checkCommand.bracketsC--; break;
            case ']': py_checkCommand.bracketsS++; break;
            case '[': py_checkCommand.bracketsS--; break;
            case '}': py_checkCommand.bracketsM++; break;
            case '{': py_checkCommand.bracketsM--; break;
            case '\"':
                for (c -= 1; c >= command; --c)
                    if (c[0] == '\"' && c[-1] != '\\')
                        break;
                break;
            case '\'':
                for (c -= 1; c >= command; --c)
                    if (c[0] == '\'' && c[-1] != '\\')
                        break;
                break;
            case '\\': isFinished &= !lineDelimeter; break;
            case ':': py_checkCommand.block |= posibleBlock; break;
        }
    }
    isFinished &= (py_checkCommand.bracketsC == 0) & (py_checkCommand.bracketsS == 0) & (py_checkCommand.bracketsM == 0);
    isFinished &= !(py_checkCommand.block & (*command != '\0'));

    pyCommand.push_back(QChar('\n'));
    pyCommand.append(commandQ);

    if(isFinished)
    {
        emit python_thread.sendCommand(pyCommand);

        this->py_checkCommand.reset();
        this->pyCommand.clear();
    }

    lb_cmd->moveCursor(QTextCursor::End);
    lb_cmd->textCursor().insertHtml(QStringLiteral("%1 <font color=\"green\">%2</font><br />")
                                    .arg(interpreter_prefix)
                                    .arg(commandQ.replace("<", "&lt;").replace(">", "&gt;")));
    lb_cmd->moveCursor(QTextCursor::End);
}

#endif
