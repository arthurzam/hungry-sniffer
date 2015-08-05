#ifdef PYTHON_CMD
#include "Python.h"
#include "sniff_window.h"
#include "ui_sniff_window.h"
#include "history_line_edit.h"
#include "EthernetPacket.h"

#include <QPlainTextEdit>

#define HS_PYDICT_ADD_OBJECT(dict, k, v) PyDict_SetItem(dict, PyUnicode_FromString(k), v)
#define HS_PYDICT_ADD_NUM(dict, k, num) HS_PYDICT_ADD_OBJECT(dict, k, PyLong_FromLong(num))
#define HS_PYDICT_ADD_STRING(dict, k, v) HS_PYDICT_ADD_OBJECT(dict, k, PyUnicode_FromString(v.c_str()))
#define HS_PYDICT_ADD_STRINGS(dict, k, v) HS_PYDICT_ADD_STRING(dict, k.c_str(), v)

#ifndef PYTHON_DIR
#define PYTHON_DIR "/usr/share/hungry-sniffer/"
#endif

extern "C" {

static PyObject* getLayer(const hungry_sniffer::Packet* layer)
{
    PyObject* d = PyDict_New();
    HS_PYDICT_ADD_STRING(d, "name", layer->getProtocol()->getName());
    HS_PYDICT_ADD_STRING(d, "info", layer->getInfo());

    PyObject* headers = PyDict_New();
    for(auto& i : layer->getHeaders())
        HS_PYDICT_ADD_STRINGS(headers, i.key, i.value);
    HS_PYDICT_ADD_OBJECT(d, "headers", headers);

    return d;
}

static PyObject* getPacket(unsigned pos)
{
    if(pos >= SniffWindow::window->model.local.size())
        return Py_None;
    struct DataStructure::localPacket& pack = SniffWindow::window->model.local[pos];

    PyObject* d = PyDict_New();
    HS_PYDICT_ADD_NUM(d, "num", pos);
    HS_PYDICT_ADD_OBJECT(d, "isShown", PyBool_FromLong(pack.isShown));
    HS_PYDICT_ADD_OBJECT(d, "data", PyByteArray_FromStringAndSize((const char*)pack.rawPacket.data, pack.rawPacket.len));
    HS_PYDICT_ADD_OBJECT(d, "time", PyFloat_FromDouble(pack.rawPacket.time.tv_sec + (double)pack.rawPacket.time.tv_usec * 0.000001));

    PyObject* layers = PyList_New(0);
    for(const hungry_sniffer::Packet* packet = pack.decodedPacket; packet != nullptr; packet = packet->getNext())
    {
        PyList_Append(layers, getLayer(packet));
    }
    HS_PYDICT_ADD_OBJECT(d, "layers", layers);

    return d;
}

PyObject* hs_getPacketNum(PyObject*, PyObject* args)
{
    int pos;
    if (!PyArg_ParseTuple(args, "i", &pos)) {
        return NULL;
    }
    return getPacket(pos);
}

PyObject* hs_getNextShown(PyObject*, PyObject* args)
{
    int pos;
    if (!PyArg_ParseTuple(args, "i", &pos)) {
        return NULL;
    }

    auto& list = SniffWindow::window->model.local;
    for(unsigned i = pos; i < list.size(); ++i)
    {
        if(list[i].isShown)
            return getPacket(i);
    }
    return Py_None;
}

PyObject* hs_getCountAll(PyObject*)
{
    return PyLong_FromLong(SniffWindow::window->model.local.size());
}

PyObject* hs_getCountShown(PyObject*)
{
    return PyLong_FromLong(SniffWindow::window->model.shownPerRow.size());
}

PyObject* hs_savePacket(PyObject*, PyObject* args)
{
    int pos;
    PyObject* data;
    if (!PyArg_ParseTuple(args, "iY", &pos, &data)) {
        return NULL;
    }

    unsigned size = PyByteArray_Size(data);
    const char* b = PyByteArray_AsString(data);
    if(pos == -1)
    {
        DataStructure::RawPacketData raw;
        gettimeofday(&raw.time, nullptr);
        raw.setData(b, size);
        SniffWindow::window->toAdd.push(raw);
    }
    else if(pos < (int)SniffWindow::window->model.local.size())
    {
        struct DataStructure::localPacket& pack = SniffWindow::window->model.local[pos];
        DataStructure::RawPacketData& raw = pack.rawPacket;
        free(raw.data);
        raw.setData(b, size);

        delete pack.decodedPacket;
        pack.decodedPacket = new hungry_sniffer::EthernetPacket(raw.data, raw.len, &SniffWindow::core->base);

        SniffWindow::window->updateTableShown();
    }
    return Py_None;
}

PyObject* hs_removePacket(PyObject*, PyObject* args)
{
    int pos;
    if (!PyArg_ParseTuple(args, "i", &pos)) {
        return NULL;
    }
    SniffWindow::window->model.remove(pos);
    SniffWindow::window->ui->statusBar->updateText();
    return Py_None;
}

PyObject* hs_setFilter(PyObject*, PyObject* args)
{
    char* str = NULL;
    if (!PyArg_ParseTuple(args, "z", &str)) {
        return NULL;
    }
    SniffWindow::window->ui->tb_filter->setText(str ? QString(str) : QStringLiteral(""));
    SniffWindow::window->on_bt_filter_apply_clicked();
    return Py_None;
}

PyObject* hs_getFilter(PyObject*)
{
    return PyUnicode_FromString(SniffWindow::window->ui->tb_filter->text().toUtf8().data());
}

PyObject* ui_reset(PyObject*)
{
    SniffWindow::window->lb_cmd->clear();
    return Py_None;
}

PyObject* ui_open(PyObject*, PyObject* args)
{
    char* str = NULL;
    if (!PyArg_ParseTuple(args, "s", &str)) {
        return NULL;
    }
    SniffWindow::window->runOfflineFile(str);
    return Py_None;
}

PyObject* ui_stop(PyObject*)
{
    SniffWindow::window->on_actionStop_triggered();
    return Py_None;
}

PyObject* ui_exit(PyObject*)
{
    SniffWindow::window->close();
    return Py_None;
}

static PyMethodDef hs_methods[] = {
    { "getPacketNum", (PyCFunction)hs_getPacketNum, METH_VARARGS, NULL },
    { "getNextShown", (PyCFunction)hs_getNextShown, METH_VARARGS, NULL },
    { "getCountAll", (PyCFunction)hs_getCountAll, METH_NOARGS, NULL },
    { "getCountShown", (PyCFunction)hs_getCountShown, METH_NOARGS, NULL },
    { "savePacket", (PyCFunction)hs_savePacket, METH_VARARGS, NULL },
    { "removePacket", (PyCFunction)hs_removePacket, METH_VARARGS, NULL },
    { "setFilter", (PyCFunction)hs_setFilter, METH_VARARGS, NULL },
    { "getFilter", (PyCFunction)hs_getFilter, METH_NOARGS, NULL },
    { NULL, NULL, 0, NULL }
};

static PyModuleDef hsModule = {
    PyModuleDef_HEAD_INIT, "_hs_private", NULL, -1, hs_methods, NULL, NULL, NULL, NULL
};

static PyObject* PyInit_hs(void)
{
    return PyModule_Create(&hsModule);
}

static PyMethodDef ui_methods[] = {
    { "reset", (PyCFunction)ui_reset, METH_NOARGS, NULL },
    { "open", (PyCFunction)ui_open, METH_VARARGS, NULL },
    { "stop", (PyCFunction)ui_stop, METH_NOARGS, NULL },
    { "exit", (PyCFunction)ui_exit, METH_NOARGS, NULL },
    { NULL, NULL, 0, NULL }
};

static PyModuleDef uiModule = {
    PyModuleDef_HEAD_INIT, "_hs_ui", NULL, -1, ui_methods, NULL, NULL, NULL, NULL
};

static PyObject* PyInit_hs_ui(void)
{
    return PyModule_Create(&uiModule);
}

static void redirect(PyObject* globals)
{
    const char* stdOutErr =
            "import sys\n"
            "class CatchOutErr:\n"
            "   def __init__(self):\n"
            "       self.value = ''\n"
            "   def write(self, txt):\n"
            "       if txt != None and txt != '':\n"
            "           self.value += '<font color=\"%1\">' + str(txt).replace('\\n','<br/>') + '</font>'\n"
            "\n"
            "catchOutErr = CatchOutErr()\n"
            "sys.stdout = catchOutErr\n"
            "sys.stderr = catchOutErr\n";
    PyRun_String(stdOutErr, Py_file_input, globals, globals);
}

static void addDirToPath(const char* path)
{
    PyObject* sys = PyImport_ImportModule("sys");
    PyObject* sys_path = PyObject_GetAttrString(sys, "path");
    PyObject* folder_path = PyUnicode_FromString(path);
    PyList_Append(sys_path, folder_path);
}

}

void SniffWindow::stopPython()
{
    Py_Finalize();
}

void SniffWindow::initPython()
{
    PyImport_AppendInittab("_hs_private",&PyInit_hs);
    PyImport_AppendInittab("_hs_ui",&PyInit_hs_ui);
    Py_Initialize();

    addDirToPath(PYTHON_DIR);

    PyObject* mainModule = PyImport_AddModule("__main__");
    PyObject* hsModule = PyImport_ImportModule("hs");
    PyModule_AddObject(mainModule, "hs", hsModule);

    this->pyGlobals = PyModule_GetDict(mainModule);
    redirect((PyObject*)this->pyGlobals);
    PyRun_String("from _hs_ui import *", Py_single_input, (PyObject*)pyGlobals, (PyObject*)pyGlobals);
    this->pyCatcher = PyObject_GetAttrString(mainModule,"catchOutErr");
}

void SniffWindow::addPyCommand(const char* command)
{
    QString output;
    if(this->pyCommand.length() == 0)
        output.append("&gt;&gt;&gt; ");
    else
        output.append(".  .  . ");
    output.append("<font color=\"green\">");
    output.append(QString(command).replace("<", "&lt;").replace(">", "&gt;"));
    output.append("</font>");
    lb_cmd->appendHtml(output);
    tb_command->clear();

    if(command[0] == '\0' && !this->py_checkCommand.block)
        return;

    this->pyCommand.append("\n");
    this->pyCommand.append(command);

    if(this->checkPyCommand(command))
    {
        this->execPyCommand();
    }
}

void SniffWindow::execPyCommand()
{
    PyRun_String(this->pyCommand.c_str(), Py_single_input, (PyObject*)pyGlobals, (PyObject*)pyGlobals);
    bool error = PyErr_Occurred();
    if (error)
    {
        PyErr_Print();
        PyErr_Clear();
    }
    PyObject *output = PyObject_GetAttrString((PyObject*)pyCatcher,"value");
    QString res(PyUnicode_AsUTF8(output));
    if(res.length() > 0)
    {
        lb_cmd->appendHtml(res.arg((error ? QStringLiteral("red") : QStringLiteral("blue"))));
        PyRun_SimpleString("catchOutErr.value = ''");
    }

    this->py_checkCommand.reset();
    this->pyCommand.clear();
}

bool SniffWindow::checkPyCommand(const char* command)
{
    bool lineDelimeter = true;
    bool posibleBlock = !this->py_checkCommand.block;
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
            case ')':
                this->py_checkCommand.bracketsC++;
                break;
            case '(':
                this->py_checkCommand.bracketsC--;
                break;
            case ']':
                this->py_checkCommand.bracketsS++;
                break;
            case '[':
                this->py_checkCommand.bracketsS--;
                break;
            case '}':
                this->py_checkCommand.bracketsM++;
                break;
            case '{':
                this->py_checkCommand.bracketsM--;
                break;
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
            case '\\':
                isFinished &= !lineDelimeter;
                break;
            case ':':
                this->py_checkCommand.block |= posibleBlock;
                break;
        }
    }
    isFinished &= (this->py_checkCommand.bracketsC >= 0) & (this->py_checkCommand.bracketsS >= 0) & (this->py_checkCommand.bracketsM >= 0);
    isFinished &= !(this->py_checkCommand.block & (*command != '\0'));

    return isFinished;
}

void SniffWindow::tb_command_returnPressed()
{
    this->addPyCommand(tb_command->text().toUtf8().constData());
}

#endif