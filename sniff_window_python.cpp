#ifdef PYTHON_CMD
#include "Python.h"
#include "sniff_window.h"
#include "ui_sniff_window.h"

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
        HS_PYDICT_ADD_STRINGS(headers, i.first, i.second);
    HS_PYDICT_ADD_OBJECT(d, "headers", headers);

    return d;
}

static PyObject* getPacket(int pos)
{
    if(pos >= SniffWindow::window->local.size())
        return Py_None;
    struct SniffWindow::localPacket& pack = SniffWindow::window->local[pos];

    PyObject* d = PyDict_New();
    HS_PYDICT_ADD_NUM(d, "num", pos);
    HS_PYDICT_ADD_OBJECT(d, "isShown", PyBool_FromLong(pack.isShown));
    HS_PYDICT_ADD_OBJECT(d, "data", PyByteArray_FromStringAndSize((const char*)pack.rawPacket.get_data(), pack.rawPacket.get_length()));

    PyObject* layers = PyList_New(0);
    for(const hungry_sniffer::Packet* packet = pack.decodedPacket.get(); packet != nullptr; packet = packet->getNext())
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

    auto list = SniffWindow::window->local;
    for(int i = pos; i < list.size(); ++i)
    {
        if(list[i].isShown)
            return getPacket(i);
    }
    return Py_None;
}

PyObject* hs_getCountAll(PyObject*)
{
    return PyLong_FromLong(SniffWindow::window->local.size());
}

PyObject* hs_getCountShown(PyObject*)
{
    int count = 0;
    for(const auto& i : SniffWindow::window->local)
        if(i.isShown)
            count++;
    return PyLong_FromLong(count);
}

}

static PyMethodDef hs_methods[] = {
    { "getPacketNum", (PyCFunction)hs_getPacketNum, METH_VARARGS, NULL },
    { "getNextShown", (PyCFunction)hs_getNextShown, METH_VARARGS, NULL },
    { "getCountAll", (PyCFunction)hs_getCountAll, METH_NOARGS, NULL },
    { "getCountShown", (PyCFunction)hs_getCountShown, METH_NOARGS, NULL },
    { NULL, NULL, 0, NULL }
};

static PyModuleDef hsModule = {
    PyModuleDef_HEAD_INIT, "_hs_private", NULL, -1, hs_methods, NULL, NULL, NULL, NULL
};

static PyObject* PyInit_hs(void)
{
    return PyModule_Create(&hsModule);
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

void SniffWindow::stopPython()
{
    Py_Finalize();
}

void SniffWindow::initPython()
{
    PyImport_AppendInittab("_hs_private",&PyInit_hs);
    Py_Initialize();

    addDirToPath(PYTHON_DIR);

    PyObject* mainModule = PyImport_AddModule("__main__");
    PyObject* hsModule = PyImport_ImportModule("hs");
    PyModule_AddObject(mainModule, "hs", hsModule);

    this->pyGlobals = PyModule_GetDict(mainModule);
    redirect((PyObject*)this->pyGlobals);
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
    ui->lb_cmd->appendHtml(output);
    ui->tb_command->clear();

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
    QString color = "blue";
    if (PyErr_Occurred())
    {
        PyErr_Print();
        PyErr_Clear();
        color = "red";
    }
    PyObject *output = PyObject_GetAttrString((PyObject*)pyCatcher,"value");
    QString res(PyUnicode_AsUTF8(output));
    if(res.length() > 0)
    {
        ui->lb_cmd->appendHtml(res.arg(color));
        PyRun_SimpleString("catchOutErr.value = ''");
    }

    this->py_checkCommand.block = false;
    this->py_checkCommand.bracketsC = 0;
    this->py_checkCommand.bracketsS = 0;
    this->py_checkCommand.bracketsM = 0;
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

void SniffWindow::on_tb_command_returnPressed()
{
    this->addPyCommand(ui->tb_command->text().toStdString().c_str());
}

#endif
