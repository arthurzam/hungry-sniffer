#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include <QInputDialog>

#include "options.h"

static bool redirect(const char* src, const char* dst, const char* protocol, bool remove)
{
    pid_t p;
    int status;
    switch ((p = fork()))
    {
        case -1:
            return false;
        case 0:
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execl("/sbin/iptables", "iptables", "-t", "nat", (remove ? "-D" : "-A"),
                  "PREROUTING", "-p", protocol, "--destination-port", src, "-j",
                  "REDIRECT", "--to-port", dst, NULL);
            break;
        default:
            waitpid(p, &status, 0);
            return !(WEXITSTATUS(status));
            break;
    }
    return true;
}

struct info_t {
    int src;
    int dst;
    const char* protcol;
};

extern "C" bool stop_portRedirect(const void* data)
{
    const info_t* info = (const info_t*)data;

    char src[16];
    sprintf(src, "%d", (info->src & 0xFFFF));
    char dst[16];
    sprintf(dst, "%d", (info->dst & 0xFFFF));

    bool res = redirect(src, dst, info->protcol, true);
    free(const_cast<void*>(data));
    return res;
}

int start_srcPortRedirect(const Packet* packet, Option::disabled_options_t& options)
{
    packet = packet->getNext(2);

    bool ok = false;
    int port = QInputDialog::getInt(nullptr, "Get Port", "Set the port to be redirected to", 80, 1, 0xFFFF, 1, &ok);

    char dst[16];
    sprintf(dst, "%d", (port & 0xFFFF));

    ok = ok && redirect(packet->realSource().c_str(), dst, "tcp", false);

    if(!ok)
        return 0;
    info_t* data = (info_t*)malloc(sizeof(info_t));
    data->src = atoi(packet->realSource().c_str());
    data->dst = port;
    data->protcol = "tcp";
    Option::enabledOption e = {"Redirect from ", data, stop_portRedirect};
    e.name.append(packet->realSource().c_str());
    e.name.append(" -> ");
    e.name.append(dst);
    options.push_back(std::move(e));
    return (Option::ENABLE_OPTION_RETURN_ADDED_DISABLE | Option::ENABLE_OPTION_RETURN_MALLOCED_DATA);
}
