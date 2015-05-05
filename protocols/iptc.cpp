#include <unistd.h>
#include <cstring>
#include <sys/wait.h>
#include "iptc.h"

bool dropIP(const char* ip, bool isIPv4)
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
            execl((isIPv4 ? "/sbin/iptables" : "/sbin/ip6tables"), (isIPv4 ? "iptables" : "ip6tables"), "-I", "INPUT", "-s", ip, "-j", "DROP", NULL);
            break;
        default:
            waitpid(p, &status, 0);
            return !(WEXITSTATUS(status));
            break;
    }
    return true;
}

bool removeDropIP(const char* ip, bool isIPv4)
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
            execl((isIPv4 ? "/sbin/iptables" : "/sbin/ip6tables"), (isIPv4 ? "iptables" : "ip6tables"), "-D", "INPUT", "-s", ip, "-j", "DROP", NULL);
            break;
        default:
            waitpid(p, &status, 0);
            return !(WEXITSTATUS(status));
            break;
    }
    return true;
}
