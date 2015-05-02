#include <unistd.h>
#include <cstring>
#include <sys/wait.h>
#include "iptc.h"

bool dropIP(const char* ip)
{
    pid_t p;
    int status;
    switch((p = fork()))
    {
        case -1:
            return false;
        case 0:
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execl("/sbin/iptables", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", NULL);
            break;
        default:
            waitpid(p, &status, 0);
            return !(WEXITSTATUS(status));
            break;
    }
    return true;
}

bool removeDropIP(const char* ip)
{
    pid_t p;
    int status;
    switch((p = fork()))
    {
        case -1:
            return false;
        case 0:
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execl("/sbin/iptables", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP", NULL);
            break;
        default:
            waitpid(p, &status, 0);
            return !(WEXITSTATUS(status));
            break;
    }
    return true;
}
