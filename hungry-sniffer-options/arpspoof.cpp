#include <signal.h>
#include <unistd.h>

#include "options.h"

static pid_t runArpspoof(const char* ip1, const char* ip2)
{
    pid_t p;
    switch ((p = fork()))
    {
        case -1:
            return -1;
        case 0:
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execlp("arpspoof", "arpspoof", "-t", ip1, ip2);
            return -1;
        default:
            return p;
    }
}

extern "C" bool stop_arpspoof(const void* data)
{
    const pid_t* newPids = static_cast<const pid_t*>(data);
    bool res = !(kill(newPids[0], SIGINT) || kill(newPids[1], SIGINT));
    free(const_cast<void*>(data));
    return res;
}

int start_arpspoof(const Packet* packet, Option::disabled_options_t& options)
{
    packet = packet->getNext(); // layer 3 - ip
    pid_t pids[2];
    pids[0] = runArpspoof(packet->realSource().c_str(), packet->realDestination().c_str());
    if(pids[0] == -1)
        return 0;
    pids[1] = runArpspoof(packet->realDestination().c_str(), packet->realSource().c_str());
    if(pids[1] == -1)
        return 0;
    pid_t* newPids = (pid_t*)malloc(2 * sizeof(pid_t));
    newPids[0] = pids[0];
    newPids[1] = pids[1];
    Option::enabledOption e = {"Arpspoof between ", newPids, stop_arpspoof};
    e.name.append(packet->realSource().c_str());
    e.name.append(" ");
    e.name.append(packet->realDestination().c_str());
    options.push_back(std::move(e));
    return (Option::ENABLE_OPTION_RETURN_ADDED_DISABLE | Option::ENABLE_OPTION_RETURN_MALLOCED_DATA);
}
