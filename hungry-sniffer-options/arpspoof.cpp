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
