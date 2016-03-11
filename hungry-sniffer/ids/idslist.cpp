#ifdef WITH_IDS

#include "idslist.h"

#include <hs_ids.h>

IDSlist IDSlist::ids_list;

IDSlist::~IDSlist()
{
    for(hungry_sniffer::ids::Rule* rule : this->list_rules)
        delete rule;
    for(hungry_sniffer::ids::Problem* problem : this->list_problems)
        delete problem;
}

bool IDSlist::checkPacket(const hungry_sniffer::Packet* packet)
{
    bool flag = true;
    for(hungry_sniffer::ids::Rule* rule : this->list_rules)
    {
        hungry_sniffer::ids::Problem* problem = rule->check(packet);
        if(problem)
        {
            flag = false;
            this->list_problems.push_back(problem);
        }
    }
    return flag;
}

#endif
