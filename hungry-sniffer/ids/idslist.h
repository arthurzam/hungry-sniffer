#if !defined(IDSLIST_H) && defined(WITH_IDS)
#define IDSLIST_H

#include <vector>

namespace hungry_sniffer {
    class Packet;

    namespace ids {
        class Rule;
        class Problem;
    }
}

class IDSlist
{
    public:
        static IDSlist ids_list;

        std::vector<hungry_sniffer::ids::Rule*> list_rules;
        std::vector<hungry_sniffer::ids::Problem*> list_problems;
    public:
        IDSlist() {}
        ~IDSlist();

        bool checkPacket(const hungry_sniffer::Packet* packet);
};

#endif // IDSLIST_H
