#ifndef FILTER_TREE_H
#define FILTER_TREE_H

#include "Protocol.h"

/**
 * @brief The FilterTree class
 *
 * Tree boolean calculator builder from a string.
 * Every node in the tree will calculate the result from all of its children and return per every packet checked.
 */
class FilterTree
{
    public:
        struct Node {
            union {
                struct {
                    Node* left;
                    Node* right;
                } ptr;
                struct {
                    const hungry_sniffer::Protocol* protocol;
                    hungry_sniffer::Protocol::filterFunction func;
                    const std::vector<std::string>* smatches;
                } value;
            } data;
            int type;

            bool get(const hungry_sniffer::Packet *eth) const;
        };

    private:
        Node* nodeArr;
        Node* root;
        std::vector<std::string>* smatchesArr;
    public:
        /**
         * @brief FilterTree constructor from filter text
         *
         * @param filterString the filter text string
         */
        FilterTree(const std::string& filterString);
        ~FilterTree()
        {
            ::free(nodeArr);
            delete[] smatchesArr;
        }

        /**
         * @brief get check if packet fits the built filter
         *
         * @param eth the packet to check
         * @return true if fits, otherwise false
         */
        bool get(const hungry_sniffer::Packet* eth) const
        {
            return !root || root->get(eth);
        }
};

#endif // FILTER_TREE_H
