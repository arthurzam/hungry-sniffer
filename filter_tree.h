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
        /**
         * @brief The Node class
         *
         * represents a node in the filter tree
         * can hold a simple check or a boolean expresation (for example Or)
         */
        class Node {
            public:
                enum Type {
                    Value = 0,
                    Or,
                    And,
                    Not
                };

            private:
                union {
                    struct {
                        Node* left;
                        Node* right;
                    } tree;
                    struct {
                        const hungry_sniffer::Protocol* protocol;
                        hungry_sniffer::Protocol::filterFunction function;
                    } filter;
                } data;
                enum Type type;
                std::vector<std::string> matches;
            public:
                /**
                 * @brief Node constructor for just protocol type
                 *
                 * @param protocol the protocol type
                 */
                Node(const hungry_sniffer::Protocol* protocol);

                /**
                 * @brief Node constructor for protocol type and filter function
                 *
                 * @param protocol the protocol type
                 * @param function the filter function
                 * @param matches the matches of the original filter text with the regular expression associated with the function
                 */
                Node(const hungry_sniffer::Protocol* protocol, hungry_sniffer::Protocol::filterFunction function, const std::smatch& matches);

                /**
                 * @brief Node constructor for binary expression
                 *
                 * @param left left sub node
                 * @param right right sub node
                 * @param type the type of this node
                 */
                Node(Node* left, Node* right, enum Type type);
                ~Node();

                /**
                 * @brief get check if packet fits the current and sub nodes
                 *
                 * @param eth the packet to check
                 * @return true if fits, otherwise false
                 */
                bool get(const hungry_sniffer::Packet* eth) const;
        };
    private:
        Node* root;
    public:
        /**
         * @brief FilterTree constructor from filter text
         *
         * @param filterString the filter text string
         */
        FilterTree(const std::string& filterString);
        ~FilterTree()
        {
            delete this->root;
        }

        /**
         * @brief get check if packet fits the built filter
         *
         * @param eth the packet to check
         * @return true if fits, otherwise false
         */
        bool get(const hungry_sniffer::Packet* eth) const
        {
            return !this->root || this->root->get(eth);
        }
};

#endif // FILTER_TREE_H
