#ifndef FILTER_TREE_H
#define FILTER_TREE_H

#include "EthernetPacket.h"
#include <regex>
#include <string>

class FilterTree
{
    public:
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
                std::smatch matches;
            public:
                Node(const hungry_sniffer::Protocol *protocol);
                Node(const hungry_sniffer::Protocol* protocol, hungry_sniffer::Protocol::filterFunction function, std::smatch&& matches);
                Node(Node* left, Node* right, enum Type type);
                ~Node();

                bool get(const EthernetPacket* eth) const;
        };
    private:
        Node* root;
    public:
        FilterTree(const std::string& filterString);
        ~FilterTree();

        bool get(const EthernetPacket* eth) const;
};

#endif // FILTER_TREE_H
