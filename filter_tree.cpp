#include "filter_tree.h"
#include "sniff_window.h"


FilterTree::Node::Node(const Protocol *protocol)
    : matches()
{
    this->type = this->Type::Value;
    this->data.filter.protocol = protocol;
    this->data.filter.function = nullptr;
}

FilterTree::Node::Node(const Protocol *protocol, Protocol::filterFunction function, std::smatch&& matches)
    : matches(std::move(matches))
{
    this->type = this->Type::Value;
    this->data.filter.protocol = protocol;
    this->data.filter.function = function;
}

FilterTree::Node::Node(FilterTree::Node *left, FilterTree::Node *right, FilterTree::Node::Type type)
    : matches()
{
    this->data.tree.left = left;
    this->data.tree.right = right;
    this->type = type;
}

FilterTree::Node::~Node()
{
    if(this->type != Type::Value)
    {
        delete this->data.tree.left;
        delete this->data.tree.right;
    }
}

bool FilterTree::Node::get(const EthernetPacket *eth) const
{
    switch (this->type) {
    case Type::And:
        return this->data.tree.left->get(eth) && this->data.tree.right->get(eth);
    case Type::Or:
        return this->data.tree.left->get(eth) ||this->data.tree.right->get(eth);
    case Type::Not:
        return !this->data.tree.left->get(eth);
    default:
        const hungry_sniffer::Packet* p = eth->hasProtocol(this->data.filter.protocol);
        if(!p)
            return false;
        return this->data.filter.function(p, this->matches);
    }
}

FilterTree::FilterTree(const std::string &filterString)
{
    this->root = this->parse(filterString.cbegin(), filterString.cend());
}

FilterTree::~FilterTree()
{
    delete this->root;
}

bool FilterTree::get(const EthernetPacket *eth) const
{
    return this->root->get(eth);
}
