#include "filter_tree.h"
#include "sniff_window.h"

static std::string::const_iterator findMatchingBracket(std::string::const_iterator start, std::string::const_iterator end);

/**
 * @brief Parse Expression that start with not ('~')
 *
 * @param start from where to search
 * @param end until where to search
 * @return Node in tree
 *
 * two cases are handled "~ip" or "~(...)"
 */
static FilterTree::Node* parseNot(std::string::const_iterator start, std::string::const_iterator end);

/**
 * @brief Parse full Expression
 *
 * @param start from where to search
 * @param end until where to search
 * @return Node in tree
 */
static FilterTree::Node* parseExpr(std::string::const_iterator start, std::string::const_iterator end);
static hungry_sniffer::Protocol::filterFunction extractRegex(const hungry_sniffer::Protocol* protocol, const std::string& regexParts, std::smatch& sm);
static FilterTree::Node* parseEndExpr(std::string::const_iterator start, std::string::const_iterator end);

static std::string::const_iterator findMatchingBracket(std::string::const_iterator start, std::string::const_iterator end)
{
    int num = 1;
    for(; start != end && num != 0; ++start)
    {
        switch(*start)
        {
            case ')': --num; break;
            case '(': ++num; break;
        }
    }
    return start;
}

static FilterTree::Node* parseNot(std::string::const_iterator start, std::string::const_iterator end)
{
    if(*start == '(') // is part of brackets
    {
        return new FilterTree::Node(parseExpr(start + 1, end - 1), nullptr, FilterTree::Node::Not);
    }
    else
    {
        return new FilterTree::Node(parseEndExpr(start, end), nullptr, FilterTree::Node::Not);
    }
}

static FilterTree::Node* parseExpr(std::string::const_iterator start, std::string::const_iterator end)
{
    FilterTree::Node* res = nullptr;
    if(*start == '(') // is part of brackets
    {
        std::string::const_iterator temp = findMatchingBracket(start + 1, end);
        //return new FilterTree::Node(parse(str, i2, i1 - 1), nullptr, FilterTree::Node::Not);
    }
    else
    {

    }
}

static hungry_sniffer::Protocol::filterFunction extractRegex(const hungry_sniffer::Protocol* protocol, const std::string& regexParts, std::smatch& sm)
{
    for(auto i = protocol->getFilters().cbegin(); i != protocol->getFilters().cend(); ++i)
    {
        if(std::regex_search(regexParts, sm, i->first))
        {
            return i->second;
        }
    }
    return nullptr;
}

static FilterTree::Node* parseEndExpr(std::string::const_iterator start, std::string::const_iterator end)
{
    FilterTree::Node* res = nullptr;
    if(*start == '(') // is part of brackets
    {
        std::string::const_iterator temp = findMatchingBracket(start + 1, end);
        //return new FilterTree::Node(parse(str, i2, i1 - 1), nullptr, FilterTree::Node::Not);
    }
    else
    {

    }
}

FilterTree::Node* FilterTree::parse(std::string::const_iterator start, std::string::const_iterator end) const
{
    std::string::const_iterator i1 = start, i2 = start, dotPlace;
    Node *node1 = nullptr, *node2 = nullptr;
    int num;
    for(; i1 != end; ++i1)
    {
        switch(*i1)
        {
            case '(':
                i2 = ++i1;
                num = 1;
                for(; i1 != end && num != 0; ++i1)
                {
                    switch(*i1)
                    {
                        case ')': --num; break;
                        case '(': ++num; break;
                    }
                }
                node1 = parse(i2, i1 - 1);
                if(i1 == end)
                    return node1;
                i2 = ++i1;
                break;
            case '|':
            case '&':
                i2 = ++i1;
                dotPlace = i2 - 1;
                for(; i1 != end && *i1 != '&' && *i1 != '|'; ++i1)
                    if(*i1 == '.')
                        dotPlace = i1;
                if(dotPlace == i2 - 1)
                    dotPlace = i1;
            {
                std::string name(i2, dotPlace);
                const hungry_sniffer::Protocol* protocol = SniffWindow::baseProtocol->findProtocol(name);

                if(i2 != dotPlace)
                {
                    std::smatch sm;
                    node2 = new Node(protocol, extractRegex(protocol, std::string(dotPlace + 1, i1), sm), std::move(sm));
                }
                else // only name
                {
                    node2 = new Node(protocol);
                }
            }
                break;
            case '~':
                i2 = ++i1;
                dotPlace = i2 - 1;
                for(; i1 != end && *i1 != '&' && *i1 != '|'; ++i1)
                    if(*i1 == '.')
                        dotPlace = i1;
                if(dotPlace == i2 - 1)
                    dotPlace = i1;
            {
                std::string name(i2, dotPlace);
                const hungry_sniffer::Protocol* protocol = SniffWindow::baseProtocol->findProtocol(name);

                if(i2 != dotPlace)
                {
                    std::smatch sm;
                    node2 = new Node(protocol, extractRegex(protocol, std::string(dotPlace + 1, i1), sm), std::move(sm));
                }
                else // only name
                {
                    node2 = new Node(protocol);
                }
                node1 = new Node(node2, nullptr, Node::Type::Not);
                node2 = nullptr;
            }
                break;
        }
    }
    return node1;
}

