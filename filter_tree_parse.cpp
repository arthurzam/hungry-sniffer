#include "filter_tree.h"
#include "sniff_window.h"

using std::string;

static string::const_iterator findMatchingBracket(string::const_iterator start, string::const_iterator end);

/**
 * @brief Parse Expression that start with not ('~')
 *
 * @param start from where to search, after the ~
 * @param end until where to search
 * @return Node in tree
 *
 * two cases are handled "~ip" or "~(...)"
 */
static FilterTree::Node* parseNot(string::const_iterator start, string::const_iterator end);

/**
 * @brief Parse full Expression
 *
 * @param start from where to search
 * @param end until where to search
 * @return Node in tree
 */
static FilterTree::Node* parseExpr(string::const_iterator start, string::const_iterator end);
static hungry_sniffer::Protocol::filterFunction extractRegex(const hungry_sniffer::Protocol* protocol, const string& regexParts, std::smatch& sm);
static FilterTree::Node* parseEndExpr(string::const_iterator start, string::const_iterator end);




static string::const_iterator findMatchingBracket(string::const_iterator start, string::const_iterator end)
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

static void findMatchingExprEnd(string::const_iterator& start, string::const_iterator end)
{
    for(; start != end && *start != '&' && *start != '|'; ++start)
        if(*start == '(')
           start = findMatchingBracket(start, end) - 1;
}

static void stripSpaces(string::const_iterator& start, string::const_iterator& end)
{
    while(*start == ' ')
        ++start;
    while(*(end - 1) == ' ')
        --end;
}

static FilterTree::Node* parseNot(string::const_iterator start, string::const_iterator end)
{
    stripSpaces(start, end);
    switch(*start)
    {
        case '(':
            return new FilterTree::Node(parseExpr(start + 1, end - 1), nullptr, FilterTree::Node::Not);
        case '~':
            return parseExpr(start + 1, end - 1);
        default:
            return new FilterTree::Node(parseEndExpr(start, end), nullptr, FilterTree::Node::Not);
    }
}

static FilterTree::Node* parseExpr(string::const_iterator start, string::const_iterator end)
{
    stripSpaces(start, end);
    FilterTree::Node* temp = nullptr;

    string::const_iterator i = start, exprStart;

    while(i != end)
    {
        switch(*i)
        {
            case ' ':
                ++i;
                break;
            case '(':
                exprStart = ++i;
                i = findMatchingBracket(i, end) - 1;
                temp = parseExpr(exprStart, i);
                if(i == end)
                    return temp;
                ++i;
                break;
            case '~':
                exprStart = ++i;
                findMatchingExprEnd(i, end);

                temp = parseNot(exprStart, i);
                if(i == end)
                    return temp;
                ++i;
                break;
            case '&':
            case '|':
                exprStart = ++i;
                findMatchingExprEnd(i, end);

                temp = new FilterTree::Node(temp, parseExpr(exprStart, i),
                        (*(exprStart - 1) == '&' ? FilterTree::Node::Type::And : FilterTree::Node::Type::Or));
                if(i == end)
                    return temp;
                ++i;
                break;
            default:
                findMatchingExprEnd(i, end);
                temp = parseEndExpr(start, i);
                break;
        }
    }
    return temp;
}

static hungry_sniffer::Protocol::filterFunction extractRegex(const hungry_sniffer::Protocol* protocol, const string& regexParts, std::smatch& sm)
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

static FilterTree::Node* parseEndExpr(string::const_iterator start, string::const_iterator end)
{
    stripSpaces(start, end);
    string::const_iterator dot = std::find(start, end, '.');
    string name(start, dot);
    const hungry_sniffer::Protocol* protocol = SniffWindow::baseProtocol->findProtocol(name);

    if(!protocol)
    {
        qDebug("protocol %s not found", name.c_str());
        return nullptr;
    }

    if(end != dot)
    {
        std::smatch sm;
        return new FilterTree::Node(protocol, extractRegex(protocol, string(dot + 1, end), sm), std::move(sm));
    }
    else // only name
    {
        return new FilterTree::Node(protocol);
    }
}

FilterTree::FilterTree(const std::string &filterString)
{
    this->root = parseExpr(filterString.cbegin(), filterString.cend());
}
