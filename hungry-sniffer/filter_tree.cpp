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

#include "filter_tree.h"
#include "sniff_window.h"
#include <hs_core.h>

enum NodeTypes {
    // if first bit is ON, then this is one type of NOT

    Value = 0, // 000
    Not = 1,   // 001
    Or = 2,    // 010
    Nor = 3,   // 011
    And = 4,   // 100
    Nand = 5,  // 101
};

struct TempNode {
    public:
        union {
            struct {
                TempNode* left;
                TempNode* right;
            } tree;
            struct {
                const hungry_sniffer::Protocol* protocol;
                hungry_sniffer::Protocol::filterFunction function;
            } filter;
        } data;
        enum NodeTypes type;
        std::vector<std::string> matches;
    public:
        TempNode(const hungry_sniffer::Protocol* protocol)
        {
            this->type = NodeTypes::Value;
            this->data.filter.protocol = protocol;
            this->data.filter.function = nullptr;
        }
        TempNode(const hungry_sniffer::Protocol* protocol, hungry_sniffer::Protocol::filterFunction function, const std::smatch& _matches)
        {
            this->type = NodeTypes::Value;
            this->data.filter.protocol = protocol;
            this->data.filter.function = function;

            matches.reserve(_matches.size());
            for(auto& i : _matches)
            {
                matches.push_back(i.str());
            }
        }
        TempNode(TempNode* left, TempNode* right, enum NodeTypes type)
        {
            this->data.tree.left = left;
            this->data.tree.right = right;
            this->type = type;
        }
        ~TempNode()
        {
            if(this->type != NodeTypes::Value)
            {
                delete this->data.tree.left;
                delete this->data.tree.right;
            }
        }
};

using std::string;
using std::vector;

namespace parseString {

    static TempNode* parseExpr(string::const_iterator start, string::const_iterator end);
    static TempNode* parseEndExpr(string::const_iterator start, string::const_iterator end);

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
        while(*start == ' ' && start != end)
            ++start;
        while(*(end - 1) == ' ' && start != end)
            --end;
    }

    static TempNode* parseNot(string::const_iterator start, string::const_iterator end)
    {
        stripSpaces(start, end);
        switch(*start)
        {
            case '(':
                return new TempNode(parseExpr(start + 1, end - 1), nullptr, NodeTypes::Not);
            case '~':
                return new TempNode(parseNot(start + 1, end), nullptr, NodeTypes::Not);
            default:
                return new TempNode(parseEndExpr(start, end), nullptr, NodeTypes::Not);
        }
    }

    static TempNode* parseExpr(string::const_iterator start, string::const_iterator end)
    {
        stripSpaces(start, end);
        TempNode* temp = nullptr;

        string::const_iterator i = start, exprStart;

        while(i != end)
        {
            switch(*i)
            {
                case ')':
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
                    break;
                case '&':
                case '|':
                    ++i;
                    if((*i ^ *(i-1)) == 0)
                        ++i;
                    exprStart = i;
                    findMatchingExprEnd(i, end);

                    temp = new TempNode(temp, parseExpr(exprStart, i),
                            (*(exprStart - 1) == '&' ? NodeTypes::And : NodeTypes::Or));
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
        for(auto& i : protocol->getFilters())
        {
            if(std::regex_search(regexParts, sm, i.first))
            {
                return i.second;
            }
        }
        return nullptr;
    }

    static TempNode* parseEndExpr(string::const_iterator start, string::const_iterator end)
    {
        stripSpaces(start, end);
        string::const_iterator dot = std::find(start, end, '.');
        string name(start, dot);
        const hungry_sniffer::Protocol* protocol = SniffWindow::core->base.findProtocol(name);

        if(!protocol)
        {
#ifndef QT_NO_DEBUG
            qDebug("protocol %s not found", name.c_str());
#endif
            return nullptr;
        }

        if(end != dot)
        {
            std::smatch sm;
            return new TempNode(protocol, extractRegex(protocol, string(dot + 1, end), sm), sm);
        }
        else // only name
        {
            return new TempNode(protocol);
        }
    }
}

namespace optimizeFilter {
    struct res {
        uint_fast16_t nodeCount;
        uint_fast16_t valueCount;

        res& operator+=(const res& other)
        {
            nodeCount += other.nodeCount;
            valueCount += other.valueCount;
            return *this;
        }
    };

    struct res countNodes(const TempNode* root)
    {
        struct res r = {1, 0};
        switch(root->type)
        {
            case NodeTypes::Value:
                r.valueCount = 1;
                break;
            case NodeTypes::Not:
                r += countNodes(root->data.tree.left);
                break;
            case NodeTypes::And:
            case NodeTypes::Or:
            case NodeTypes::Nor:
            case NodeTypes::Nand:
                r += countNodes(root->data.tree.left);
                r += countNodes(root->data.tree.right);
                break;
        }
        return r;
    }

    static FilterTree::Node* putNode(FilterTree::Node* nodeArr, int& nodeLoc, vector<std::string>* smatchesArr, int& smatchLoc, TempNode* temp)
    {
        if(!temp)
            return nullptr;
        FilterTree::Node* pos = nodeArr + nodeLoc;
        nodeLoc++;
        pos->type = temp->type;

        if(temp->type == NodeTypes::Value)
        {
            if(temp->matches.size() > 0)
            {
                smatchesArr[smatchLoc] = std::move(temp->matches);
                pos->data.value.smatches = smatchesArr + smatchLoc;
                smatchLoc++;
            }
            else
                pos->data.value.smatches = nullptr;
            pos->data.value.func = temp->data.filter.function;
            pos->data.value.protocol = temp->data.filter.protocol;
        }
        else
        {
            pos->data.ptr.left = putNode(nodeArr, nodeLoc, smatchesArr, smatchLoc, temp->data.tree.left);
            pos->data.ptr.right = putNode(nodeArr, nodeLoc, smatchesArr, smatchLoc, temp->data.tree.right);
            switch(pos->type) // here it can be only And/Or/Not
            {
                case NodeTypes::Not:
                {
                    FilterTree::Node* child1 = pos->data.ptr.left;
                    switch(child1->type)
                    {
                        case NodeTypes::Not:
                            return child1->data.ptr.left;
                        case NodeTypes::And:
                        case NodeTypes::Nand:
                        case NodeTypes::Or:
                        case NodeTypes::Nor:
                            pos->type = child1->type ^ 1;
                            pos->data.ptr.left = child1->data.ptr.left;
                            pos->data.ptr.right = child1->data.ptr.right;
                            break;
                    }
                    break;
                }
                case NodeTypes::And:
                case NodeTypes::Or:
                {
                    FilterTree::Node* child1 = pos->data.ptr.left;
                    FilterTree::Node* child2 = pos->data.ptr.right;
                    if(((child1->type & child2->type) & 1) == 1) // NOR / NAND / NOT
                    {
                        child1->type = child1->type & ~1;
                        child2->type = child2->type & ~1;
                        if(child1->type == 0)
                            pos->data.ptr.left = child1->data.ptr.left;
                        if(child2->type == 0)
                            pos->data.ptr.right = child2->data.ptr.left;
                        static_assert(7 - NodeTypes::And == NodeTypes::Nor, "");
                        static_assert(7 - NodeTypes::Or == NodeTypes::Nand, "");
                        pos->type = 7 - pos->type;
                    }
                    break;
                }
            }
        }

        return pos;
    }

    static FilterTree::Node* optimize(FilterTree::Node* nodeArr, vector<std::string>* smatchesArr, TempNode* temp)
    {
        int nodeLoc = 0, smatchLoc = 0;
        return putNode(nodeArr, nodeLoc, smatchesArr, smatchLoc, temp);
    }
}

FilterTree::FilterTree(const std::string &filterString)
{
    TempNode* temp = parseString::parseExpr(filterString.cbegin(), filterString.cend());
    if(!temp) return;
    optimizeFilter::res r = optimizeFilter::countNodes(temp);
    nodeArr = (FilterTree::Node*)malloc(r.nodeCount * sizeof(FilterTree::Node));
    smatchesArr = new std::vector<std::string>[r.valueCount];
    root = optimizeFilter::optimize(this->nodeArr, this->smatchesArr, temp);
    delete temp;
}

bool FilterTree::Node::get(const hungry_sniffer::Packet *eth) const
{
    switch (this->type) {
        case NodeTypes::Value:
        {
            const hungry_sniffer::Packet* p = eth->hasProtocol(this->data.value.protocol);
            if(!p)
                return false;
            return !this->data.value.func || this->data.value.func(p, this->data.value.smatches);
        }
        case NodeTypes::Or:
            return this->data.ptr.left->get(eth) || this->data.ptr.right->get(eth);
        case NodeTypes::And:
            return this->data.ptr.left->get(eth) && this->data.ptr.right->get(eth);
        case NodeTypes::Not:
            return !this->data.ptr.left->get(eth);
        case NodeTypes::Nor:
            return !(this->data.ptr.left->get(eth) || this->data.ptr.right->get(eth));
        case NodeTypes::Nand:
            return !(this->data.ptr.left->get(eth) && this->data.ptr.right->get(eth));
    }
    return false;
}
