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

#ifndef FILTER_TREE_H
#define FILTER_TREE_H

#include "hs_protocol.h"

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
        Node* nodeArr = nullptr;
        Node* root = nullptr;
        std::vector<std::string>* smatchesArr = nullptr;
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
