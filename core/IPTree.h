#pragma once

#include "AmSubnet.h"

#include <vector>
#include <set>
#include <string>
#include <memory>
#include <optional>

#include <sys/socket.h>

class IPTree {
    struct Node {
        // use set to resolve collisions
        std::set<int>         indexes;
        std::unique_ptr<Node> zero;
        std::unique_ptr<Node> one;
        void                  clear();
    };

    Node ipv4_root;
    Node ipv6_root;

    Node *get_node_ipv4(const sockaddr_storage &addr, unsigned int mask_len);
    Node *get_node_ipv6(const sockaddr_storage &addr, unsigned int mask_len);
    void  serialize_nodes_tree(const Node &node, AmArg &ret) const;

  public:
    using MatchResult = std::vector<int /* external index */>;
    void clear();

    void addSubnet(const AmSubnet &subnet, int external_index);
    /* fills ret with matched nodes */
    void                       match(const sockaddr_storage &addr, MatchResult &ret) const;
    std::optional<MatchResult> match(const sockaddr_storage &addr) const;

    operator AmArg() const;
};
