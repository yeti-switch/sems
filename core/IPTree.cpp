#include "IPTree.h"
#include "sip/ip_util.h"

#include <byteswap.h>

void IPTree::Node::clear()
{
    one.reset();
    zero.reset();
    indexes.clear();
}

IPTree::Node *IPTree::get_node_ipv4(const sockaddr_storage &addr, unsigned int mask_len)
{
    Node *node = &ipv4_root;
    if (!mask_len) {
        return node;
    }

    auto         addr_bytes = bswap_32(SAv4(&addr)->sin_addr.s_addr);
    unsigned int bit_mask   = 1U << 31;
    while (mask_len--) {
        auto &child = (addr_bytes & bit_mask) ? node->one : node->zero;
        node        = child.get();
        if (!node) {
            node = new Node();
            child.reset(node);
        }
        bit_mask >>= 1;
    }

    return node;
}

IPTree::Node *IPTree::get_node_ipv6(const sockaddr_storage &addr, unsigned int mask_len)
{
    Node *node = &ipv6_root;
    if (!mask_len) {
        return node;
    }

    const uint8_t *addr_bytes = &SAv6(&addr)->sin6_addr.s6_addr[0];
    unsigned int   bit_mask   = 1 << 7;
    while (mask_len--) {
        auto &child = ((*addr_bytes) & bit_mask) ? node->one : node->zero;
        node        = child.get();
        if (!node) {
            node = new Node();
            child.reset(node);
        }

        bit_mask >>= 1;
        if (!bit_mask) {
            bit_mask = 1 << 7;
            addr_bytes++;
        }
    }
    return node;
}

void IPTree::serialize_nodes_tree(const Node &node, AmArg &ret) const
{
    ret.assertStruct();
    if (!node.indexes.empty()) {
        auto &a = ret["idx"];
        for (const auto &idx : node.indexes)
            a.push(idx);
    }
    if (node.one.get()) {
        serialize_nodes_tree(*node.one.get(), ret["1"]);
    }
    if (node.zero.get()) {
        serialize_nodes_tree(*node.zero.get(), ret["0"]);
    }
}

void IPTree::clear()
{
    ipv4_root.clear();
    ipv6_root.clear();
}

void IPTree::addSubnet(const AmSubnet &subnet, int external_index)
{
    auto        mask_len = subnet.get_mask_len();
    const auto &addr     = subnet.get_addr();

    Node *node = (addr.ss_family == AF_INET) ? get_node_ipv4(addr, mask_len) : get_node_ipv6(addr, mask_len);

    node->indexes.emplace(external_index);
}

void IPTree::match(const sockaddr_storage &addr, MatchResult &ret) const
{
    if (addr.ss_family == AF_INET) {
        auto        *node       = &ipv4_root;
        auto         addr_bytes = bswap_32(SAv4(&addr)->sin_addr.s_addr);
        unsigned int bit_mask   = 1U << 31;
        do {
            for (const auto &idx : node->indexes)
                ret.push_back(idx);

            node = (addr_bytes & bit_mask) ? node->one.get() : node->zero.get();

            bit_mask >>= 1;
        } while (node);
    } else {
        auto          *node       = &ipv6_root;
        const uint8_t *addr_bytes = &SAv6(&addr)->sin6_addr.s6_addr[0];
        unsigned int   bit_mask   = 1 << 7;
        do {
            for (const auto &idx : node->indexes)
                ret.push_back(idx);

            node = ((*addr_bytes) & bit_mask) ? node->one.get() : node->zero.get();

            bit_mask >>= 1;
            if (!bit_mask) {
                bit_mask = 1 << 7;
                addr_bytes++;
            }
        } while (node);
    }
}

std::optional<IPTree::MatchResult> IPTree::match(const sockaddr_storage &addr) const
{
    IPTree::MatchResult result;

    match(addr, result);

    if (result.empty())
        return std::nullopt;
    return result;
}

IPTree::operator AmArg() const
{
    AmArg ret;
    serialize_nodes_tree(ipv4_root, ret["ip4"]);
    serialize_nodes_tree(ipv6_root, ret["ip6"]);
    return ret;
}
