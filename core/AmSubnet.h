#pragma once

#include "AmArg.h"

#include <sys/socket.h>
#include <stdint.h>
#include <string>

class AmSubnet {
    std::string raw;

    sockaddr_storage addr;
    sockaddr_storage mask;
    sockaddr_storage network;
    unsigned int mask_len;

    bool parse_addr(const std::string &addr_str);
    bool parse_mask(const std::string &mask_str);
  public:
    AmSubnet();
    ~AmSubnet() {}

    bool parse(const std::string &s);
    bool contains(const sockaddr_storage &addr) const;

    const sockaddr_storage& get_addr() const { return addr; }
    const sockaddr_storage& get_mask() const { return mask; }
    const sockaddr_storage& get_network() const { return network; }
    unsigned int get_mask_len() const { return mask_len; }
    operator AmArg() const;
};

