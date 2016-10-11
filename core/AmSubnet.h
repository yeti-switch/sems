#pragma once

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

    bool parse(std::string &s);
    bool contains(const sockaddr_storage &addr) const;
};

