#include "AmSubnet.h"

#include "log.h"
#include "sip/ip_util.h"

#include "AmUtils.h"

#include <vector>
#include <cstring>

#define SAv4_addr(v) (SAv4(&v)->sin_addr.s_addr)

AmSubnet::AmSubnet() {
    memset(&addr,0,sizeof(sockaddr_storage));
    memset(&mask,0,sizeof(sockaddr_storage));
    memset(&network,0,sizeof(sockaddr_storage));
}

bool AmSubnet::parse_addr(const std::string &addr_str)
{
    raw = addr_str;
    if(!am_inet_pton(addr_str.c_str(), &addr)) {
        ERROR("%s(%s) invalid IP address", FUNC_NAME,
              addr_str.c_str());
        return false;
    }
    return true;
}

bool AmSubnet::parse_mask(const std::string &mask_str)
{
    //!TODO: implement IPv6 support
    if(addr.ss_family!=AF_INET){
        ERROR("%s(%s) unsupported address type for '%s'",FUNC_NAME,
              mask_str.c_str(),raw.c_str());
    }

    if(mask_str.empty()){
        mask_len = 32;
    } else if(str2i(mask_str, mask_len)){
        ERROR("%s(%s) invalid mask value",FUNC_NAME,
              mask_str.c_str());
        return false;
    }

    mask.ss_family = AF_INET;
    SAv4_addr(mask) = htonl(0xFFFFFFFF << (32-mask_len));

    network.ss_family = AF_INET;
    SAv4_addr(network) = SAv4_addr(addr) & SAv4_addr(mask);

    return true;
}

bool AmSubnet::parse(std::string &s)
{
    if(s.empty()) return false;

    std::vector<string> v = explode(s, "/");
    if(v.size()>2) {
        ERROR("wrong subnet string (too many slashes): '%s'",s.c_str());
        return false;
    }

    return parse_addr(v[0]) && parse_mask(v.size() > 1 ? v[1] : string());
}

bool AmSubnet::contains(const sockaddr_storage &ip) const
{
    if(ip.ss_family!=network.ss_family){
        DBG("%s() different address families",FUNC_NAME);
        return false;
    }
    //!TODO: implement IPv6 support
    return ( SAv4_addr(network) == (SAv4_addr(ip) & SAv4_addr(mask)));
}
