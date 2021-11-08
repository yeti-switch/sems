#include "AmSubnet.h"

#include "log.h"
#include "sip/ip_util.h"

#include "AmUtils.h"

#include <vector>
#include <cstring>

#define SAv4_addr(v) (SAv4(&v)->sin_addr.s_addr)
#define SAv6_addr(v) ((uint64_t*)(SAv6(&v)->sin6_addr.s6_addr))

#define TYP_INIT 0 
#define TYP_SMLE 1 
#define TYP_BIGE 2
static unsigned long long htonll(unsigned long long src) { 
  static int typ = TYP_INIT; 
  unsigned char c; 
  union { 
    unsigned long long ull; 
    unsigned char c[8]; 
  } x; 
  if (typ == TYP_INIT) { 
    x.ull = 0x01; 
    typ = (x.c[7] == 0x01ULL) ? TYP_BIGE : TYP_SMLE; 
  } 
  if (typ == TYP_BIGE) 
    return src; 
  x.ull = src; 
  c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c; 
  c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c; 
  c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c; 
  c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c; 
  return x.ull; 
}

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
    if(mask_str.empty()){
        mask_len = addr.ss_family == AF_INET ? 32 : 128;
    } else if(str2i(mask_str, mask_len)){
        ERROR("%s(%s) invalid mask value",FUNC_NAME,
              mask_str.c_str());
        return false;
    }

    mask.ss_family = addr.ss_family;
    network.ss_family = addr.ss_family;
    if(addr.ss_family == AF_INET) {
        SAv4_addr(mask) = htonl((~0UL) << (32-mask_len));
        SAv4_addr(network) = SAv4_addr(addr) & SAv4_addr(mask);
    } else {
        SAv6_addr(mask)[0] = (mask_len >= 64 ? htonll(~0ULL) : (htonll((~0ULL) << (64-mask_len))));
        SAv6_addr(mask)[1] = (mask_len >= 64 ? htonll((~0ULL) << (128-mask_len)) : 0);
        SAv6_addr(network)[0] = SAv6_addr(addr)[0] & SAv6_addr(mask)[0];
        SAv6_addr(network)[1] = SAv6_addr(addr)[1] & SAv6_addr(mask)[1];
    }

    return true;
}

bool AmSubnet::parse(const std::string &s)
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
        return false;
    }
    if(addr.ss_family == AF_INET) {
        return ( SAv4_addr(network) == (SAv4_addr(ip) & SAv4_addr(mask)));
    } else {
        return ( SAv6_addr(network)[0] == (SAv6_addr(ip)[0] & SAv6_addr(mask)[0])) &&
               ( SAv6_addr(network)[1] == (SAv6_addr(ip)[1] & SAv6_addr(mask)[1]));
    }
}

AmSubnet::operator AmArg() const
{
    AmArg a;
    a["address"] = get_addr_str(&addr);
    a["mask"] = get_addr_str(&mask);
    a["network"] = get_addr_str(&network);
    a["mask_len"] = mask_len;
    return a;
}
