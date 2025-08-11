/*
 * $Id: resolver.cpp 1048 2008-07-15 18:48:07Z sayer $
 *
 * Copyright (C) 2007 Raphael Coeffic
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "resolver.h"
#include "hash.h"

#include "parse_dns.h"
#include "parse_common.h"
#include "ip_util.h"
#include "trans_layer.h"
#include "tr_blacklist.h"
#include "wheeltimer.h"

#include "AmUtils.h"
#include "AmStatistics.h"

#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <assert.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <list>
#include <utility>
#include <algorithm>
#include <iterator>
#include <string_view>

using std::list;
using std::make_pair;
using std::pair;

#include "log.h"
#include "socket_ssl.h"

#define DEFAULT_SIP_PORT  5060
#define DEFAULT_RTSP_PORT 554

#define ALIAS_RESOLVING_LIMIT 5

// Maximum number of SRV entries
// within a cache entry
//
// (the limit is the # bits in dns_handle::srv_used)
#define MAX_SRV_RR (sizeof(unsigned int) * 8)

#define DNS_REPLY_BUFFER_SIZE NS_PACKETSZ * 2

/* in seconds */
#define DNS_CACHE_CYCLE 10L

/* avoids issues with racing on DNS cache operations
 * and with DNS responses with entries TTL 0 */
#define DNS_CACHE_EXPIRE_DELAY 2

/* in us */
#define DNS_CACHE_SINGLE_CYCLE ((DNS_CACHE_CYCLE * 1000000L) / DNS_CACHE_SIZE)

const char *dns_priority_str(const dns_priority priority)
{
#define dpts(e)                                                                                                        \
    case e: return #e;
    switch (priority) {
        dpts(IPv4_only) dpts(IPv6_only) dpts(Dualstack) dpts(IPv4_pref) dpts(IPv6_pref)
    };
    return "";
}

dns_priority string_to_priority(const string &priority)
{
#define stdp(e)                                                                                                        \
    if (priority == #e)                                                                                                \
        return e;
    stdp(IPv4_only) stdp(IPv6_only) stdp(Dualstack) stdp(IPv4_pref) stdp(IPv6_pref) return IPv4_only;
}

struct srv_entry : public dns_base_entry {
    string target;

    unsigned short p;
    unsigned short w;
    unsigned short port;

    virtual string to_str();
};

struct cname_entry : public dns_base_entry {
    string         target;
    virtual string to_str();
};

string cname_entry::to_str()
{
    return string("CNAME/") + target;
}

int dns_ip_entry::next_ip(dns_handle *h, sockaddr_storage *sa, dns_priority priority)
{
    if (h->ip_e != this) {
        h->prepare(this, priority);
    }

    int &index = h->ip_n;
    if ((index < 0) || (index >= static_cast<int>(h->ip_indexes.size())))
        return 0;

    int ip_index = static_cast<int>(h->ip_indexes[static_cast<size_t>(h->ip_n)]);
    if ((ip_index < 0) || (ip_index >= static_cast<int>(ip_vec.size())))
        return -1;

    // copy address
    dynamic_cast<ip_entry *>(ip_vec[static_cast<size_t>(ip_index)])->to_sa(sa);
    index++;

    // reached the end?
    if (index >= static_cast<int>(h->ip_indexes.size())) {
        index = -1;
    }

    return 1;
}

void dns_ip_entry::sort_by_priority(dns_handle *handle, dns_priority priority)
{
    size_t i;
    auto  &ret = handle->ip_indexes;

    ret.reserve(ip_vec.size());

    if (priority == Dualstack) {
        for (i = 0; i < ip_vec.size(); i++)
            ret.emplace_back(i);
        return;
    }

    if (priority == IPv4_pref || priority == IPv4_only) {
        // add ipv4 head
        for (i = 0; i < ip_vec.size(); i++) {
            if (IPv4 == dynamic_cast<ip_entry *>(ip_vec[i])->type)
                ret.emplace_back(i);
        }
        if (priority == IPv4_only || !ret.empty())
            return;
        // add ipv6 tail
        for (i = 0; i < ip_vec.size(); i++) {
            if (IPv6 == dynamic_cast<ip_entry *>(ip_vec[i])->type)
                ret.emplace_back(i);
        }
        return;
    }

    if (priority == IPv6_pref || priority == IPv6_only) {
        // add ipv6 head
        for (i = 0; i < ip_vec.size(); i++) {
            if (IPv6 == dynamic_cast<ip_entry *>(ip_vec[i])->type)
                ret.emplace_back(i);
        }
        if (priority == IPv6_only || !ret.empty())
            return;
        // add ipv4 tail
        for (i = 0; i < ip_vec.size(); i++) {
            if (IPv4 == dynamic_cast<ip_entry *>(ip_vec[i])->type)
                ret.emplace_back(i);
        }
        return;
    }
}

dns_base_entry *dns_ip_entry::get_rr(dns_record *rr, u_char *, u_char *)
{
    // TODO: check record size

    ip_entry *new_ip = new ip_entry{};
    if (rr->type == ns_t_a) {
        DBG3("A: TTL=%i %s %i.%i.%i.%i", ns_rr_ttl(*rr), ns_rr_name(*rr), ns_rr_rdata(*rr)[0], ns_rr_rdata(*rr)[1],
             ns_rr_rdata(*rr)[2], ns_rr_rdata(*rr)[3]);
        new_ip->type = IPv4;
        memcpy(&(new_ip->addr), ns_rr_rdata(*rr), sizeof(in_addr));
    } else if (rr->type == ns_t_aaaa) {
        const u_short *a = reinterpret_cast<const u_short *>(ns_rr_rdata(*rr));
        DBG3("AAAA: TTL=%i %s %x:%x:%x:%x:%x:%x:%x:%x", ns_rr_ttl(*rr), ns_rr_name(*rr), htons(a[0]), htons(a[1]),
             htons(a[2]), htons(a[3]), htons(a[4]), htons(a[5]), htons(a[6]), htons(a[7]));
        new_ip->type = IPv6;
        memcpy(&(new_ip->addr6), ns_rr_rdata(*rr), sizeof(in6_addr));
    } else {
        delete new_ip;
        return nullptr;
    }

    return new_ip;
}

bool dns_ip_entry::union_rr(const vector<dns_base_entry *> &entries)
{
    for (auto &entry : entries) {
        ip_entry &casted_entry = *dynamic_cast<ip_entry *>(entry);
        if (count_if(ip_vec.begin(), ip_vec.end(), [&casted_entry](const dns_base_entry *e) {
                return casted_entry == *dynamic_cast<const ip_entry *>(e);
            }))
        {
            continue;
        }
        ip_vec.push_back(casted_entry.clone());
    }
    return true;
}

static bool srv_less(const dns_base_entry *le, const dns_base_entry *re)
{
    const srv_entry *l_srv = dynamic_cast<const srv_entry *>(le);
    const srv_entry *r_srv = dynamic_cast<const srv_entry *>(re);

    if (l_srv->p != r_srv->p)
        return l_srv->p < r_srv->p;
    else
        return l_srv->w < r_srv->w;
};

class dns_srv_entry : public dns_entry {
    unsigned short default_service_port;

  public:
    dns_srv_entry(unsigned short default_service_port)
        : dns_entry(dns_r_srv)
        , default_service_port(default_service_port)
    {
    }

    void init() { stable_sort(ip_vec.begin(), ip_vec.end(), srv_less); }

    dns_base_entry *get_rr(dns_record *rr, u_char *begin, u_char *end);

    int next_ip(dns_handle *h, sockaddr_storage *sa, dns_priority priority)
    {
        int &index = h->srv_n;
        if (index >= static_cast<int>(ip_vec.size()))
            return 0;

        if (h->srv_e != this) {
            h->prepare(this, priority);
        } else if (h->ip_n != -1) {
            if (h->port) {
                // DBG("setting port to %i",ntohs(h->port));
                reinterpret_cast<sockaddr_in *>(sa)->sin_port = h->port;
            } else {
                // DBG("setting port to %i",default_service_port);
                reinterpret_cast<sockaddr_in *>(sa)->sin_port = htons(default_service_port);
            }
            return h->ip_e->next_ip(h, sa, priority);
        }

        if (index < 0) {
            return -1;
        }

        // reset IP record
        h->reset(dns_r_ip);

        list<pair<unsigned int, size_t>> srv_lst;
        size_t                           i = static_cast<size_t>(index);

        // fetch current priority
        unsigned short p     = dynamic_cast<srv_entry *>(ip_vec[i])->p;
        unsigned int   w_sum = 0;

        // and fetch records with same priority
        // which have not been chosen yet
        int          srv_lst_size = 0;
        unsigned int used_mask    = (1 << i);

        while (p == dynamic_cast<srv_entry *>(ip_vec[i])->p) {
            if (!(used_mask & h->srv_used)) {
                w_sum += dynamic_cast<srv_entry *>(ip_vec[i])->w;
                srv_lst.push_back(std::make_pair(w_sum, i));
                srv_lst_size++;
            }

            if ((++i >= ip_vec.size()) || (i >= MAX_SRV_RR)) {
                break;
            }

            used_mask = used_mask << 1;
        }

        srv_entry *e = nullptr;
        if ((srv_lst_size > 1) && w_sum) {
            // multiple records: apply weigthed load balancing
            // - remember the entries which have already been used
            unsigned int r          = random() % (w_sum + 1);
            auto         srv_lst_it = srv_lst.begin();
            while (srv_lst_it != srv_lst.end()) {
                if (srv_lst_it->first >= r) {
                    h->srv_used |= (1 << (srv_lst_it->second));
                    e = dynamic_cast<srv_entry *>(ip_vec[srv_lst_it->second]);
                    break;
                }
                ++srv_lst_it;
            }
            // will only happen if the algorithm
            // is broken
            if (!e)
                return -1;
        } else if (srv_lst_size == 0) {
            // empty srv_lst
            return -1;
        } else {
            // single record or all weights == 0
            e = dynamic_cast<srv_entry *>(ip_vec[srv_lst.begin()->second]);
            if ((i < ip_vec.size()) && (i < MAX_SRV_RR)) {
                index = static_cast<int>(i);
            } else if (!w_sum) {
                index++;
            } else {
                index = -1;
            }
        }

        // TODO: find a solution for IPv6
        h->port = htons(e->port);
        if (h->port) {
            // DBG("setting port to %i",e->port);
            reinterpret_cast<sockaddr_in *>(sa)->sin_port = h->port;
        } else {
            // DBG("setting port to 5060");
            reinterpret_cast<sockaddr_in *>(sa)->sin_port = htons(5060);
        }

        // check if name is an IP address
        if (am_inet_pton(e->target.c_str(), sa) == 1) {
            DBG("target '%s' is an IP address srv_port: %i", e->target.c_str(),
                ntohs(reinterpret_cast<sockaddr_in *>(sa)->sin_port));
            h->ip_n = -1; // flag end of IP list
            return 1;
        }

        DBG("target '%s' must be resolved first. srv_port: %i", e->target.c_str(),
            ntohs(reinterpret_cast<sockaddr_in *>(sa)->sin_port));

        dns_handle tmp_handle;
        if ((resolver::instance()->resolve_name(e->target.c_str(), &tmp_handle, sa, priority) >= 0) && tmp_handle.ip_e)
        {
            const auto &indexes = tmp_handle.ip_indexes; // See dns_ip_entry::sort_by_priority()
            const auto &v       = tmp_handle.ip_e->ip_vec;

            switch (indexes.size()) {
            case 0: break;
            case 1: dynamic_cast<ip_entry *>(v[indexes[0]])->to_sa(sa); return 1;
            default:
                // return random address from the resolved A/AAAA entries
                dynamic_cast<ip_entry *>(v[indexes[std::rand() % indexes.size()]])->to_sa(sa);
                return 1;
            }
        }

        return -1;
    }
};

class dns_cname_entry : public dns_entry {
    string target;

  public:
    dns_cname_entry()
        : dns_entry(dns_r_cname)
    {
    }
    void            init() {}
    dns_base_entry *get_rr(dns_record *rr, u_char *begin, u_char *end);
    int             next_ip(dns_handle *, sockaddr_storage *, const dns_priority) { return -1; }
    dns_entry      *resolve_alias(dns_cache &cache, const dns_priority priority, dns_rr_type tt_type);
};

dns_entry::dns_entry(dns_rr_type type)
    : dns_base_entry()
    , type(type)
{
}

dns_entry::~dns_entry()
{
    DBG3("dns_entry::~dns_entry(): %s", to_str().c_str());
    for (vector<dns_base_entry *>::iterator it = ip_vec.begin(); it != ip_vec.end(); ++it) {
        delete *it;
    }
}

dns_entry *dns_entry::make_entry(ns_type t, unsigned short srv_port)
{
    switch (t) {
    case ns_t_srv:   return new dns_srv_entry(srv_port);
    case ns_t_cname: return new dns_cname_entry();
    case ns_t_a:
    case ns_t_aaaa:  return new dns_ip_entry();
    case ns_t_naptr: return new dns_naptr_entry();
    default:         return nullptr;
    }
}

void dns_entry::add_rr(dns_record *rr, u_char *begin, u_char *end, long now)
{
    dns_base_entry *e = get_rr(rr, begin, end);
    if (!e)
        return;

    e->expire = static_cast<uint64_t>(rr->ttl + now + DNS_CACHE_EXPIRE_DELAY);
    if (expire < e->expire)
        expire = e->expire;

    ip_vec.push_back(e);
}

string dns_entry::to_str()
{
    string res;

    for (vector<dns_base_entry *>::iterator it = ip_vec.begin(); it != ip_vec.end(); it++) {
        if (it != ip_vec.begin())
            res += ", ";
        res += (*it)->to_str();
    }

    return "[" + res + "]";
}

dns_bucket::dns_bucket(unsigned long id)
    : dns_bucket_base(id)
{
}

dns_bucket::~dns_bucket()
{
    for (auto el : elmts) {
        dec_ref(el.second);
    }
}

bool dns_bucket::insert(const string &name, dns_entry *e)
{
    if (!e)
        return false;

    lock();
    if (!(elmts.insert(std::make_pair(name, e)).second)) {
        // if insertion failed
        unlock();
        return false;
    }

    inc_ref(e);
    unlock();

    return true;
}

bool dns_bucket::remove(const string &name)
{
    lock();
    value_map::iterator it = elmts.find(name);
    if (it != elmts.end()) {
        dns_entry *e = it->second;
        elmts.erase(it);

        dec_ref(e);
        unlock();

        return true;
    }

    unlock();
    return false;
}


dns_entry *dns_bucket::find(const string &name)
{
    lock();
    value_map::iterator it = elmts.find(name);
    if (it == elmts.end()) {
        unlock();
        return nullptr;
    }

    dns_entry *e = it->second;

    u_int64_t now = wheeltimer::instance()->unix_clock.get();
    if (now >= e->expire) {
        elmts.erase(it);
        dec_ref(e);
        unlock();
        return nullptr;
    }

    inc_ref(e);
    unlock();
    return e;
}

bool ip_entry::operator==(const ip_entry &entry)
{
    if (type != entry.type)
        return false;
    if (type == IPv4) {
        return addr.s_addr == entry.addr.s_addr;
    } else if (type == IPv6) {
        return IN6_ARE_ADDR_EQUAL(&addr6, &entry.addr6);
    }
    return false;
}

ip_entry *ip_entry::clone()
{
    ip_entry *entry = new ip_entry();
    entry->type     = type;
    if (type == IPv4) {
        memcpy(&entry->addr, &addr, sizeof(in_addr));
    } else if (type == IPv6) {
        memcpy(&entry->addr6, &addr6, sizeof(in6_addr));
    }
    return entry;
}

void ip_entry::to_sa(sockaddr_storage *sa)
{
    // DBG("copying ip_entry...");
    switch (type) {
    case IPv4:
    {
        sockaddr_in *sa_in = reinterpret_cast<sockaddr_in *>(sa);
        sa_in->sin_family  = AF_INET;
        memcpy(&(sa_in->sin_addr), &addr, sizeof(in_addr));
    } break;
    case IPv6:
    {
        sockaddr_in6 *sa_in6 = reinterpret_cast<sockaddr_in6 *>(sa);
        sa_in6->sin6_family  = AF_INET6;
        memcpy(&(sa_in6->sin6_addr), &addr6, sizeof(in6_addr));
    } break;
    default: break;
    }
}

string ip_entry::to_str()
{
    if (type == IPv4) {
        u_char *cp = reinterpret_cast<u_char *>(&addr);
        return string("A/") + int2str(cp[0]) + "." + int2str(cp[1]) + "." + int2str(cp[2]) + "." + int2str(cp[3]);
    } else {
        u_short *cp = reinterpret_cast<u_short *>(&addr);
        return string("AAAA/") + int2hexstr(htons(cp[0])) + ":" + int2hexstr(htons(cp[1])) + ":" +
               int2hexstr(htons(cp[2])) + ":" + int2hexstr(htons(cp[3])) + ":" + int2hexstr(htons(cp[4])) + ":" +
               int2hexstr(htons(cp[5])) + ":" + int2hexstr(htons(cp[6])) + ":" + int2hexstr(htons(cp[7]));
    }
}


void ip_port_entry::to_sa(sockaddr_storage *sa)
{
    DBG("copying ip_port_entry...");
    switch (type) {
    case IPv4:
    {
        sockaddr_in *sa_in = reinterpret_cast<sockaddr_in *>(sa);
        sa_in->sin_family  = AF_INET;
        memcpy(&(sa_in->sin_addr), &addr, sizeof(in_addr));
        if (port) {
            sa_in->sin_port = htons(port);
        } else {
            sa_in->sin_port = htons(5060);
        }
    } break;
    case IPv6:
    {
        sockaddr_in6 *sa_in6 = reinterpret_cast<sockaddr_in6 *>(sa);
        sa_in6->sin6_family  = AF_INET6;
        memcpy(&(sa_in6->sin6_addr), &addr6, sizeof(in6_addr));
        sa_in6->sin6_port = htons(port);
    } break;
    default: break;
    }
}

string ip_port_entry::to_str()
{
    return ip_entry::to_str() + ":" + int2str(port);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

dns_base_entry *dns_srv_entry::get_rr(dns_record *rr, u_char *begin, u_char *end)
{
    if (rr->type != ns_t_srv)
        return nullptr;

    int     ret;
    u_char  name_buf[NS_MAXDNAME];
    u_char *rdata = ns_rr_rdata(*rr);

    /* Expand the target's name */
    u_char *p = rdata + 6;
    if ((ret = dns_expand_name(&p, begin, end, name_buf, /* Result                */
                               NS_MAXDNAME))             /* Size of result buffer */
        < 0)                                             /* Negative: error       */
    {
        ERROR("dns_expand_name failed: %d", ret);
        return nullptr;
    }

    DBG("SRV: TTL=%i %s P=<%i> W=<%i> P=<%i> T=<%s>", ns_rr_ttl(*rr), ns_rr_name(*rr), dns_get_16(rdata),
        dns_get_16(rdata + 2), dns_get_16(rdata + 4), name_buf);

    srv_entry *srv_r = new srv_entry();
    srv_r->p         = dns_get_16(rdata);
    srv_r->w         = dns_get_16(rdata + 2);
    srv_r->port      = dns_get_16(rdata + 4);
    srv_r->target    = reinterpret_cast<const char *>(name_buf);

    return srv_r;
}

#pragma GCC diagnostic pop

string srv_entry::to_str()
{
    return string("SRV/") + target + ":" + int2str(port) + "/" + int2str(p) + "/" + int2str(w);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

dns_base_entry *dns_cname_entry::get_rr(dns_record *rr, u_char *begin, u_char *end)
{
    if (rr->type != ns_t_cname)
        return nullptr;

    int     ret;
    u_char  name_buf[NS_MAXDNAME];
    u_char *rdata = ns_rr_rdata(*rr);

    /* Expand the target's name */
    u_char *p = rdata;
    if ((ret = dns_expand_name(&p, begin, end, name_buf, /* Result                */
                               NS_MAXDNAME))             /* Size of result buffer */
        < 0)                                             /* Negative: error       */
    {                                                    /* Negative: error       */
        ERROR("dns_expand_name failed: %d", ret);
        return nullptr;
    }

    DBG("CNAME: TTL=%i %s T=<%s>", ns_rr_ttl(*rr), ns_rr_name(*rr), name_buf);

    cname_entry *cname_r = new cname_entry();
    cname_r->target      = reinterpret_cast<const char *>(name_buf);

    return cname_r;
}

#pragma GCC diagnostic pop

dns_entry *dns_cname_entry::resolve_alias(dns_cache &cache, const dns_priority priority, dns_rr_type rr_type)
{
    dns_bucket *b;

    if (ip_vec.empty()) {
        DBG("empty cname entry");
        return nullptr;
    }

    if (rr_type == dns_r_srv) {
        DBG("skip CNAME alias resolving for SRV");
        return nullptr;
    }

    string &target = dynamic_cast<cname_entry *>(ip_vec[0])->target;
    DBG("cname entry points to target: %s."
        " search for appropriate entry in the local cache",
        target.c_str());
    b            = cache.get_bucket(hashlittle(target.data(), target.size(), 0));
    dns_entry *e = b->find(target);
    if (e) {
        DBG("return entry %s found in the local cache", e->to_str().c_str());
        return e;
    }

    DBG("entry for target %s is not found in the local cache. try to resolve it", target.c_str());

    switch (rr_type) {
    case dns_r_ip:
        resolver::instance()->query_dns(target.c_str(), rr_type, IPv4);
        resolver::instance()->query_dns(target.c_str(), rr_type, IPv6);
        break;
    default:
        if (resolver::instance()->query_dns(target.c_str(), rr_type, IPnone) < 0) {
            return nullptr;
        }
    }

    // final lookup in the cache
    e = b->find(target);
    if (e) {
        DBG("return resolved entry %s from the cache", e->to_str().c_str());
    }
    return e;
}

struct dns_search_h {
    dns_entry_map entry_map;
    uint64_t      now;

    dns_search_h() { now = wheeltimer::instance()->unix_clock.get(); }
};

int rr_to_dns_entry(dns_record *rr, dns_section_type t, u_char *begin, u_char *end, void *data)
{
    // only answer and additional sections
    if (t != dns_s_an && t != dns_s_ar)
        return 0;

    dns_search_h *h    = static_cast<dns_search_h *>(data);
    string        name = ns_rr_name(*rr);

    dns_entry              *dns_e = nullptr;
    dns_entry_map::iterator it    = h->entry_map.find(name);

    if (it == h->entry_map.end()) {
        dns_e = dns_entry::make_entry(static_cast<ns_type>(rr->type));
        if (!dns_e) {
            // unsupported record type
            return 0;
        }
        if (!h->entry_map.insert(name, dns_e)) {
            delete dns_e;
            dns_e = nullptr;
        }
    } else {
        dns_e = it->second;
    }

    if (dns_e)
        dns_e->add_rr(rr, begin, end, static_cast<long>(h->now));

    return 0;
}

dns_handle::dns_handle()
    : srv_e(nullptr)
    , srv_n(0)
    , ip_e(nullptr)
    , ip_n(0)
{
}

dns_handle::dns_handle(const dns_handle &h)
{
    *this = h;
}

dns_handle::~dns_handle()
{
    if (ip_e)
        dec_ref(ip_e);
    if (srv_e)
        dec_ref(srv_e);
}

bool dns_handle::valid()
{
    return (ip_e) || (srv_e);
}

bool dns_handle::eoip()
{
    if (srv_e)
        return (srv_n == -1) && (ip_n == -1);
    else
        return (ip_n == -1);
}

u_int64_t dns_handle::get_expired()
{
    if (srv_e)
        return srv_e->expire;
    else if (ip_e)
        return ip_e->expire;
    else
        return 0;
}

int dns_handle::next_ip(sockaddr_storage *sa, dns_priority priority)
{
    if (!valid() || eoip())
        return -1;

    if (srv_e)
        return srv_e->next_ip(this, sa, priority);
    else
        return ip_e->next_ip(this, sa, priority);
}

const dns_handle &dns_handle::operator=(const dns_handle &rh)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclass-memaccess"
    memcpy(this, &rh, sizeof(dns_handle));
#pragma GCC diagnostic pop

    if (srv_e)
        inc_ref(srv_e);
    if (ip_e)
        inc_ref(ip_e);

    return *this;
}

static bool naptr_less(const dns_base_entry *le, const dns_base_entry *re)
{
    const naptr_record *l_naptr = dynamic_cast<const naptr_record *>(le);
    const naptr_record *r_naptr = dynamic_cast<const naptr_record *>(re);

    if (l_naptr->order != r_naptr->order)
        return l_naptr->order < r_naptr->order;
    else
        return l_naptr->pref < r_naptr->pref;
}

void dns_naptr_entry::init()
{
    stable_sort(ip_vec.begin(), ip_vec.end(), naptr_less);
}

dns_base_entry *dns_naptr_entry::get_rr(dns_record *rr, u_char *, u_char *end)
{
    enum NAPTR_FieldIndex {
        NAPTR_Flags       = 0,
        NAPTR_Services    = 1,
        NAPTR_Regexp      = 2,
        NAPTR_Replacement = 3,
        NAPTR_Fields
    };

    if (rr->type != ns_t_naptr)
        return nullptr;

    const u_char *rdata = ns_rr_rdata(*rr);

    unsigned short order = dns_get_16(rdata);
    rdata += 2;

    unsigned short pref = dns_get_16(rdata);
    rdata += 2;

    cstring fields[NAPTR_Fields];

    for (int i = 0; i < NAPTR_Fields; i++) {
        if (rdata > end) {
            ERROR("corrupted NAPTR record!!");
            return nullptr;
        }

        fields[i].len = *(rdata++);
        fields[i].s   = reinterpret_cast<const char *>(rdata);

        rdata += fields[i].len;
    }

    printf("ENUM: TTL=%i P=<%i> W=<%i>"
           " FL=<%.*s> S=<%.*s>"
           " REG=<%.*s> REPL=<%.*s>\n",
           ns_rr_ttl(*rr), order, pref, fields[NAPTR_Flags].len, fields[NAPTR_Flags].s, fields[NAPTR_Services].len,
           fields[NAPTR_Services].s, fields[NAPTR_Regexp].len, fields[NAPTR_Regexp].s, fields[NAPTR_Replacement].len,
           fields[NAPTR_Replacement].s);

    naptr_record *naptr_r = new naptr_record();
    naptr_r->order        = order;
    naptr_r->pref         = pref;
    naptr_r->flags        = c2stlstr(fields[NAPTR_Flags]);
    naptr_r->services     = c2stlstr(fields[NAPTR_Services]);
    naptr_r->regexp       = c2stlstr(fields[NAPTR_Regexp]);
    naptr_r->replace      = c2stlstr(fields[NAPTR_Replacement]);

    return naptr_r;
}

sip_target::sip_target()
{
    bzero(&ss, sizeof(sockaddr_storage));
}

sip_target::sip_target(const sip_target &target)
{
    *this = target;
}

const sip_target &sip_target::operator=(const sip_target &target)
{
    memcpy(&ss, &target.ss, sizeof(sockaddr_storage));
    trsp = target.trsp;
    return *this;
}

void sip_target::clear()
{
    memset(&ss, 0, sizeof(sockaddr_storage));
    trsp = trsp_socket::tr_invalid;
}

void sip_target::resolve(const cstring &trsp_str, bool sips_scheme)
{
    sockaddr_ssl *sa_ssl = reinterpret_cast<sockaddr_ssl *>(&ss);

    sa_ssl->ssl_marker = false;
    int trsp_tmp       = trsp_socket::tr_proto_udp;
    if (trsp_str.len) {
        switch (LOWER_B(trsp_str.s[0])) {
        case 'u':
            if (3 == trsp_str.len && 'd' == LOWER_B(trsp_str.s[1]) && 'p' == LOWER_B(trsp_str.s[2])) {
                // udp
                trsp_tmp = trsp_socket::tr_proto_udp;
            }
            break;
        case 't':
            if (3 == trsp_str.len) {
                // tcp|tls
                switch (LOWER_B(trsp_str.s[1])) {
                case 'c':
                    if ('p' == LOWER_B(trsp_str.s[2])) {
                        // tcp
                        trsp_tmp = trsp_socket::tr_proto_tcp;
                    }
                    break;
                case 'l':
                    if ('s' == LOWER_B(trsp_str.s[2])) {
                        // tls
                        trsp_tmp           = trsp_socket::tr_proto_tls;
                        sa_ssl->ssl_marker = true;
                    }
                    break;
                }
            }
            break;
        case 'w':
            // ws|wss
            switch (trsp_str.len) {
            case 2:
                if ('s' == LOWER_B(trsp_str.s[1])) {
                    // ws
                    trsp_tmp = trsp_socket::tr_proto_ws;
                }
                break;
            case 3:
                if ('s' == LOWER_B(trsp_str.s[1]) && 's' == LOWER_B(trsp_str.s[2])) {
                    // wss
                    trsp_tmp           = trsp_socket::tr_proto_wss;
                    sa_ssl->ssl_marker = true;
                }
                break;
            }
            break;
        } // switch(LOWER_B(trsp_str.s[0]))
    }

    switch (ss.ss_family) {
    case AF_INET:
        // skip OR with tr_addr_family_ipv4 coz it zero
        // trsp_tmp |= trsp_socket::tr_addr_family_ipv4;
        break;
    case AF_INET6: trsp_tmp |= trsp_socket::tr_addr_family_ipv6; break;
    }

    trsp = static_cast<trsp_socket::socket_transport>(trsp_tmp);

    SA_transport(&ss) = trsp_tmp;

    if (sips_scheme) {
        sa_ssl->ssl_marker = true;
        sa_ssl->sig        = sockaddr_ssl::SIG_RSA;
        sa_ssl->cipher     = sockaddr_ssl::CIPHER_AES128;
        sa_ssl->mac        = sockaddr_ssl::MAC_SHA1;
    }
}

sip_target_set::sip_target_set(dns_priority priority_)
    : priority(priority_)
    , dest_list()
    , dest_list_it(dest_list.begin())
{
}

void sip_target_set::reset_iterator()
{
    dest_list_it = dest_list.begin();
}

bool sip_target_set::has_next()
{
    return dest_list_it != dest_list.end();
}

int sip_target_set::get_next(sockaddr_storage *ss, trsp_socket::socket_transport &next_trsp, unsigned int flags)
{
    do {
        if (!has_next())
            return -1;

        sip_target &t = *dest_list_it;
        memcpy(ss, &t.ss, sizeof(sockaddr_storage));
        next_trsp = t.trsp;

        next();

    } while (!(flags & TR_FLAG_DISABLE_BL) && tr_blacklist::instance()->exist(ss));

    return 0;
}

bool sip_target_set::next()
{
    dest_list_it++;
    return has_next();
}

void sip_target_set::prev()
{
    if (dest_list_it != dest_list.begin())
        dest_list_it--;
}

void sip_target_set::debug()
{
    DBG("target list:");

    for (list<sip_target>::iterator it = dest_list.begin(); it != dest_list.end(); it++) {
        DBG("\t%c %s:%u/%d(%s)", it == dest_list_it ? '>' : ' ', am_inet_ntop(&it->ss).c_str(), am_get_port(&it->ss),
            it->trsp, trsp_socket::socket_transport2proto_str(it->trsp));
    }
}

sip_target_set::sip_target_set(const sip_target_set &other)
{
    dest_list = other.dest_list;
    dest_list_it =
        std::next(dest_list.begin(), std::distance(other.dest_list.begin(),
                                                   static_cast<list<sip_target>::const_iterator>(other.dest_list_it)));
    priority = other.priority;
}

dns_entry_map::dns_entry_map()
    : map<string, dns_entry *>()
{
}

dns_entry_map::~dns_entry_map()
{
    for (iterator it = begin(); it != end(); ++it) {
        dec_ref(it->second);
    }
}

std::pair<dns_entry_map::iterator, bool> dns_entry_map::insert(const dns_entry_map::value_type &x)
{
    return dns_entry_map_base::insert(x);
}

bool dns_entry_map::insert(const string &key, dns_entry *e)
{
    std::pair<iterator, bool> res = emplace(key, e);
    if (res.second) {
        inc_ref(e);
        return true;
    }
    return false;
}

dns_entry *dns_entry_map::fetch(const key_type &key)
{
    iterator it = find(key);
    if (it != end())
        return it->second;
    return nullptr;
}

bool _resolver::disable_srv = false;

_resolver::_resolver()
    : cache(DNS_CACHE_SIZE)
    , b_stop(false)
    , stat_requests_total(stat_group(Counter, "resolver", "requests_total").addAtomicCounter())
    , stat_requests_cached(stat_group(Counter, "resolver", "requests_cached").addAtomicCounter())
    , stat_requests_failed(stat_group(Counter, "resolver", "requests_failed").addAtomicCounter())
    , stat_queries_total(stat_group(Counter, "resolver", "queries_total").addAtomicCounter())
    , stat_queries_parsing_errors(stat_group(Counter, "resolver", "queries_parsing_errors").addAtomicCounter())
    , stat_queries_search_errors_host_not_found(stat_group(Counter, "resolver", "queries_search_errors")
                                                    .addAtomicCounter()
                                                    .addLabel("reason", "host_not_found"))
    , stat_queries_search_errors_no_data(
          stat_group(Counter, "resolver", "queries_search_errors").addAtomicCounter().addLabel("reason", "no_data"))
    , stat_queries_search_errors_try_again(
          stat_group(Counter, "resolver", "queries_search_errors").addAtomicCounter().addLabel("reason", "try_again"))
    , stat_queries_search_errors_recovery(
          stat_group(Counter, "resolver", "queries_search_errors").addAtomicCounter().addLabel("reason", "recovery"))
    , stat_queries_search_errors_unknown(
          stat_group(Counter, "resolver", "queries_search_errors").addAtomicCounter().addLabel("reason", "unknown"))
{
    stat_group(Counter, "resolver", "requests_total").setHelp("resolving attempts total");
    stat_group(Counter, "resolver", "requests_cached").setHelp("resolving attempts processed by the cache");
    stat_group(Counter, "resolver", "requests_failed").setHelp("resolving attempts failed");
    stat_group(Counter, "resolver", "queries_total").setHelp("DNS queries");
    stat_group(Counter, "resolver", "queries_parsing_errors").setHelp("DNS replies parsing errors");
    stat_group(Counter, "resolver", "queries_search_errors").setHelp("DNS search errors");
}

_resolver::~_resolver()
{
    cache.cleanup();
}

void _resolver::dispose()
{
    stop(true);
}

inline bool rr_type_supports_merging(dns_rr_type rr_type)
{
    return rr_type == dns_r_ip;
}

int _resolver::query_dns(const char *name, dns_rr_type rr_type, address_type addr_type)
{
    u_char dns_res[DNS_REPLY_BUFFER_SIZE];

    if (!name)
        return -1;

    DBG3("Querying '%s' (%s)...", name, dns_rr_type_str(rr_type, addr_type));

    stat_queries_total.inc();

    int dns_res_len =
        res_search(name, ns_c_in, dns_rr_type_tons_type(rr_type, addr_type), dns_res, DNS_REPLY_BUFFER_SIZE);

    if (dns_res_len < 0) {
        switch (h_errno) {
        case HOST_NOT_FOUND:
            DBG("%s/%d: Unknown domain", name, rr_type);
            stat_queries_search_errors_host_not_found.inc();
            break;
        case NO_DATA:
            DBG("%s/%d: No records", name, rr_type);
            stat_queries_search_errors_no_data.inc();
            break;
        case TRY_AGAIN:
            DBG("%s/%d: No response for query (try again)", name, rr_type);
            stat_queries_search_errors_try_again.inc();
            break;
        case NO_RECOVERY:
            ERROR("%s/%d: Non recoverable error (FORMERR, REFUSED, NOTIMP)", name, rr_type);
            stat_queries_search_errors_recovery.inc();
            break;
        default:
            ERROR("%s/%d: Unexpected error. res_search returned: %d", name, rr_type, h_errno);
            stat_queries_search_errors_unknown.inc();
            break;
        }

        return 0;
    }

    /*
     * Initialize a handle to this response.  The handle will
     * be used later to extract information from the response.
     */
    dns_search_h h;
    if (dns_msg_parse(dns_res, dns_res_len, rr_to_dns_entry, &h) < 0) {
        DBG("Could not parse DNS reply");
        stat_queries_parsing_errors.inc();
        return -1;
    }

    // save parsed entries to the cache
    for (const auto &it : h.entry_map) {
        const string &name         = it.first;
        dns_entry    *parsed_entry = it.second;

        if (!parsed_entry || parsed_entry->ip_vec.empty())
            continue;

        dns_bucket *b          = cache.get_bucket(hashlittle(name.c_str(), name.length(), 0));
        dns_entry  *hash_entry = b->find(name);

        if (!hash_entry) {
            parsed_entry->init();
            if (b->insert(name, parsed_entry)) {
                DBG3("DNS cache: inserted new entry: '%s' -> %s", name.c_str(), parsed_entry->to_str().c_str());
            }
        } else if (hash_entry->get_type() == parsed_entry->get_type()) {
            if (rr_type_supports_merging(parsed_entry->get_type())) {
                if (hash_entry->union_rr(parsed_entry->ip_vec)) {
                    DBG3("DNS cache: merged entries. name:'%s', merged: %s, parsed: %s", name.c_str(),
                         hash_entry->to_str().c_str(), parsed_entry->to_str().c_str());
                } else {
                    DBG("DNS cache: failed to merge entries. name: '%s', hashed: %s, parsed: %s", name.c_str(),
                        hash_entry->to_str().c_str(), parsed_entry->to_str().c_str());
                }
            } else {
                DBG("DNS cache: ignore duplicate entry. name: '%s', hashed: %s, parsed: %s", name.c_str(),
                    hash_entry->to_str().c_str(), parsed_entry->to_str().c_str());
            }
            dec_ref(hash_entry);
        } else {
            DBG("DNS cache: ignore entry with another type. name: '%s', hashed: %s, parsed: %s", name.c_str(),
                hash_entry->to_str().c_str(), parsed_entry->to_str().c_str());
            dec_ref(hash_entry);
        }
    }

    return 0;
}

int _resolver::resolve_name(const char *name, dns_handle *h, sockaddr_storage *sa, const dns_priority priority,
                            dns_rr_type rr_type)
{
    int ret;

    // already have a valid handle?
    if (h->valid()) {
        if (h->eoip()) {
            return -1;
        }
        ret = h->next_ip(sa, priority);
        if (ret > 0) {
            switch (priority) {
            case IPv4_only:
                if (sa->ss_family == AF_INET)
                    return ret;
                break;
            case IPv6_only:
                if (sa->ss_family == AF_INET6)
                    return ret;
                break;
            default: return ret;
            }
            DBG("no entries for given priority: %s", dns_priority_str(priority));
            return -1;
        }
        return ret;
    }

    stat_requests_total.inc();

    if (rr_type == dns_r_ip) {
        // first try to detect if 'name' is already an IP address
        ret = am_inet_pton(name, sa);
        if (ret == 1) {
            if ((sa->ss_family == AF_INET && priority == IPv6_only) ||
                (sa->ss_family == AF_INET6 && priority == IPv4_only))
            {
                ERROR("Invalid argument, name %s is not compatible with priority type %s", get_addr_str(sa).c_str(),
                      dns_priority_str(priority));

                stat_requests_failed.inc();
                return -1;
            }
            h->ip_n  = -1; // flag end of IP list
            h->srv_n = -1;
            return 0; // 'name' is an IP add
        }
    }

    // name is NOT an IP address -> try a cache look up
    ret = resolve_name_cache(name, h, sa, priority, rr_type);
    if (ret > 0) {
        stat_requests_cached.inc();
        return ret;
    }

    // query dns
    switch (rr_type) {
    case dns_r_ip:
        query_dns(name, rr_type, IPv4);
        query_dns(name, rr_type, IPv6);
        break;
    default:
        if (query_dns(name, rr_type, IPnone) < 0) {
            stat_requests_failed.inc();
            return -1;
        }
    }

    h->reset(rr_type);
    if ((ret = resolve_name_cache(name, h, sa, priority, rr_type)) > 0) {
        return ret;
    }

    stat_requests_failed.inc();
    return -1;
}

int _resolver::str2ip(const char *name, sockaddr_storage *sa, const address_type types)
{
    if (types & IPv4) {
        int ret = inet_pton(AF_INET, name, &reinterpret_cast<sockaddr_in *>(sa)->sin_addr);
        if (ret == 1) {
            reinterpret_cast<sockaddr_in *>(sa)->sin_family = AF_INET;
            return 1;
        } else if (ret < 0) {
            /*ERROR("while trying to detect an IPv4 address '%s': %s",
                  name,strerror(errno));*/
            return ret;
        }
    }

    if (types & IPv6) {
        if ((name[0] == '[') && (name[strlen(name) - 1] == ']')) {
            (const_cast<char *>(name))[strlen(name) - 1] = 0;
            name++;
        }
        int ret = inet_pton(AF_INET6, name, &reinterpret_cast<sockaddr_in6 *>(sa)->sin6_addr);
        if (ret == 1) {
            reinterpret_cast<sockaddr_in6 *>(sa)->sin6_family = AF_INET6;
            return 1;
        } else if (ret < 0) {
            /*ERROR("while trying to detect an IPv6 address '%s': %s",
                  name,strerror(errno));*/
            return ret;
        }
    }

    return 0;
}

int _resolver::set_destination_ip(const cstring &next_scheme, const cstring &next_hop, unsigned short next_port,
                                  const cstring &next_trsp, sockaddr_storage *remote_ip, dns_priority priority,
                                  dns_handle *h_dns)
{

    string nh = c2stlstr(next_hop);

    DBG("checking whether '%s' is IP address...", nh.c_str());
    if (am_inet_pton(nh.c_str(), remote_ip) != 1) {

        // nh does NOT contain a valid IP address
        if (!next_port) {
            // no explicit port specified,
            // try SRV first
            if (disable_srv) {
                DBG("no port specified, but DNS SRV disabled (skipping).");
            } else {
                string srv_name;
                if (!lower_cmp_n(next_scheme, "sip")) {
                    srv_name = "_sip._";

                    if (!next_trsp.len || !lower_cmp_n(next_trsp, "udp")) {
                        srv_name += "udp";
                    } else if (!lower_cmp_n(next_trsp, "tcp")) {
                        srv_name += "tcp";
                    } else if (!lower_cmp_n(next_trsp, "tls")) {
                        srv_name += "tls";
                    } else {
                        DBG("unsupported transport: skip SRV lookup");
                        goto no_SRV;
                    }
                } else if (!lower_cmp_n(next_scheme, "sips")) {
                    srv_name = "_sips._tcp";
                }

                srv_name += "." + nh;

                DBG("no port specified, looking up SRV '%s'...", srv_name.c_str());

                if (resolver::instance()->resolve_name(srv_name.c_str(), h_dns, remote_ip, priority, dns_r_srv) >= 0) {
                    DBG("target %s was resolved by SRV", srv_name.c_str());
                    return 0;
                }

                DBG("no SRV record for %s", srv_name.c_str());
            }
        }

    no_SRV:
        memset(remote_ip, 0, sizeof(sockaddr_storage));
        int err = resolver::instance()->resolve_name(nh.c_str(), h_dns, remote_ip, priority);
        if (err < 0) {
            DBG("Unresolvable Request URI domain <%s>", nh.c_str());
            return RESOLVING_ERROR_CODE;
        }
    } else { // if (am_inet_pton(nh.c_str(), remote_ip) != 1)
        am_set_port(remote_ip, next_port);
    }

    if (!am_get_port(remote_ip)) {
        if (!next_port) {
            if (!lower_cmp_n(next_trsp, "tls"))
                next_port = 5061;
            else
                next_port = 5060;
        }
        am_set_port(remote_ip, next_port);
    }

    DBG("set destination to %s:%u", nh.c_str(), am_get_port(remote_ip));

    return 0;
}

int _resolver::resolve_name_cache(const char *name, dns_handle *h, sockaddr_storage *sa, const dns_priority priority,
                                  dns_rr_type t)
{
    std::string_view name_{ name };
    int              ret, limit;

    // omit final dot
    if (name_.ends_with("."))
        name_.remove_suffix(1);

    dns_bucket *b = cache.get_bucket(hashlittle(name_.data(), name_.length(), 0));
    dns_entry  *e = b->find(string{ name_ });

    // first attempt to get a valid IP
    // (from the cache)
    if (e) {
        if (dns_entry *re = e->resolve_alias(cache, priority, t)) {
            dec_ref(e);
            e     = re;
            limit = ALIAS_RESOLVING_LIMIT;
            while (e) {
                if (!limit) {
                    DBG("recursive resolving chain limit(%d) reached "
                        "for root entry with target: <%s>",
                        ALIAS_RESOLVING_LIMIT, e->to_str().c_str());
                    dec_ref(e);
                    return -1;
                }
                limit--;
                if (nullptr != (re = e->resolve_alias(cache, priority, t))) {
                    dec_ref(e);
                    e = re;
                    continue;
                }
                break;
            }
        }
        if (e->get_type() != t) {
            DBG("resolved to %s but it has different type %s (priority %s). ignore it", e->to_str().c_str(),
                dns_rr_type_str(e->get_type(), IPnone), dns_priority_str(priority));
            dec_ref(e);
            return -1;
        }
        ret = e->next_ip(h, sa, priority);
        dec_ref(e);

        if (ret > 0) {
            switch (priority) {
            case IPv4_only:
                if (sa->ss_family == AF_INET)
                    return ret;
                break;
            case IPv6_only:
                if (sa->ss_family == AF_INET6)
                    return ret;
                break;
            default: return ret;
            }
            DBG("no entries for given priority: %s", dns_priority_str(priority));
            return -1;
        }
        return ret;
    }
    return 0;
}

int _resolver::resolve_targets(const list<sip_destination> &dest_list, sip_target_set *targets)
{
    bool sips_scheme;

    for (list<sip_destination>::const_iterator it = dest_list.begin(); it != dest_list.end(); it++) {
        sip_target t;
        dns_handle h_dns;

        DBG("sip_destination: %.*s:%.*s:%u/%.*s", it->scheme.len, it->scheme.s, it->host.len, it->host.s, it->port,
            it->trsp.len, it->trsp.s);

        if (set_destination_ip(it->scheme, it->host, it->port, it->trsp, &t.ss, targets->priority, &h_dns) != 0) {
            DBG("Unresolvable destination %.*s:%u/%.*s", it->host.len, it->host.s, it->port, it->trsp.len, it->trsp.s);
            return RESOLVING_ERROR_CODE;
        }

        sips_scheme = !lower_cmp_n(it->scheme, "sips");

        do {
            t.resolve(it->trsp, sips_scheme);
            targets->dest_list.push_back(t);
        } while (h_dns.next_ip(&t.ss, Dualstack) > 0);
    } // for it: dest_list

    return 0;
}

void _resolver::clear_cache()
{
    int removed = 0;
    for (unsigned long i = 0; i < cache.get_size(); i++) {
        dns_bucket *bucket = cache.get_bucket(i);
        bucket->lock();
        auto it = bucket->elmts.begin();
        while (it != bucket->elmts.end()) {
            dns_entry *dns_e = static_cast<dns_entry *>(it->second);
            it               = bucket->elmts.erase(it);
            dec_ref(dns_e);
            removed++;
        }
        bucket->unlock();
    }
    DBG("resolver::clear_cache() %d entries removed", removed);
}

unsigned int _resolver::count_cache()
{
    unsigned int size = 0;
    for (unsigned long i = 0; i < cache.get_size(); i++) {
        dns_bucket *bucket = cache.get_bucket(i);
        bucket->lock();
        bucket->dump([&size](const string &, dns_entry *) { size++; });
        bucket->unlock();
    }
    return size;
}

void _resolver::dump_cache(AmArg &ret)
{
    for (unsigned long i = 0; i < cache.get_size(); i++) {
        dns_bucket *bucket = cache.get_bucket(i);
        bucket->lock();
        AmArg &entries = ret["entries"];
        bucket->dump([&entries](const string &name, dns_entry *entry) {
            AmArg data;
            data["data"]   = entry->to_str();
            data["name"]   = name;
            data["expire"] = (long long)(entry->expire - wheeltimer::instance()->unix_clock.get());
            entries.push(data);
        });
        bucket->unlock();
    }
}

void _resolver::run()
{
    struct timespec tick, rem;
    tick.tv_sec  = (DNS_CACHE_SINGLE_CYCLE / 1000000L);
    tick.tv_nsec = (DNS_CACHE_SINGLE_CYCLE - (tick.tv_sec) * 1000000L) * 1000L;

    unsigned long i = 0;
    setThreadName("resolver");

    while (!b_stop.get()) {
        nanosleep(&tick, &rem);

        u_int64_t   now    = wheeltimer::instance()->unix_clock.get();
        dns_bucket *bucket = cache.get_bucket(i);

        bucket->lock();

        for (dns_bucket::value_map::iterator it = bucket->elmts.begin(); it != bucket->elmts.end(); ++it) {
            dns_entry *dns_e = static_cast<dns_entry *>(it->second);
            if (now >= it->second->expire) {
                dns_bucket::value_map::iterator tmp_it        = it;
                bool                            end_of_bucket = (++it == bucket->elmts.end());

                DBG3("DNS record expired (%p) '%s' -> %s", static_cast<void *>(dns_e), tmp_it->first.c_str(),
                     dns_e->to_str().c_str());

                bucket->elmts.erase(tmp_it);
                dec_ref(dns_e);

                if (end_of_bucket)
                    break;
            } else {
                // DBG("######### record %p expires in %li seconds ##########",
                //     dns_e,it->second->expire-tv_now.tv_sec);
            }
        }

        bucket->unlock();

        if (++i >= cache.get_size())
            i = 0;
    }

    DBG("resolver thread finished");
}

void dns_handle::dump(AmArg &ret)
{
    if (srv_e) {
        ret["type"] = "srv";
        // ret["port"] = port;
        AmArg                    &entries = ret["entries"];
        vector<dns_base_entry *> &v       = srv_e->ip_vec;
        for (size_t i = 0; i < v.size(); i++) {
            entries.push(AmArg());
            AmArg     &a  = entries.back();
            srv_entry *e  = dynamic_cast<srv_entry *>(v[i]);
            a["priority"] = e->p;
            a["weight"]   = e->w;
            a["port"]     = e->port;
            a["target"]   = e->target;
        }
    } else if (ip_e) { // ip_e
        char             host[NI_MAXHOST] = "";
        sockaddr_storage ss;
        ret["type"]                       = "ip";
        AmArg                    &entries = ret["entries"];
        vector<dns_base_entry *> &v       = ip_e->ip_vec;
        for (size_t i = 0; i < v.size(); i++) {
            entries.push(AmArg());
            AmArg    &a = entries.back();
            ip_entry *e = dynamic_cast<ip_entry *>(v[i]);
            e->to_sa(&ss);
            a["addr"] = am_inet_ntop_sip(&ss, host, NI_MAXHOST);
        }
    } else {
        ret["type"] = "unknown";
    }
}

void dns_handle::dumpIps(AmArg &ret, dns_priority priority)
{
    sockaddr_storage remote_ip;
    std::string      addr;
    prepare(ip_e, priority);
    AmArg &entries = ret["entries"];
    while (next_ip(&remote_ip, priority) > 0) {
        addr = get_addr_str_sip(&remote_ip);
        entries.push(AmArg());
        AmArg &a  = entries.back();
        a["addr"] = addr.c_str();
    }
}

void dns_handle::prepare(dns_entry *e, dns_priority priority)
{
    if (!e)
        return;
    if (e->get_type() == dns_r_ip) {
        if (ip_e)
            dec_ref(ip_e);
        ip_e = dynamic_cast<dns_ip_entry *>(e);
        inc_ref(ip_e);
        ip_n = 0;
        ip_indexes.clear();
        ip_e->sort_by_priority(this, priority);
    } else if (e->get_type() == dns_r_srv) {
        if (srv_e)
            dec_ref(srv_e);
        srv_e = dynamic_cast<dns_srv_entry *>(e);
        inc_ref(srv_e);
        srv_n    = 0;
        srv_used = 0;
        ip_n     = -1;
    }
}

void dns_handle::reset(dns_rr_type type)
{
    if (type == dns_r_ip && ip_e) {
        dec_ref(ip_e);
        ip_e = nullptr;
        ip_n = -1;
    }
    if (type == dns_r_srv && srv_e) {
        dec_ref(srv_e);
        srv_e    = nullptr;
        srv_n    = 0;
        srv_used = 0;
    }
}


/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */
