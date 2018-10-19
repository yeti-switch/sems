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

using std::pair;
using std::make_pair;
using std::list;

#include "log.h"

#define DEFAULT_SIP_PORT 5060
#define DEFAULT_RTSP_PORT 554

#define ALIAS_RESOLVING_LIMIT 5

// Maximum number of SRV entries
// within a cache entry
//
// (the limit is the # bits in dns_handle::srv_used)
#define MAX_SRV_RR (sizeof(unsigned int)*8)

/* in seconds */
#define DNS_CACHE_CYCLE 10L

/* avoids issues with racing on DNS cache operations
 * and with DNS responses with entries TTL 0 */
#define DNS_CACHE_EXPIRE_DELAY 2

/* in us */
#define DNS_CACHE_SINGLE_CYCLE \
  ((DNS_CACHE_CYCLE*1000000L)/DNS_CACHE_SIZE)

const char* dns_priority_str(const dns_priority priority)
{
#define dpts(e) case e: return #e;
    switch(priority) {
        dpts(IPv4_only)
        dpts(IPv6_only)
        dpts(Dualstack)
        dpts(IPv4_pref)
        dpts(IPv6_pref)
    };
    return "";
}

dns_priority string_to_priority(const string& priority)
{
#define stdp(e) if(priority == #e) return e;
    stdp(IPv4_only)
    stdp(IPv6_only)
    stdp(Dualstack)
    stdp(IPv4_pref)
    stdp(IPv6_pref)
    return IPv4_only;
}

struct srv_entry
    : public dns_base_entry
{
    unsigned short   p;
    unsigned short   w;

    unsigned short port;
    string       target;

    virtual string to_str();
};

struct cname_entry
    : public dns_base_entry
{
    string       target;
    virtual string to_str() { return target; }
};

int dns_ip_entry::next_ip(dns_handle* h, sockaddr_storage* sa, dns_priority priority)
{
    if(h->ip_e != this){
        h->prepare(this, priority);
    }
    
    int& index = h->ip_n;
    if((index < 0) || (index >= (int)h->ip_indexes.size()))
	return 0;

    int ip_index = h->ip_indexes[h->ip_n];
    if((ip_index < 0) || (ip_index >= (int)ip_vec.size()))
	return -1;
    
    //copy address
    ((ip_entry*)ip_vec[ip_index])->to_sa(sa);
    index++;
    
    // reached the end?
    if(index >= (int)h->ip_indexes.size()) {
	index = -1;
    }
    
    return 1;
}

void dns_ip_entry::sort_by_priority(dns_handle* handle, dns_priority priority)
{
    struct ip_index {
        ip_index(const ip_index& ip) {
            operator = (ip);
        }
        ip_index(address_type type_, unsigned int index_, dns_priority priority_)
        : type(type_), index(index_), priority(priority_){}

        void operator = (const ip_index& ip) {
            index = ip.index;
            type = ip.type;
            priority = ip.priority;
        }

        bool operator == (const ip_index& ip) {
            return ip.index == index && ip.type == type;
        }

        bool operator < (const ip_index& ip) const{
            if((priority == IPv4_pref && type == IPv4 && ip.type == IPv6) ||
               (priority == IPv6_pref && type == IPv6 && ip.type == IPv4)) {
                return true;
            }
            if((priority == IPv4_pref && type == IPv6 && ip.type == IPv4) ||
               (priority == IPv6_pref && type == IPv4 && ip.type == IPv6)) {
                return false;
            }
            if(type == ip.type) {
                return index < ip.index;
            }

            return type < ip.type;
        }
        address_type type;
        unsigned int index;
        dns_priority priority;
    };
    map<ip_index, unsigned int> indexes;
    int index = 0;
    for(auto& ip : ip_vec) {
        ip_entry* entry = (ip_entry*)ip;
        indexes.insert(std::make_pair(ip_index(entry->type, index, priority), index));
        index++;
    }

    for(auto& ip_index_ : indexes) {
        if((ip_index_.first.type == IPv4 && priority == IPv6_only) ||
           (ip_index_.first.type == IPv6 && priority == IPv4_only)) {
	    continue;
	}

        handle->ip_indexes.push_back(ip_index_.second);
    }
	}
	
dns_base_entry* dns_ip_entry::get_rr(dns_record* rr, u_char* begin, u_char* end)
{
    ip_entry* new_ip = new ip_entry();
    if(rr->type == ns_t_a) {
        DBG("A: TTL=%i %s %i.%i.%i.%i\n",
        ns_rr_ttl(*rr),
        ns_rr_name(*rr),
        ns_rr_rdata(*rr)[0],
        ns_rr_rdata(*rr)[1],
        ns_rr_rdata(*rr)[2],
        ns_rr_rdata(*rr)[3]);

        new_ip->type = IPv4;
        memcpy(&(new_ip->addr), ns_rr_rdata(*rr), sizeof(in_addr));
    } else if(rr->type == ns_t_aaaa) {
        DBG("AAAA: TTL=%i %s %x:%x:%x:%x:%x:%x:%x:%x\n",
        ns_rr_ttl(*rr),
        ns_rr_name(*rr),
        htons(*(short*)(ns_rr_rdata(*rr))),
        htons(*(short*)(ns_rr_rdata(*rr) + 2)),
        htons(*(short*)(ns_rr_rdata(*rr) + 4)),
        htons(*(short*)(ns_rr_rdata(*rr) + 6)),
        htons(*(short*)(ns_rr_rdata(*rr) + 8)),
        htons(*(short*)(ns_rr_rdata(*rr) + 10)),
        htons(*(short*)(ns_rr_rdata(*rr) + 12)),
        htons(*(short*)(ns_rr_rdata(*rr) + 14)));

        new_ip->type = IPv6;
        memcpy(&(new_ip->addr6), ns_rr_rdata(*rr), sizeof(in6_addr));
    } else {
        return NULL;
	}

    return new_ip;
	}

bool dns_ip_entry::union_rr(const vector<dns_base_entry*>& entries)
{
    for(auto& entry : entries) {
        auto it = find_if(ip_vec.begin(), ip_vec.end(), [entry](const dns_base_entry* entry_)
        {
            ip_entry* ipentrynew = (ip_entry*)entry;
            ip_entry* ipentryold = (ip_entry*)entry_;

            return *ipentrynew == *ipentryold;
        });
        if(it == ip_vec.end()) {
            ip_entry* ipentrynew = (ip_entry*)entry;
            ip_vec.push_back(ipentrynew->clone());
        }
    }

    return true;
}

static bool srv_less(const dns_base_entry* le, const dns_base_entry* re)
{
    const srv_entry* l_srv = (const srv_entry*)le;
    const srv_entry* r_srv = (const srv_entry*)re;

    if(l_srv->p != r_srv->p)
	return l_srv->p < r_srv->p;
    else
	return l_srv->w < r_srv->w;
};

class dns_srv_entry
    : public dns_entry
{
    unsigned short default_service_port;
public:
	dns_srv_entry(unsigned short default_service_port)
		: default_service_port(default_service_port),
		  dns_entry(dns_r_srv)
    {}

    void init(){
	stable_sort(ip_vec.begin(),ip_vec.end(),srv_less);
    }

    dns_base_entry* get_rr(dns_record* rr, u_char* begin, u_char* end);

    int next_ip(dns_handle* h, sockaddr_storage* sa, dns_priority priority)
    {
        int& index = h->srv_n;
        if(index >= (int)ip_vec.size()) return 0;

        if(h->srv_e != this) {
            h->prepare(this, priority);
        } else if(h->ip_n != -1) {
            if(h->port) {
                //DBG("setting port to %i",ntohs(h->port));
                ((sockaddr_in*)sa)->sin_port = h->port;
            } else {
                //DBG("setting port to %i",default_service_port);
                ((sockaddr_in*)sa)->sin_port = htons(default_service_port);
            }
            return h->ip_e->next_ip(h,sa, priority);
        }

        if(index < 0)
        {
            return -1;
        }

        // reset IP record
        h->reset(dns_r_ip);

        list<pair<unsigned int,int> > srv_lst;
        int i = index;

        // fetch current priority
        unsigned short p = ((srv_entry*)ip_vec[i])->p;
        unsigned int w_sum = 0;

        // and fetch records with same priority
        // which have not been chosen yet
        int srv_lst_size=0;
        unsigned int used_mask=(1<<i);

        while(p == ((srv_entry*)ip_vec[i])->p) {

            if(!(used_mask & h->srv_used)) {
                w_sum += ((srv_entry*)ip_vec[i])->w;
                srv_lst.push_back(std::make_pair(w_sum,i));
                srv_lst_size++;
            }

            if((++i >= (int)ip_vec.size()) ||
               (i >= (int)MAX_SRV_RR))
            {
                break;
            }

            used_mask = used_mask << 1;
        }

        srv_entry* e=NULL;
        if((srv_lst_size > 1) && w_sum) {
            // multiple records: apply weigthed load balancing
            // - remember the entries which have already been used
            unsigned int r = random() % (w_sum+1);
            list<pair<unsigned int,int> >::iterator srv_lst_it = srv_lst.begin();
            while(srv_lst_it != srv_lst.end()) {
                if(srv_lst_it->first >= r) {
                    h->srv_used |= (1<<(srv_lst_it->second));
                    e = (srv_entry*)ip_vec[srv_lst_it->second];
                    break;
                }
                ++srv_lst_it;
            }
            // will only happen if the algorithm
            // is broken
            if(!e)
                return -1;
        } else if(srv_lst_size == 0) {
            //empty srv_lst
            return -1;
        } else {
            // single record or all weights == 0
            e = (srv_entry*)ip_vec[srv_lst.begin()->second];
            if( (i<(int)ip_vec.size()) && (i<(int)MAX_SRV_RR)) {
                index = i;
            } else if(!w_sum){
                index++;
            } else {
                index = -1;
            }
        }

        //TODO: find a solution for IPv6
        h->port = htons(e->port);
        if(h->port) {
            //DBG("setting port to %i",e->port);
            ((sockaddr_in*)sa)->sin_port = h->port;
        } else {
            //DBG("setting port to 5060");
            ((sockaddr_in*)sa)->sin_port = htons(5060);
        }

        // check if name is an IP address
        if(am_inet_pton(e->target.c_str(),sa) == 1) {
            DBG("target '%s' is an IP address srv_port: %i",
                e->target.c_str(),
                ntohs(((sockaddr_in*)sa)->sin_port));
            h->ip_n = -1; // flag end of IP list
            return 1;
        }

        DBG("target '%s' must be resolved first. srv_port: %i",
            e->target.c_str(),
            ntohs(((sockaddr_in*)sa)->sin_port));
        return resolver::instance()->resolve_name(e->target.c_str(),h,sa,priority);
    }
};

class dns_cname_entry
  : public dns_entry
{
    string target;
  public:
    dns_cname_entry()
     : dns_entry(dns_r_cname)
    { }
    void init() {}
    dns_base_entry* get_rr(dns_record* rr, u_char* begin, u_char* end);
    int next_ip(dns_handle* h, sockaddr_storage* sa, const dns_priority priority) { return -1; }
    dns_entry *resolve_alias(dns_cache &cache, const dns_priority priority, dns_rr_type tt_type);
};

dns_entry::dns_entry(dns_rr_type type)
    : dns_base_entry(),
      type(type)
{
}

dns_entry::~dns_entry()
{
    DBG("dns_entry::~dns_entry(): %s",to_str().c_str());
    for(vector<dns_base_entry*>::iterator it = ip_vec.begin();
	it != ip_vec.end(); ++it) {

	delete *it;
    }
}

dns_entry* dns_entry::make_entry(ns_type t, unsigned short srv_port)
{
    switch(t){
    case ns_t_srv:
	return new dns_srv_entry(srv_port);
	case ns_t_cname:
	return new dns_cname_entry();
    case ns_t_a:
    case ns_t_aaaa:
	return new dns_ip_entry();
    case ns_t_naptr:
	return new dns_naptr_entry();
    default:
	return NULL;
    }
}

void dns_entry::add_rr(dns_record* rr, u_char* begin, u_char* end, long now)
{
    dns_base_entry* e = get_rr(rr,begin,end);
    if(!e) return;

    e->expire = rr->ttl + now + DNS_CACHE_EXPIRE_DELAY;
    if(expire < e->expire)
	expire = e->expire;

    ip_vec.push_back(e);
}

string dns_entry::to_str()
{
    string res;

    for(vector<dns_base_entry*>::iterator it = ip_vec.begin();
	it != ip_vec.end(); it++) {
	
	if(it != ip_vec.begin())
	    res += ", ";

	res += (*it)->to_str();
    }

    return "[" + res + "]";
}

dns_bucket::dns_bucket(unsigned long id) 
  : dns_bucket_base(id) 
{
}

bool dns_bucket::insert(const string& name, dns_entry* e)
{
    if(!e) return false;

    lock();
    if(!(elmts.insert(std::make_pair(name,e)).second)){
	// if insertion failed
	unlock();
	return false;
    }

    inc_ref(e);
    unlock();

    return true;
}

bool dns_bucket::remove(const string& name)
{
    lock();
    value_map::iterator it = elmts.find(name);
    if(it != elmts.end()){
	
	dns_entry* e = it->second;
	elmts.erase(it);

	dec_ref(e);
	unlock();
	
	return true;
    }

    unlock();
    return false;
}


dns_entry* dns_bucket::find(const string& name)
{
    lock();
    value_map::iterator it = elmts.find(name);
    if(it == elmts.end()){
	unlock();
	return NULL;
    }

    dns_entry* e = it->second;

    u_int64_t now = wheeltimer::instance()->unix_clock.get();
    if(now >= e->expire){
	elmts.erase(it);
	dec_ref(e);
	unlock();
	return NULL;
    }

    inc_ref(e);
    unlock();
    return e;
}

static void dns_error(int error, const char* domain, dns_rr_type type)
{
    switch(error){
        case HOST_NOT_FOUND:
          DBG("%s/%d: Unknown domain", domain, type);
          break;
        case NO_DATA:
          DBG("%s/%d: No records", domain, type);
          break;
        case TRY_AGAIN:
          DBG("%s/%d: No response for query (try again)",domain, type);
          break;
        case NO_RECOVERY:
          ERROR("%s/%d: Non recoverable error (FORMERR, REFUSED, NOTIMP)",
              domain, type);
        default:
          ERROR("%s/%d: Unexpected error. res_search returned: %d",
                domain,type,error);
          break;
    }
}

bool ip_entry::operator == (const ip_entry& entry)
{
    if(type != entry.type)
        return false;
    if(type == IPv4) {
        return memcmp(&addr,&entry.addr, sizeof(in_addr)) == 0;
    } else if(type == IPv6) {
        return memcmp(&addr6,&entry.addr6, sizeof(in6_addr)) == 0;
    }
    return false;
}

ip_entry* ip_entry::clone()
{
    ip_entry* entry = new ip_entry();
    entry->type = type;
    if(type == IPv4) {
        memcpy(&entry->addr,&addr, sizeof(in_addr));
    } else if(type == IPv6) {
        memcpy(&entry->addr6,&addr6, sizeof(in6_addr));
    }
    return entry;
}

void ip_entry::to_sa(sockaddr_storage* sa)
{
    //DBG("copying ip_entry...");
    switch(type){
    case IPv4:
	{
	    sockaddr_in* sa_in = (sockaddr_in*)sa;
	    sa_in->sin_family = AF_INET;
	    memcpy(&(sa_in->sin_addr),&addr,sizeof(in_addr));
	} break;
    case IPv6:
	{
	    sockaddr_in6* sa_in6 = (sockaddr_in6*)sa;
	    sa_in6->sin6_family = AF_INET6;
	    memcpy(&(sa_in6->sin6_addr),&addr6,sizeof(in6_addr));
	} break;
    default:
	break;
    }
}

string ip_entry::to_str()
{
    if(type == IPv4) {
	u_char* cp = (u_char*)&addr;
	return int2str(cp[0]) + 
	    "." + int2str(cp[1]) + 
	    "." + int2str(cp[2]) + 
	    "." + int2str(cp[3]);
    }
    else {
	u_short* cp = (u_short*)&addr;
	return int2hexstr(htons(cp[0])) +
	    ":" + int2hexstr(htons(cp[1])) +
	    ":" + int2hexstr(htons(cp[2])) +
	    ":" + int2hexstr(htons(cp[3])) +
	    ":" + int2hexstr(htons(cp[4])) +
	    ":" + int2hexstr(htons(cp[5])) +
	    ":" + int2hexstr(htons(cp[6]));
    }
}


void ip_port_entry::to_sa(sockaddr_storage* sa)
{
    DBG("copying ip_port_entry...");
    switch(type){
    case IPv4:
	{
	    sockaddr_in* sa_in = (sockaddr_in*)sa;
	    sa_in->sin_family = AF_INET;
	    memcpy(&(sa_in->sin_addr),&addr,sizeof(in_addr));
	    if(port) {
		sa_in->sin_port = htons(port);
	    }
	    else {
		sa_in->sin_port = htons(5060);
	    }
	} break;
    case IPv6:
	{
	    sockaddr_in6* sa_in6 = (sockaddr_in6*)sa;
	    sa_in6->sin6_family = AF_INET6;
	    memcpy(&(sa_in6->sin6_addr),&addr6,sizeof(in6_addr));
	    sa_in6->sin6_port = htons(port);
	} break;
    default:
	break;
    }
}

string ip_port_entry::to_str()
{
    return ip_entry::to_str() + ":" + int2str(port);
}

dns_base_entry* dns_srv_entry::get_rr(dns_record* rr, u_char* begin, u_char* end)
{
    if(rr->type != ns_t_srv)
	return NULL;

    u_char name_buf[NS_MAXDNAME];
    const u_char * rdata = ns_rr_rdata(*rr);
	
    /* Expand the target's name */
    u_char* p = (u_char*)rdata+6;
    if (dns_expand_name(&p,begin,end,
    			   name_buf,         /* Result                */
    			   NS_MAXDNAME)      /* Size of result buffer */
    	< 0) {    /* Negative: error       */
	
		DBG("dns_expand_name failed\n");
    	return NULL;
    }
    
    DBG("SRV: TTL=%i %s P=<%i> W=<%i> P=<%i> T=<%s>\n",
    	ns_rr_ttl(*rr),
    	ns_rr_name(*rr),
    	dns_get_16(rdata),
    	dns_get_16(rdata+2),
    	dns_get_16(rdata+4),
    	name_buf);
    
    srv_entry* srv_r = new srv_entry();
    srv_r->p = dns_get_16(rdata);
    srv_r->w = dns_get_16(rdata+2);
    srv_r->port = dns_get_16(rdata+4);
    srv_r->target = (const char*)name_buf;

    return srv_r;
}

string srv_entry::to_str()
{
    return target + ":" + int2str(port)
	+ "/" + int2str(p)
	+ "/" + int2str(w);
};

dns_base_entry* dns_cname_entry::get_rr(dns_record* rr, u_char* begin, u_char* end)
{
    if(rr->type != ns_t_cname)
        return NULL;

    u_char name_buf[NS_MAXDNAME];
    const u_char * rdata = ns_rr_rdata(*rr);

    /* Expand the target's name */
    u_char* p = (u_char*)rdata;
    if (dns_expand_name(&p,begin,end,
                   name_buf,         /* Result                */
                   NS_MAXDNAME)      /* Size of result buffer */
        < 0) {    /* Negative: error       */

        ERROR("dns_expand_name failed\n");
        return NULL;
    }

    DBG("CNAME: TTL=%i %s T=<%s>\n",
        ns_rr_ttl(*rr),
        ns_rr_name(*rr),
        name_buf);

    cname_entry* cname_r = new cname_entry();
    cname_r->target = (const char*)name_buf;

    return cname_r;
}

dns_entry *dns_cname_entry::resolve_alias(dns_cache &cache, const dns_priority priority, dns_rr_type rr_type)
{
    dns_bucket *b;

    if(ip_vec.empty()) {
        DBG("empty cname entry");
        return nullptr;
    }
    string &target = ((cname_entry *)ip_vec[0])->target;
    DBG("cname entry points to target: %s."
        " search for appropriate entry in the local cache",
        target.c_str());
    b = cache.get_bucket(hashlittle(target.data(),target.size(),0));
    dns_entry *e = b->find(target);
    if(e) {
        DBG("return entry %s found in the local cache",
            e->to_str().c_str());
        return e;
    }

    DBG("entry for target %s is not found in the local cache. try to resolve it",
        target.c_str());
    //not found in cache. resolve target
    dns_entry_map entry_map;
    if((priority != IPv6_only && resolver::instance()->query_dns(target.c_str(),rr_type, IPv4) < 0) ||
       (priority != IPv4_only && resolver::instance()->query_dns(target.c_str(),rr_type, IPv6) < 0)) {
        return nullptr;
    }

    //final lookup in the cache
    e = b->find(target);
    if(e) {
        DBG("return resolved entry %s from the cache",
            e->to_str().c_str());
    }
    return e;
}

struct dns_search_h
{
    dns_entry_map entry_map;
    uint64_t      now;

    dns_search_h() {
	now = wheeltimer::instance()->unix_clock.get();
    }
};

int rr_to_dns_entry(dns_record* rr, dns_section_type t,
		    u_char* begin, u_char* end, void* data)
{
    // only answer and additional sections
    if(t != dns_s_an && t != dns_s_ar)
	return 0;

    dns_search_h* h = (dns_search_h*)data;
    string name = ns_rr_name(*rr);

    dns_entry* dns_e = NULL;
    dns_entry_map::iterator it = h->entry_map.find(name);

    if(it == h->entry_map.end()) {
	dns_e = dns_entry::make_entry((ns_type)rr->type);
	if(!dns_e) {
	    // unsupported record type
	    return 0;
	}
	h->entry_map.insert(name,dns_e);
    }
    else {
	dns_e = it->second;
    }

    dns_e->add_rr(rr,begin,end,h->now);
    return 0;
}

dns_handle::dns_handle() 
  : srv_e(0), srv_n(0), ip_e(0), ip_n(0) 
{}

dns_handle::dns_handle(const dns_handle& h)
{
    *this = h;
}

dns_handle::~dns_handle() 
{ 
    if(ip_e) 
	dec_ref(ip_e); 

    if(srv_e) 
	dec_ref(srv_e); 
}

bool dns_handle::valid() 
{ 
    return (ip_e);
}

bool dns_handle::eoip()  
{ 
    if(srv_e)
	return (srv_n == -1) && (ip_n == -1);
    else
	return (ip_n == -1);
}

int dns_handle::next_ip(sockaddr_storage* sa, dns_priority priority)
{
    if(!valid() || eoip()) return -1;

    if(srv_e)
	return srv_e->next_ip(this,sa,priority);
    else
	return ip_e->next_ip(this,sa,priority);
}

const dns_handle& dns_handle::operator = (const dns_handle& rh)
{
    memcpy(this,(const void*)&rh,sizeof(dns_handle));
    
    if(srv_e)
	inc_ref(srv_e);
    
    if(ip_e)
	inc_ref(ip_e);
    
    return *this;
}

static bool naptr_less(const dns_base_entry* le, const dns_base_entry* re)
{
    const naptr_record* l_naptr = (const naptr_record*)le;
    const naptr_record* r_naptr = (const naptr_record*)re;

    if(l_naptr->order != r_naptr->order)
	return l_naptr->order < r_naptr->order;
    else
	return l_naptr->pref < r_naptr->pref;
}

void dns_naptr_entry::init()
{
    stable_sort(ip_vec.begin(),ip_vec.end(),naptr_less);
}

dns_base_entry* dns_naptr_entry::get_rr(dns_record* rr, u_char* begin, u_char* end)
{
    enum NAPTR_FieldIndex {
	NAPTR_Flags       = 0,
	NAPTR_Services    = 1,
	NAPTR_Regexp      = 2,
	NAPTR_Replacement = 3,
	NAPTR_Fields
    };

    if(rr->type != ns_t_naptr)
	return NULL;

    const u_char * rdata = ns_rr_rdata(*rr);

    unsigned short order = dns_get_16(rdata);
    rdata += 2;

    unsigned short pref = dns_get_16(rdata);
    rdata += 2;

    cstring fields[NAPTR_Fields];

    for(int i=0; i < NAPTR_Fields; i++) {

	if(rdata > end) {
	    ERROR("corrupted NAPTR record!!\n");
	    return NULL;
	}

	fields[i].len = *(rdata++);
	fields[i].s = (const char*)rdata;

	rdata += fields[i].len;
    }

    printf("ENUM: TTL=%i P=<%i> W=<%i>"
	   " FL=<%.*s> S=<%.*s>"
	   " REG=<%.*s> REPL=<%.*s>\n",
	   ns_rr_ttl(*rr),
	   order, pref,
	   fields[NAPTR_Flags].len,       fields[NAPTR_Flags].s,
	   fields[NAPTR_Services].len,    fields[NAPTR_Services].s,
	   fields[NAPTR_Regexp].len,      fields[NAPTR_Regexp].s,
	   fields[NAPTR_Replacement].len, fields[NAPTR_Replacement].s);

    naptr_record* naptr_r = new naptr_record();
    naptr_r->order = order;
    naptr_r->pref  = pref;
    naptr_r->flags = c2stlstr(fields[NAPTR_Flags]);
    naptr_r->services = c2stlstr(fields[NAPTR_Services]);
    naptr_r->regexp = c2stlstr(fields[NAPTR_Regexp]);
    naptr_r->replace = c2stlstr(fields[NAPTR_Replacement]);

    return naptr_r;
}

sip_target::sip_target() {
    bzero(&ss, sizeof(sockaddr_storage));
}

sip_target::sip_target(const sip_target& target)
{
    *this = target;
}

const sip_target& sip_target::operator = (const sip_target& target)
{
    memcpy(&ss,&target.ss,sizeof(sockaddr_storage));
    memcpy(trsp,target.trsp,SIP_TRSP_SIZE_MAX+1);
    return target;
}

void sip_target::clear()
{
    memset(&ss,0,sizeof(sockaddr_storage));
    memset(trsp,'\0',SIP_TRSP_SIZE_MAX+1);
}

sip_target_set::sip_target_set(dns_priority priority_)
    : dest_list(),
      dest_list_it(dest_list.begin()),
      priority(priority_)
{}

void sip_target_set::reset_iterator()
{
    dest_list_it = dest_list.begin();
}

bool sip_target_set::has_next()
{
    return dest_list_it != dest_list.end();
}

int sip_target_set::get_next(sockaddr_storage* ss, trsp_socket::socket_transport& next_trsp,
			     unsigned int flags)
{
    do {
        if(!has_next())
            return -1;

        static cstring trsp_udp_name("udp");
        static cstring trsp_tcp_name("tcp");

        sip_target& t = *dest_list_it;
        memcpy(ss,&t.ss,sizeof(sockaddr_storage));

        //TODO: replace with bitmap for protocols combination
        if(0==strncasecmp(t.trsp, trsp_udp_name.s, trsp_udp_name.len)) {
            //UDP
            switch(ss->ss_family) {
            case AF_INET:
                next_trsp = trsp_socket::udp_ipv4;
                break;
            case AF_INET6:
                next_trsp = trsp_socket::udp_ipv6;
                break;
            default:
                //unexpected address family for UDP transport
                next_trsp = trsp_socket::tr_invalid;
            }
        } else if(0==strncasecmp(t.trsp, trsp_tcp_name.s, trsp_tcp_name.len)) {
            //TCP
            switch(ss->ss_family) {
            case AF_INET:
                next_trsp = trsp_socket::tcp_ipv4;
                break;
            case AF_INET6:
                next_trsp = trsp_socket::tcp_ipv6;
                break;
            default:
                //unexpected address family for TCP transport
                next_trsp = trsp_socket::tr_invalid;
            }
        } else {
            //unknown transport name
            next_trsp = trsp_socket::tr_invalid;
        }

        next();

        // set default transport to UDP
        if(!next_trsp) {
            if(ss->ss_family == AF_INET) {
                next_trsp = trsp_socket::udp_ipv4;
            } else {
                next_trsp = trsp_socket::udp_ipv6;
            }
        }

    } while(!(flags & TR_FLAG_DISABLE_BL) &&
            tr_blacklist::instance()->exist(ss));

    return 0;
}

bool sip_target_set::next()
{
    dest_list_it++;
    return has_next();
}

void sip_target_set::prev()
{
    if(dest_list_it!=dest_list.begin())
        dest_list_it--;
}

void sip_target_set::debug()
{
    DBG("target list:");

    for(list<sip_target>::iterator it = dest_list.begin();
        it != dest_list.end(); it++)
    {
        DBG("\t%c %s:%u/%s",
            it == dest_list_it ? '>' : ' ',
            am_inet_ntop(&it->ss).c_str(),
            am_get_port(&it->ss),it->trsp);
    }
}

sip_target_set::sip_target_set(const sip_target_set& other) {
    dest_list = other.dest_list;
    dest_list_it = std::next(dest_list.begin(),
        std::distance(other.dest_list.begin(),
        (list<sip_target>::const_iterator)other.dest_list_it));
    priority = other.priority;
}

dns_entry_map::dns_entry_map()
    : map<string,dns_entry*>()
{
}

dns_entry_map::~dns_entry_map()
{
    for(iterator it = begin(); it != end(); ++it) {
	dec_ref(it->second);
    }
}

std::pair<dns_entry_map::iterator, bool>
dns_entry_map::insert(const dns_entry_map::value_type& x)
{
    return dns_entry_map_base::insert(x);
}

bool dns_entry_map::insert(const string& key, dns_entry* e)
{
    std::pair<iterator, bool> res = emplace(key,e);
    if(res.second) {
        inc_ref(e);
        return true;
    }
    return false;
}

dns_entry* dns_entry_map::fetch(const key_type& key)
{
    iterator it = find(key);
    if(it != end())
	return it->second;
    return NULL;
}

bool _resolver::disable_srv = false;

_resolver::_resolver()
    : cache(DNS_CACHE_SIZE)
{
    start();
}

_resolver::~_resolver()
{
    
}

int _resolver::query_dns(const char* name, dns_rr_type rr_type, address_type addr_type)
{
    u_char dns_res[NS_PACKETSZ];

    if(!name) return -1;

    DBG("Querying '%s' (%s)...",name,dns_rr_type_str(rr_type, addr_type));

    int dns_res_len = res_search(name,ns_c_in,dns_rr_type_tons_type(rr_type, addr_type),
				 dns_res,NS_PACKETSZ);
    if(dns_res_len < 0){
        dns_error(h_errno,name,rr_type);
        return 0;
    }

    /*
     * Initialize a handle to this response.  The handle will
     * be used later to extract information from the response.
     */
    dns_search_h h;
    if (dns_msg_parse(dns_res, dns_res_len, rr_to_dns_entry, &h) < 0) {
	DBG("Could not parse DNS reply");
	return -1;
    }

    for(dns_entry_map::iterator it = h.entry_map.begin();
	it != h.entry_map.end(); it++) {

	dns_entry* e = it->second;
	if(!e || e->ip_vec.empty()) continue;

        dns_bucket* b = cache.get_bucket(hashlittle(it->first.c_str(),
                                it->first.length(),0));
        dns_entry* entry = b->find(it->first.c_str());
        if(!entry) {
	e->init();
            if(b->insert(it->first,e)) {
                DBG("new DNS cache entry: '%s' -> %s",
                it->first.c_str(), it->second->to_str().c_str());
            }
        } else if(entry->get_type() == e->get_type()){
            if(entry->union_rr(e->ip_vec)) {
                DBG("unite together new and old DNS cache entries: '%s' -> %s",
                it->first.c_str(), it->second->to_str().c_str());
            } else {
                ERROR("cannot unite together new and old DNS cache entries, '%s' -> %s", it->first.c_str(), it->second->to_str().c_str());
            }
        } else {
            ERROR("insertion new DNS cache entry is failed, '%s' -> %s", it->first.c_str(), it->second->to_str().c_str());
        }
    }

    return 0;
}

int _resolver::resolve_name(const char* name, dns_handle* h, sockaddr_storage* sa, const dns_priority priority, dns_rr_type rr_type)
{
	int ret;

    // already have a valid handle?
    if(h->valid()) {
        if(h->eoip()) return -1;
        ret = h->next_ip(sa, priority);
    }

    if(rr_type == dns_r_ip)
    {
        // first try to detect if 'name' is already an IP address
        ret = am_inet_pton(name,sa);
        if(ret == 1) {
            if((sa->ss_family == AF_INET && priority == IPv6_only) ||
               (sa->ss_family == AF_INET6 && priority == IPv4_only)) {
                ERROR("Invalid argument, name %s not compatable with priority type %s",
                      get_addr_str((sockaddr_storage*)&sa).c_str(), dns_priority_str(priority));
                return -1;
            }
            h->ip_n = -1; // flag end of IP list
            h->srv_n = -1;
            return 0; // 'name' is an IP add
        }
    }

    // name is NOT an IP address -> try a cache look up
    ret = resolve_name_cache(name, h, sa, priority, rr_type);
    if(ret > 0) {
        if((priority == IPv4_pref && sa->ss_family == AF_INET) ||
           (priority == IPv6_pref && sa->ss_family == AF_INET6))
            return ret;
    }

    // no valid IP, query the DNS
    if((priority != IPv6_only && query_dns(name,rr_type, IPv4) < 0) ||
       (priority != IPv4_only && query_dns(name,rr_type, IPv6) < 0)) {
        return -1;
    }

    h->reset(rr_type);
    if((ret = resolve_name_cache(name, h, sa, priority, rr_type)) > 0) {
            return ret;
    }

    return -1;
}

int _resolver::str2ip(const char* name,
		      sockaddr_storage* sa,
		      const address_type types)
{
    if(types & IPv4){
	int ret = inet_pton(AF_INET,name,&((sockaddr_in*)sa)->sin_addr);
	if(ret==1) {
	    ((sockaddr_in*)sa)->sin_family = AF_INET;
	    return 1;
	}
	else if(ret < 0) {
	    ERROR("while trying to detect an IPv4 address '%s': %s",
		  name,strerror(errno));
	    return ret;
	}
    }
    
    if(types & IPv6){
    if( (name[0] == '[') &&
        (name[strlen(name) - 1] == ']') ) {
        ((char*)name)[strlen(name) - 1] = 0;
        name++;
    }
	int ret = inet_pton(AF_INET6,name,&((sockaddr_in6*)sa)->sin6_addr);
	if(ret==1) {
	    ((sockaddr_in6*)sa)->sin6_family = AF_INET6;
	    return 1;
	}
	else if(ret < 0) {
	    ERROR("while trying to detect an IPv6 address '%s': %s",
		  name,strerror(errno));
	    return ret;
	}
    }

    return 0;
}

int _resolver::set_destination_ip(const cstring& next_hop,
				  unsigned short next_port,
				  const cstring& next_trsp,
				  sockaddr_storage* remote_ip,
                  dns_priority priority,
				  dns_handle* h_dns)
{

    string nh = c2stlstr(next_hop);

    DBG("checking whether '%s' is IP address...\n", nh.c_str());
    if (am_inet_pton(nh.c_str(), remote_ip) != 1) {

	// nh does NOT contain a valid IP address
    
	if(!next_port) {
	    // no explicit port specified,
	    // try SRV first
	    if (disable_srv) {
		DBG("no port specified, but DNS SRV disabled (skipping).\n");
	    } else {
		string srv_name = "_sip._";
		if(!next_trsp.len || !lower_cmp_n(next_trsp,"udp")){
		    srv_name += "udp";
		}
		else if(!lower_cmp_n(next_trsp,"tcp")) {
		    srv_name += "tcp";
		}
		else {
		    DBG("unsupported transport: skip SRV lookup");
		    goto no_SRV;
		}

		srv_name += "." + nh;

		DBG("no port specified, looking up SRV '%s'...\n",
		    srv_name.c_str());

		if(!resolver::instance()->resolve_name(srv_name.c_str(),
						       h_dns,remote_ip,
						       priority,dns_r_srv)){
		    return 0;
		}

		DBG("no SRV record for %s",srv_name.c_str());
	    }
	}

    no_SRV:
	memset(remote_ip,0,sizeof(sockaddr_storage));
	int err = resolver::instance()->resolve_name(nh.c_str(),
						     h_dns,remote_ip,
						     priority);
	if(err < 0){
		WARN("Unresolvable Request URI domain <%s>\n",nh.c_str());
	    return -478;
	}
    }
    else {
	am_set_port(remote_ip,next_port);
    }

    if(!am_get_port(remote_ip)) {
	if(!next_port) next_port = 5060;
	am_set_port(remote_ip,next_port);
    }

    DBG("set destination to %s:%u\n",
	nh.c_str(), am_get_port(remote_ip));
    
    return 0;
}

int _resolver::resolve_name_cache(const char* name,
                                dns_handle* h,
                                sockaddr_storage* sa,
                                const dns_priority priority,
                                dns_rr_type t)
{
    int ret, limit;

    dns_bucket* b = cache.get_bucket(hashlittle(name,strlen(name),0));
    dns_entry* e = b->find(name);

    // first attempt to get a valid IP
    // (from the cache)
    if(e){
        if(dns_entry *re = e->resolve_alias(cache, priority, t)) {
            dec_ref(e);
            e = re;
            limit = ALIAS_RESOLVING_LIMIT;
            while(e) {
                if(!limit) {
                    DBG("recursive resolving chain limit(%d) reached "
                        "for root entry with target: <%s>",
                        ALIAS_RESOLVING_LIMIT,e->to_str().c_str());
                    dec_ref(e);
                    return -1;
                }
                limit--;
                if(nullptr!=(re = e->resolve_alias(cache, priority, t))) {
                    dec_ref(e);
                    e = re;
                    continue;
                }
                break;
            }

        }
        if(e->get_type() != t) {
            DBG("resolved to %s but it has different type %s (priority %s). ignore it",
            e->to_str().c_str(),dns_rr_type_str(e->get_type(), IPnone),dns_priority_str(priority));
            dec_ref(e);
            return -1;
        }
        ret = e->next_ip(h, sa, priority);
        dec_ref(e);
        return ret;
    }
    return 0;
}

int _resolver::resolve_targets(const list<sip_destination>& dest_list,
			       sip_target_set* targets)
{
    for(list<sip_destination>::const_iterator it = dest_list.begin();
	it != dest_list.end(); it++) {
	
	sip_target t;
	dns_handle h_dns;

	DBG("sip_destination: %.*s:%u/%.*s",
	    it->host.len,it->host.s,
	    it->port,
	    it->trsp.len,it->trsp.s);

	if(set_destination_ip(it->host,it->port,it->trsp,&t.ss, targets->priority,&h_dns) != 0) {
		WARN("Unresolvable destination %.*s:%u/%.*s",
			  it->host.len,it->host.s,
			  it->port,
			  it->trsp.len,it->trsp.s);
	    return -478;
	}
	if(it->trsp.len && (it->trsp.len <= SIP_TRSP_SIZE_MAX)) {
	    memcpy(t.trsp,it->trsp.s,it->trsp.len);
	    t.trsp[it->trsp.len] = '\0';
	}
	else {
	    t.trsp[0] = '\0';
	}

	do {
	    targets->dest_list.push_back(t);

	} while(h_dns.next_ip(&t.ss, Dualstack) == 0);
    }

    return 0;
}

void _resolver::clear_cache(){
	int removed = 0;
	for(unsigned long i=0; i<cache.get_size(); i++){
		dns_bucket* bucket = cache.get_bucket(i);
		bucket->lock();
		for(dns_bucket::value_map::iterator it = bucket->elmts.begin();
				it != bucket->elmts.end(); ++it){
			dns_entry* dns_e = (dns_entry*)it->second;
			dns_bucket::value_map::iterator tmp_it = it;
			bool end_of_bucket = (++it == bucket->elmts.end());

			bucket->elmts.erase(tmp_it);
			dec_ref(dns_e);
			removed++;

			if(end_of_bucket) break;
		}
		bucket->unlock();
	}
	DBG("resolver::clear_cache() %d entries removed",removed);
}

void _resolver::run()
{
    struct timespec tick,rem;
    tick.tv_sec  = (DNS_CACHE_SINGLE_CYCLE/1000000L);
    tick.tv_nsec = (DNS_CACHE_SINGLE_CYCLE - (tick.tv_sec)*1000000L) * 1000L;

    unsigned long i = 0;
    setThreadName("resolver");
    for(;;) {
	nanosleep(&tick,&rem);

	u_int64_t now = wheeltimer::instance()->unix_clock.get();
	dns_bucket* bucket = cache.get_bucket(i);

	bucket->lock();
	    
	for(dns_bucket::value_map::iterator it = bucket->elmts.begin();
	    it != bucket->elmts.end(); ++it){

	    dns_entry* dns_e = (dns_entry*)it->second;
	    if(now >= it->second->expire){

		dns_bucket::value_map::iterator tmp_it = it;
		bool end_of_bucket = (++it == bucket->elmts.end());

		DBG("DNS record expired (%p) '%s' -> %s",dns_e,
			tmp_it->first.c_str(),dns_e->to_str().c_str());

		bucket->elmts.erase(tmp_it);
		dec_ref(dns_e);

		if(end_of_bucket) break;
	    }
	    else {
		//DBG("######### record %p expires in %li seconds ##########",
		//    dns_e,it->second->expire-tv_now.tv_sec);
	    }
	}

	bucket->unlock();

	if(++i >= cache.get_size()) i = 0;
    }
}

void dns_handle::dump(AmArg &ret) {
    if(srv_e) {
        ret["type"] = "srv";
        //ret["port"] = port;
        AmArg &entries = ret["entries"];
        vector<dns_base_entry*> &v = srv_e->ip_vec;
        for(int i = 0;i < (int)v.size();i++){
            entries.push(AmArg());
            AmArg &a = entries.back();
            srv_entry *e = (srv_entry *)v[i];
            a["priority"] = e->p;
            a["weight"] = e->w;
            a["port"] = e->port;
            a["target"] = e->target;
        }
    } else if(ip_e) { //ip_e
        char host[NI_MAXHOST] = "";
        sockaddr_storage ss;
        ret["type"] = "ip";
        AmArg &entries = ret["entries"];
        vector<dns_base_entry*> &v = ip_e->ip_vec;
        for(int i = 0;i < (int)v.size();i++){
            entries.push(AmArg());
            AmArg &a = entries.back();
            ip_entry *e = (ip_entry *)v[i];
            e->to_sa(&ss);
            a["addr"] = am_inet_ntop_sip(&ss,host,NI_MAXHOST);
        }
    } else {
        ret["type"] = "unknown";
    }
}

void dns_handle::dumpIps(AmArg &ret, dns_priority priority)
{
    sockaddr_storage remote_ip;
    std::string addr;
    prepare(ip_e, priority);
    AmArg &entries = ret["entries"];
    while(next_ip(&remote_ip, priority) > 0) {
        addr = get_addr_str_sip(&remote_ip);
        entries.push(AmArg());
        AmArg &a = entries.back();
        a["addr"] = addr.c_str();
    }
}

void dns_handle::prepare(dns_entry* e, dns_priority priority)
{
    if(e->get_type() == dns_r_ip) {
        if(ip_e)
            dec_ref(ip_e);
        ip_e = (dns_ip_entry*)e;
        inc_ref(ip_e);
        ip_n = 0;
        ip_indexes.clear();
        ip_e->sort_by_priority(this, priority);
    } else if(e->get_type() == dns_r_srv) {
        if(srv_e)
            dec_ref(srv_e);
        srv_e = (dns_srv_entry*)e;
        inc_ref(srv_e);
        srv_n = 0;
        srv_used = 0;
        ip_n = -1;
    }
}

void dns_handle::reset(dns_rr_type type)
{
    if(type == dns_r_ip && ip_e) {
        dec_ref(ip_e);
        ip_e = NULL;
        ip_n = -1;
    }
    if(type == dns_r_srv && srv_e) {
        dec_ref(srv_e);
        srv_e = NULL;
        srv_n = 0;
        srv_used = 0;
    }
}


/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */
