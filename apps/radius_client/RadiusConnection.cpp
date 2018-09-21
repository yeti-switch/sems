#include "RadiusConnection.h"
#include "RadiusPacket.h"

#include "AmSessionContainer.h"
#include "sip/resolver.h"

#include <fcntl.h>
#include <sip/ip_util.h>
#include <string.h>
#include <errno.h>

#include <sstream>

RadiusConnection::RadiusConnection(
    unsigned int connection_id,
    string &name,
    string &server,
    unsigned short port,
    string &secret,
    unsigned int timeout_msec,
    unsigned int attempts)
  : last_id(0),
    sock(-1),
    requests_sent(0),
    replies_got(0),
    requests_err(0),
    requests_timeouts(0),
    replies_err(0),
    replies_socket_err(0),
    replies_match_err(0),
    replies_validate_err(0),
    min_response_time(0),
    max_response_time(0),
    connection_id(connection_id),
    name(name),
    server(server),
    port(port),
    secret(secret),
    timeout(timeout_msec),
    attempts(attempts)
{
    timeout_tv.tv_sec = timeout/1000;
    timeout_tv.tv_usec = (timeout-timeout_tv.tv_sec*1000)*1000;
}

RadiusConnection::~RadiusConnection()
{
    DBG("remove radius connection %p",this);
    close(sock);
}

int RadiusConnection::init()
{
    struct sockaddr_storage a;

    sock = ::socket(PF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        ERROR("can't create socket. error: %s",strerror(errno));
        return -1;
    }

    //::fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

    memset(&a,0,sizeof(sockaddr_storage));
    SAv4(&a)->sin_family = AF_INET;
    //am_set_port(&a,1010);

    if(::bind(sock,(struct sockaddr *)&a, sizeof(struct sockaddr))) {
        ERROR("can't bind socket: %s",strerror(errno));
        return -1;
    }

    dns_handle dh;
    if(-1==resolver::instance()->resolve_name(
        server.c_str(),
        &dh,&a,IPv4_only))
    {
        ERROR("can't resolve %s",server.c_str());
        return -1;
    }
    DBG("%s -> %s",server.c_str(),get_addr_str(&a).c_str());
    am_set_port(&a,port);

    if(::connect(sock,(struct sockaddr *)&a, sizeof(struct sockaddr))) {
        ERROR("can't connect: %s",strerror(errno));
        return -1;
    }

    if(::fcntl(sock, F_SETFL, O_NONBLOCK)) {
        ERROR("can't set nonblock: %s",strerror(errno));
        return -1;
    }

    return 0;
}

void RadiusConnection::process()
{
    struct timeval now, diff;

    DBG("process radius reply");
    RadiusPacket reply;
    if(0!=reply.read_from_socket(sock)){
        ERROR("error reading radius reply. ignore it");
        replies_socket_err++;
        return;
    }
    gettimeofday(&now,NULL);
    DBG("got reply with id %d",reply.id());

    SentMap::iterator it = sent_map.find(reply.id());
    if(it==sent_map.end()){
        DBG("reply not matched with sent requests. ignore it");
        replies_match_err++;
        return;
    }

    RadiusPacket *request = it->second;
    if(!reply.validate(*request,secret)){
        DBG("reply validation failed. ignore it");
        replies_validate_err++;
        return;
    }

    DBG("got reply with code %d for session %s",
        reply.code(),
        request->session().c_str());

    timersub(reply.timestamp(),request->timestamp(),&diff);
    update_min_max(min_response_time,max_response_time,timeval2double(diff));

    on_reply(*request,reply);

    sent_map.erase(it);
    delete request;
}

void RadiusConnection::avp_info::info(AmArg &info) const
{
    info["type"] = type;
    info["format"] = fmt_name;
    info["value"] = value;
    info["vsa"] = vsa;
    if(vsa) {
        info["vsa_vendor_id"] = (long long int)vsa_vendor_id;
        info["vsa_vendor_type"] = vsa_vendor_type;
    }
}

int RadiusConnection::avp_info::parse(const AmArg &a)
{
    try {
        name = a["name"].asCStr();
        type = a["type_id"].asInt();
        value = a["value"].asCStr();

        vsa = a["is_vsa"].asBool();
        if(vsa){
            vsa_vendor_id = a["vsa_vendor_id"].asInt();
            vsa_vendor_type = a["vsa_vendor_type"].asInt();
        }

        fmt_name = a["format"].asCStr();
        if(fmt_name=="string")        fmt = str;
        else if(fmt_name=="integer")  fmt = integer;
        else if(fmt_name=="octets")   fmt = octets;
        else if(fmt_name=="date")     fmt = date;
        else if(fmt_name=="ipaddr")   fmt = ipv4;
        else if(fmt_name=="ip6addr")  fmt = ipv6;
        else {
            ERROR("uknown attribute format: '%s'",fmt_name.c_str());
            return 1;
        }

    } catch(...){
        ERROR("uknown exception on AmArg parsing");
        return 1;
    }
    return 0;
}

int RadiusConnection::avp_info::add2packet(RadiusPacket *p, const map<string,string> &values_hash) const
{
#define PLACEHOLDER_WRAPPER '$'

    int i;
    bool arg = false;
    std::stringstream ss;
    struct sockaddr_storage a;
    size_t pos = 0, start = 0, end = 0;

    //replace placeholders
    while((pos = value.find(PLACEHOLDER_WRAPPER,pos))!=string::npos){
        if(!arg){
            //found placeholder start
            arg = true;
            if(pos > 0) {
                //update with non-placeholder chunk
                ss << value.substr(end,pos-end);
            }
            pos++;
            start = pos;
        } else {
            //found placeholder end
            arg = false;
            if(start==pos){ //empty placeholder (escaping)
                ss << PLACEHOLDER_WRAPPER;
            } else {
                const string placeholder_name = value.substr(start,pos-start);
                //resolve placeholder using values hash
                map<string,string>::const_iterator
                    it = values_hash.find(placeholder_name);
                if(it!=values_hash.end()){
                    ss << it->second.c_str();
                } else {
                    WARN("uknown variable name '%s' in placeholder. leave it as is",
                         placeholder_name.c_str());
                    ss << PLACEHOLDER_WRAPPER
                       << placeholder_name
                       << PLACEHOLDER_WRAPPER;
                    /*for(it = values_hash.begin(); it!=values_hash.end();it++){
                        DBG("values_hash[%s]: <%s>",
                            it->first.c_str(), it->second.c_str());
                    }*/
                }
            }
            pos++;
            end = pos;
        }
    }

    if(arg){
        ERROR("unbalanced placeholder wrappers count in %s."
              "use %c%c to place %c",
              value.c_str(),
              PLACEHOLDER_WRAPPER, PLACEHOLDER_WRAPPER,
              PLACEHOLDER_WRAPPER);
        return 1;
    }

    if(end < value.length()){
        /* update with ending chunk
           will be overall string if no placeholders */
        ss << value.substr(end);
    }

    string v = ss.str();

    DBG("add avp: %d:%s:%s with value %s",
        type,name.c_str(),fmt_name.c_str(),v.c_str());

    switch(fmt){
    case str:
    case octets:
        if(vsa) return p->add_vendor_attr(type,vsa_vendor_id,vsa_vendor_type,v.data(),v.size());
        else    return p->add_attr_string(type,v);
        break;
    case integer:
    case date:
        if(!str2int(v,i)){
            ERROR("can't convert %s to integer",v.c_str());
            return 1;
        }
        if(vsa) return p->add_vendor_attr_int32(type,vsa_vendor_id,vsa_vendor_type,i);
        else    return p->add_attr_int32(type,i);
        break;
    case ipv4:
        if(1!=am_inet_pton(v.c_str(), &a)){
            ERROR("can't convert %s to IP address",v.c_str());
            return 1;
        }
        if(a.ss_family!=AF_INET){
            ERROR("%s is not IPv4 address",v.c_str());
            return 1;
        }
        if(vsa) return p->add_vendor_attr(type,vsa_vendor_id,vsa_vendor_type,(const char *)&(SAv4(&a)->sin_addr),sizeof(struct in_addr));
        else    return p->add_attr(type,(const char *)&(SAv4(&a)->sin_addr),sizeof(struct in_addr));
        break;
    case ipv6:
        if(1!=am_inet_pton(v.c_str(), &a)){
            ERROR("can't convert %s to IP address",v.c_str());
            return 1;
        }
        if(a.ss_family!=AF_INET6){
            ERROR("%s is not IPv6 address",v.c_str());
            return 1;
        }
        if(vsa) return p->add_vendor_attr(type,vsa_vendor_id,vsa_vendor_type,(const char *)&(SAv6(&a)->sin6_addr),sizeof(struct in6_addr));
        else    return p->add_attr(type,(const char *)&(SAv6(&a)->sin6_addr),sizeof(struct in6_addr));
        break;
    }

    return 0;
#undef PLACEHOLDER_WRAPPER
}

int RadiusConnection::parse_avps(avps_t &avps, const AmArg &raw_avps)
{
    if(isArgUndef(raw_avps)){
        DBG("empty avps configuration. skip parsing");
        return 0;
    }
    for(unsigned int i = 0;i< raw_avps.size(); i++){
        AmArg &a = raw_avps.get(i);
        if(isArgUndef(a)) continue;
        DBG("%d: %s",i,AmArg::print(a).c_str());
        avps.push_back(avp_info());
        if(avps.back().parse(a)){
            ERROR("error when parsing avp %d: %s",i,AmArg::print(a).c_str());
            return 1;
        }
    }
    return 0;
}

void RadiusConnection::check_timeouts()
{
    struct timeval now, expired_at;
    RadiusPacket *p;
    queue<SentMap::iterator> expired_requests;

    gettimeofday(&now,NULL);

    for(SentMap::iterator it = sent_map.begin();
        it!=sent_map.end();it++)
    {
        p = it->second;
        if(timercmp(&now,p->expire(),>)){

            if(p->get_attempt() < attempts) {
                timeradd(&now,&timeout_tv,&expired_at);
                p->set_expire(expired_at);
                p->send(sock);
                continue;
            }

            expired_requests.push(it);
        }
    }

    while(!expired_requests.empty()){
        SentMap::iterator &it = expired_requests.front();
        p = it->second;

        requests_timeouts++;
        on_timeout(*p);
        delete p;
        sent_map.erase(it);
        expired_requests.pop();
    }
}

void RadiusConnection::getStat(AmArg &stat)
{
    stat["id"] = (long long int)connection_id;
    stat["requests_sent"]  = requests_sent;
    stat["requests_errors"]  = requests_err;
    stat["requests_timeouts"]  = requests_timeouts;
    stat["replies_received"]  = replies_got;
    stat["replies_errors"] = replies_err;
    stat["replies_socket_errors"] = replies_socket_err;
    stat["replies_match_errors"] = replies_match_err;
    stat["replies_validate_errors"] = replies_validate_err;
    stat["max_response_time"] = max_response_time;
    stat["min_response_time"] = min_response_time;
}

void RadiusConnection::getInfo(AmArg &info)
{
    DBG("get info");
    info["id"] = (int)connection_id;
    info["name"] = name;
    info["server"] = server;
    info["port"] = port;
    info["secret"] = secret;
    info["timeout"] = (int)timeout;
    info["attempts"] = (int)attempts;
}
