#include "RadiusAccConnection.h"

RadiusAccConnection::RadiusAccConnection(
    unsigned int connection_id,
    string &name,
    string &server,
    unsigned short port,
    string &secret,
    unsigned int timeout_msec,
    unsigned int attempts,
    AmArg start_avps,
    AmArg interim_avps,
    AmArg stop_avps,
    bool enable_start_accounting,
    bool enable_interim_accounting,
    bool enable_stop_accounting,
    int interim_accounting_interval)
  : RadiusConnection(
        connection_id,
        name,
        server,
        port,
        secret,
        timeout_msec,
        attempts),
    start_avps_raw(start_avps),
    interim_avps_raw(interim_avps),
    stop_avps_raw(stop_avps),
    rules(
        enable_start_accounting,
        enable_interim_accounting,
        enable_stop_accounting,
        interim_accounting_interval
    )
{}

int RadiusAccConnection::init()
{
    DBG("loading start avps");
    if(parse_avps(start_avps,start_avps_raw)){
        ERROR("can't parse start_avps");
        return 1;
    }
    DBG("loading interim avps");
    if(parse_avps(interim_avps,interim_avps_raw)){
        ERROR("can't parse interim_avps");
        return 1;
    }
    DBG("loading stop avps");
    if(parse_avps(stop_avps,stop_avps_raw)){
        ERROR("can't parse stop_avps");
        return 1;
    }
    return RadiusConnection::init();
}

void RadiusAccConnection::AccountingRequest(const RadiusRequestEvent &req)
{
    struct timeval expire_at;
    RadiusPacket *p;

    if(sent_map.find(last_id)!=sent_map.end()){
        ERROR("last_id points to existent request. discard packet. generate request error");
        requests_err++;
        return;
    }

    p = new RadiusPacket(RadiusPacket::AccountingRequest,last_id);

    timeradd(&req.created_at,&timeout_tv,&expire_at);
    p->set_session_id(req.session_id);
    p->set_expire(expire_at);

    avps_t &avps = get_avps(req.accounting_type);
    for(avps_t::const_iterator it = avps.begin();
        it!=avps.end();++it)
    {
        const avp_info &avp = *it;
        if(avp.add2packet(p,req.values_hash)){
            ERROR("can't add avp %d:%s:%s with value %s",
                  avp.type,avp.name.c_str(),avp.fmt_name.c_str(),
                  avp.value.c_str());
            delete p;
            return;
        }
    }
    p->build(secret);

    if(0!=p->send(sock)){
        ERROR("error sending radius request");
        delete p;
        return;
    }
    requests_sent++;

    sent_map[last_id] = p;
    last_id = (last_id + 1) % 255;
}

void RadiusAccConnection::on_timeout(RadiusPacket &p)
{
    DBG("response timeout for radius acc packet for session %s",p.session().c_str());
}

void RadiusAccConnection::on_reply(RadiusPacket &request, RadiusPacket &reply)
{
    DBG("got reply for accounting request for session %s with code %d",
        request.session().c_str(),reply.code());
}

void RadiusAccConnection::add_avps_info(const avps_t &avps, AmArg &ret)
{
    for(avps_t::const_iterator it = avps.begin();
        it!=avps.end();++it)
    {
        ret.push(AmArg());
        it->info(ret.back());
    }
}

RadiusConnection::avps_t& RadiusAccConnection::get_avps(RadiusRequestEvent::RadiusAccountingType type)
{
    switch(type){
    case RadiusRequestEvent::Start:
        return start_avps;
    case RadiusRequestEvent::Interim:
        return interim_avps;
    case RadiusRequestEvent::End:
        return stop_avps;
    }
    ERROR("invalid radius accounting type: %d. failover to interim",type);
    return interim_avps;
}

void RadiusAccConnection::getInfo(AmArg &info)
{
    RadiusConnection::getInfo(info);
    add_avps_info(start_avps,info["start_avps"]);
    add_avps_info(interim_avps,info["interim_avps"]);
    add_avps_info(stop_avps,info["stop_avps"]);
    info["enable_start_accounting"] = rules.enable_start_accounting;
    info["enable_interim_accounting"] = rules.enable_interim_accounting;
    info["enable_stop_accounting"] = rules.enable_stop_accounting;
    info["interim_accounting_interval"] = rules.interim_accounting_interval;
}
