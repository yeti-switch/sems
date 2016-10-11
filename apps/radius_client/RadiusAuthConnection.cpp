#include "RadiusAuthConnection.h"

#include "AmSessionContainer.h"

RadiusAuthConnection::RadiusAuthConnection(
    unsigned int connection_id,
    string &name,
    string &server,
    unsigned short port,
    string &secret,
    bool reject_on_error,
    unsigned int timeout_msec,
    unsigned int attempts,
    AmArg avps)
  : RadiusConnection(
        connection_id,
        name,
        server,
        port,
        secret,
        timeout_msec,
        attempts),
    reject_on_error(reject_on_error),
    raw_avps(avps)
{}

int RadiusAuthConnection::init()
{
    return
        parse_avps(avps,raw_avps)
        || RadiusConnection::init();
}

void RadiusAuthConnection::AccessRequest(const RadiusRequestEvent &req)
{
    struct timeval expire_at;
    RadiusPacket *p;

    if(sent_map.find(last_id)!=sent_map.end()){
        ERROR("last_id points to existent request. discard packet. generate request error");
        goto err;
    }

    p = new RadiusPacket(RadiusPacket::AccessRequest,last_id);

    timeradd(&req.created_at,&timeout_tv,&expire_at);
    p->set_session_id(req.session_id);
    p->set_expire(expire_at);

    for(avps_t::const_iterator it = avps.begin();
        it!=avps.end();++it)
    {
        const avp_info &avp = *it;
        if(avp.add2packet(p,req.values_hash)){
            ERROR("can't add avp %d:%s:%s with value %s",
                  avp.type,avp.name.c_str(),avp.fmt_name.c_str(),
                  avp.value.c_str());
            goto err_free_packet;
        }
    }
    p->build(secret);

    if(0!=p->send(sock)){
        ERROR("error sending radius request");
        goto err_free_packet;
    }
    requests_sent++;

    sent_map[last_id] = p;
    last_id = (last_id + 1) % 255;
    return;
err_free_packet:
    delete p;
err:
    requests_err++;
    if(!AmSessionContainer::instance()->postEvent(
        req.session_id,
        new RadiusReplyEvent(RadiusReplyEvent::Error,
                             RADIUS_REQUEST_ERROR,
                             reject_on_error)))
    {
        ERROR("can't post reply event to session %s",
              req.session_id.c_str());
    }
    return;
}

void RadiusAuthConnection::on_timeout(RadiusPacket &p)
{
    if(!AmSessionContainer::instance()->postEvent(
        p.session(),
        new RadiusReplyEvent(RadiusReplyEvent::Error,
                             RADIUS_RESPONSE_TIMEOUT,
                             reject_on_error)))
    {
        ERROR("can't post reply event to session %s",
              p.session().c_str());
    }
}

void RadiusAuthConnection::on_reply(RadiusPacket &request, RadiusPacket &reply)
{
    int error_code = 0;
    RadiusReplyEvent::RadiusResult reply_result;

    switch(reply.code()){
    case RadiusPacket::AccessAccept:
        reply_result = RadiusReplyEvent::Accepted;
        replies_got++;
        break;
    case RadiusPacket::AccessReject:
        reply_result = RadiusReplyEvent::Rejected;
        replies_got++;
        break;
    default:
        ERROR("unexpected reply code: %d for session %s",
              reply.code(),
              request.session().c_str());
        reply_result = RadiusReplyEvent::Error;
        error_code = RADIUS_INVALID_RESPONSE;
        replies_err++;
        break;
    };

    if(!AmSessionContainer::instance()->postEvent(
        request.session().c_str(),
        new RadiusReplyEvent(reply_result,
                             error_code,
                             reject_on_error)))
    {
        ERROR("can't post reply event to session %s",
              request.session().c_str());
    }
}

void RadiusAuthConnection::getInfo(AmArg &info)
{
    RadiusConnection::getInfo(info);

    info["reject_on_errors"] = reject_on_error;

    AmArg &avps_arg = info["avps"];
    for(avps_t::const_iterator it = avps.begin();
        it!=avps.end();++it)
    {
        avps_arg.push(AmArg());
        it->info(avps_arg.back());
    }
}
