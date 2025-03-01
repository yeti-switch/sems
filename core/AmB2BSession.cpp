/*
 * Copyright (C) 2002-2003 Fhg Fokus
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

#include "AmB2BSession.h"
#include "AmSessionContainer.h"
#include "ampi/MonitoringAPI.h"
#include "AmUtils.h"
#include "sip/hash.h"

#include <assert.h>

// helpers
//static const string sdp_content_type(SIP_APPLICATION_SDP);
//static const string empty;
static const string sendonly("sendonly");
static const string recvonly("recvonly");
static const string sendrecv("sendrecv");
static const string inactive("inactive");
static const string zero_connection("0.0.0.0");

enum MediaActivity { Inactive, Sendonly, Recvonly, Sendrecv };

static const string sip_method_invite_str(SIP_METH_INVITE);

//
// helper functions
//

/** returns true if connection is active.
 * Returns given default_value if the connection address is empty to cope with
 * connection address set globaly and not per media stream */
static bool connectionActive(const SdpConnection &connection, bool default_value)
{
    if (connection.address.empty()) return default_value;
    if (connection.address == zero_connection) return false;
    return true;
}

/** Returns true if there is no direction=inactione or sendonly attribute in
 * given media stream. It doesn't check the connection address! */
static MediaActivity getMediaActivity(const vector<SdpAttribute> &attrs, MediaActivity default_value)
{
    // go through attributes and try to find sendonly/recvonly/sendrecv/inactive
    for (std::vector<SdpAttribute>::const_iterator a = attrs.begin();
         a != attrs.end(); ++a)
    {
        if (a->attribute == sendonly) return Sendonly;
        if (a->attribute == inactive) return Inactive;
        if (a->attribute == recvonly) return Recvonly;
        if (a->attribute == sendrecv) return Sendrecv;
    }

    return default_value; // none of the attributes given, return (session) default
}

static MediaActivity getMediaActivity(const SdpMedia &m, MediaActivity)
{
    if (m.send) {
        if (m.recv) return Sendrecv;
        else return Sendonly;
    } else {
        if (m.recv) return Recvonly;
    }
    return Inactive;
}

static void errCode2RelayedReply(AmSipReply &reply, int err_code, unsigned default_code = 500)
{
    // FIXME: use cleaner method to propagate error codes/reasons,
    // do it everywhere in the code
    if ((err_code < -399) && (err_code > -700)) {
        reply.code = -err_code;
    } else reply.code = default_code;

    // TODO: optimize with a table
    switch (reply.code) {
    case 400: reply.reason = "Bad Request"; break;
    case 478: reply.reason = "Unresolvable destination"; break;
    case 488: reply.reason = SIP_REPLY_NOT_ACCEPTABLE_HERE; break;
    case 491: reply.reason = SIP_REPLY_PENDING; break;
    default: reply.reason = SIP_REPLY_SERVER_INTERNAL_ERROR;
    }
}

//
// AmB2BSession methods
//

AmB2BSession::AmB2BSession(
    const string& other_local_tag,
    AmSipDialog* p_dlg, AmSipSubscription* p_subs)
  : AmSession(p_dlg),
    other_id(other_local_tag),
    sip_relay_only(true),
    remote_on_hold(false),
    rtp_stream_shared(false),
    est_invite_cseq(0),
    est_invite_other_cseq(0),
    subs(p_subs),
    rtp_relay_mode(RTP_Direct),
    rtp_relay_force_symmetric_rtp(false),
    rtp_ping(false),
    rtp_relay_transparent_seqno(true),
    rtp_relay_transparent_ssrc(true),
    rtp_relay_timestamp_aligning(false),
    enable_dtmf_transcoding(false),
    enable_inbound_dtmf_filtering(false),
    enable_dtmf_rtp_filtering(false),
    enable_dtmf_rtp_detection(false),
    enable_dtmf_rtp_force_relay(true),
    enable_cn_rtp_force_relay(false),
    dead_rtp_time(AmConfig.dead_rtp_time),
    ignore_relay_streams(false),
    media_session(nullptr)
{
    if(!subs) subs = new AmSipSubscription(dlg,this);
}

AmB2BSession::~AmB2BSession()
{
    clearRtpReceiverRelay();

    DBG3("relayed_req.size() = %zu",relayed_req.size());

    map<int,AmSipRequest>::iterator it = recvd_req.begin();
    DBG3("recvd_req.size() = %zu",recvd_req.size());
    for(;it != recvd_req.end(); ++it){
        DBG3("  <%i,%s>",it->first,it->second.method.c_str());
    }

    if(subs)
        delete subs;
}

void AmB2BSession::set_sip_relay_only(bool r)
{
    sip_relay_only = r;

    // disable offer/answer if we just relay requests
    //dlg.setOAEnabled(!sip_relay_only); ???
}

void AmB2BSession::clear_other()
{
    setOtherId("");
}

void AmB2BSession::process(AmEvent* event)
{
    B2BEvent* b2b_e = dynamic_cast<B2BEvent*>(event);
    if(b2b_e) {
        onB2BEvent(b2b_e);
        return;
    }

    SingleSubTimeoutEvent* to_ev = dynamic_cast<SingleSubTimeoutEvent*>(event);
    if(to_ev) {
        subs->onTimeout(to_ev->timer_id,to_ev->sub);
        return;
    }

    AmSession::process(event);
}

void AmB2BSession::finalize()
{
    // clean up relayed_req
    if(!other_id.empty()) {
        while(!relayed_req.empty()) {
            TransMap::iterator it = relayed_req.begin();
            const AmSipRequest& req = it->second;
            if(req.method == SIP_METH_BYE) {
                relayError(req.method,req.cseq,true,200,"OK");
            } else {
                relayError(req.method,req.cseq,true,481,SIP_REPLY_NOT_EXIST);
            }
            relayed_req.erase(it);
        }
    }
    AmSession::finalize();
}

void AmB2BSession::relayError(const string &method, unsigned cseq,
                              bool forward, int err_code)
{
    if (method != "ACK") {
        AmSipReply n_reply;

        errCode2RelayedReply(n_reply, err_code, 500);
        n_reply.cseq = cseq;
        n_reply.cseq_method = method;
        n_reply.from_tag = dlg->getLocalTag();
        n_reply.remote_port = 0;
        n_reply.local_reply = true;

        if(n_reply.code == 491) {
            //add Retry-After header with random 2-10 seconds
            n_reply.hdrs += SIP_HDR_COLSP(SIP_HDR_RETRY_AFTER)
                + int2str((get_random() % 8) + 2) + CRLF;
        }

        DBG("relaying B2B SIP error reply %u %s", n_reply.code, n_reply.reason.c_str());
        relayEvent(new B2BSipReplyEvent(n_reply, forward, method, getLocalTag()));
    }
}

void AmB2BSession::relayError(const string &method, unsigned cseq, bool forward, int sip_code, const char *reason)
{
    if (method != "ACK") {
        AmSipReply n_reply;

        n_reply.code = sip_code;
        n_reply.reason = reason;
        n_reply.cseq = cseq;
        n_reply.cseq_method = method;
        n_reply.from_tag = dlg->getLocalTag();
        n_reply.remote_port = 0;
        n_reply.local_reply = true;

        DBG("relaying B2B SIP reply %d %s", sip_code, reason);
        relayEvent(new B2BSipReplyEvent(n_reply, forward, method, getLocalTag()));
    }
}

void AmB2BSession::onB2BEvent(B2BEvent* ev)
{
    DBG("AmB2BSession::onB2BEvent");
    switch(ev->event_id) {

    case B2BSipRequest:
    {
        B2BSipRequestEvent* req_ev = dynamic_cast<B2BSipRequestEvent*>(ev);
        assert(req_ev);

        DBG("B2BSipRequest: %s (fwd=%s)",
            req_ev->req.method.c_str(),
            req_ev->forward?"true":"false");

        if(req_ev->forward) {
            // Check Max-Forwards first
            if(req_ev->req.max_forwards == 0) {
                relayError(req_ev->req.method,req_ev->req.cseq,
                           true,483,SIP_REPLY_TOO_MANY_HOPS);
                return;
            }

            if(req_ev->req.method == SIP_METH_INVITE &&
               dlg->getUACInvTransPending())
            {
                // don't relay INVITE if INV trans pending
                DBG("not sip-relaying INVITE with pending INV transaction, "
                    "b2b-relaying 491 pending");
                relayError(req_ev->req.method, req_ev->req.cseq,
                           true, 491, SIP_REPLY_PENDING);
                return;
            }

            if(req_ev->req.method == SIP_METH_BYE &&
               dlg->getStatus() != AmBasicSipDialog::Connected)
            {
                DBG("not sip-relaying BYE in not connected dlg, b2b-relaying 200 OK");
                relayError(req_ev->req.method, req_ev->req.cseq,
                           true, 200, "OK");
                terminateLeg(); //no any reasons to stay alive
                return;
            }

            int res = relaySip(req_ev->req);
            if(res < 0) {
                // reply relayed request internally
                if(req_ev->req.method == SIP_METH_BYE) {
                    DBG("failed to send BYE request. generate 200 ok and drop dialog");
                    relayError(req_ev->req.method, req_ev->req.cseq,
                               true, 200, "OK");
                    dlg->drop();
                    //no return here. to call onOtherBye()
                } else {
                    relayError(req_ev->req.method, req_ev->req.cseq, true, res);
                    return;
                }
            }
        } //if(req_ev->forward)

        if((req_ev->req.method == SIP_METH_BYE)
            // CANCEL is handled differently: other side has already
            // sent a terminate event.
            /*|| (req_ev->req.method == SIP_METH_CANCEL)*/)
        {
            onOtherBye(req_ev->req);
        }
    } //case B2BSipRequest
    return;

    case B2BSipReply:
    {
        B2BSipReplyEvent* reply_ev = dynamic_cast<B2BSipReplyEvent*>(ev);
        assert(reply_ev);

        DBG("B2BSipReply: %i %s (fwd=%s)",reply_ev->reply.code,
            reply_ev->reply.reason.c_str(),
            reply_ev->forward?"true":"false");

        DBG("B2BSipReply: content-type = %s",
            reply_ev->reply.body.getCTStr().c_str());

        if(reply_ev->forward) {
            std::map<int,AmSipRequest>::iterator t_req =
                recvd_req.find(reply_ev->reply.cseq);
            if(t_req != recvd_req.end()) {
                if((reply_ev->reply.code >= 300) && (reply_ev->reply.code <= 305) &&
                   !reply_ev->reply.contact.empty())
                {
                    // relay with Contact in 300 - 305 redirect messages
                    AmSipReply n_reply(reply_ev->reply);
                    n_reply.hdrs+=SIP_HDR_COLSP(SIP_HDR_CONTACT) +
                        reply_ev->reply.contact+ CRLF;

                    if(relaySip(t_req->second,n_reply) < 0) {
                        terminateOtherLeg();
                        terminateLeg();
                    }
                } else {
                    // relay response
                    if(relaySip(t_req->second,reply_ev->reply) < 0) {
                        terminateOtherLeg();
                        terminateLeg();
                    }
                }
            } else {
                DBG("Cannot relay reply: request already replied"
                    " (code=%u;cseq=%u;call-id=%s)",
                    reply_ev->reply.code, reply_ev->reply.cseq,
                    reply_ev->reply.callid.c_str());
            }
        } else {
            // check whether not-forwarded (locally initiated)
            // INV/UPD transaction changed session in other leg
            if(SIP_IS_200_CLASS(reply_ev->reply.code) &&
               (!reply_ev->reply.body.empty()) &&
               (reply_ev->reply.cseq_method == SIP_METH_INVITE ||
                reply_ev->reply.cseq_method == SIP_METH_UPDATE))
            {
                if(updateSessionDescription(reply_ev->reply.body)) {
                    if(reply_ev->reply.cseq != est_invite_cseq) {
                        if(dlg->getUACInvTransPending()) {
                            DBG("changed session, but UAC INVITE trans pending");
                            // todo(?): save until trans is finished?
                            return;
                        }
                        DBG("session description changed - refreshing");
                        sendEstablishedReInvite();
                    } else {
                        DBG("reply to establishing INVITE request - not refreshing");
                    }
                }
            }
        }
    } //case B2BSipReply
    return;

    case B2BTerminateLeg:
        DBG("terminateLeg()");
        terminateLeg();
        break;

    case B2BClearMedia:
        DBG("clear media");
        if(media_session) media_session->clearAudio(a_leg);
        break;
    }//switch(ev->event_id)

    //ERROR("unknown event caught");
}

bool AmB2BSession::getMappedReferID(unsigned int refer_id,
                                    unsigned int& mapped_id) const
{
    map<unsigned int, unsigned int>::const_iterator id_it =
        refer_id_map.find(refer_id);
    if(id_it != refer_id_map.end()) {
        mapped_id = id_it->second;
        return true;
    }

    return false;
}

void AmB2BSession::insertMappedReferID(unsigned int refer_id,
                                       unsigned int mapped_id)
{
    refer_id_map[refer_id] = mapped_id;
}

void AmB2BSession::onSipRequest(const AmSipRequest& req)
{
    bool fwd = sip_relay_only &&
        (req.method != SIP_METH_CANCEL) &&
        (req.method != SIP_METH_INFO);

    if(((req.method == SIP_METH_SUBSCRIBE) ||
       (req.method == SIP_METH_NOTIFY) ||
       (req.method == SIP_METH_REFER))
        && !subs->onRequestIn(req))
    {
        return;
    }

    if(!fwd) {
        AmSession::onSipRequest(req);
    } else {
        updateRefreshMethod(req.hdrs);

        if(req.method == SIP_METH_BYE)
            onBye(req);
    }

    B2BSipRequestEvent* r_ev = new B2BSipRequestEvent(req,fwd);

    if(fwd) {
        DBG("relaying B2B SIP request (fwd) %s %s",
            r_ev->req.method.c_str(), r_ev->req.r_uri.c_str());

        if(r_ev->req.method == SIP_METH_NOTIFY) {

            string event = getHeader(r_ev->req.hdrs,SIP_HDR_EVENT,true);
            string id = get_header_param(event,"id");
            event = strip_header_params(event);

            if(event == "refer" && !id.empty()) {
                int id_int = 0;
                if(str2int(id,id_int)) {
                    unsigned int mapped_id = 0;
                    if(getMappedReferID(id_int,mapped_id)) {
                        removeHeader(r_ev->req.hdrs,SIP_HDR_EVENT);
                        r_ev->req.hdrs += SIP_HDR_COLSP(SIP_HDR_EVENT) "refer;id="
                          + int2str(mapped_id) + CRLF;
                    }
                }
            }
        }

        int res = relayEvent(r_ev);
        if(res == 0) {
            // successfuly relayed, store the request
            if(req.method != SIP_METH_ACK)
                recvd_req.insert(std::make_pair(req.cseq,req));
        } else {
            // relay failed, generate error reply
            DBG("relay failed, replying error");
            AmSipReply n_reply;
            errCode2RelayedReply(n_reply, res, 500);
            dlg->reply(req, n_reply.code, n_reply.reason);
        }

        return;
    } //if(fwd)

    if(r_ev->req.method!=SIP_METH_INFO) {
        DBG("relaying B2B SIP request %s %s",
            r_ev->req.method.c_str(), r_ev->req.r_uri.c_str());
        relayEvent(r_ev);
    }
}

void AmB2BSession::onRequestSent(const AmSipRequest& req)
{
    if(((req.method == SIP_METH_SUBSCRIBE) ||
       (req.method == SIP_METH_NOTIFY) ||
       (req.method == SIP_METH_REFER)))
    {
        subs->onRequestSent(req);
    }

    AmSession::onRequestSent(req);
}

void AmB2BSession::updateLocalSdp(AmSdp &sdp,
                                  const string &, unsigned int)
{
    if(rtp_relay_mode == RTP_Direct) return; // nothing to do

    if(!media_session) {
        // report missing media session (here we get for rtp_relay_mode == RTP_Relay)
        ERROR("BUG: media session is missing, can't update local SDP");
        return; // FIXME: throw an exception here?
    }

    auto atype = dlg->getOutboundAddrType();
    media_session->replaceConnectionAddress(sdp, a_leg, atype);
}

void AmB2BSession::updateLocalBody(AmMimeBody& body,
                                   const string &sip_msg_method,
                                   unsigned int sip_msg_cseq)
{
    AmMimeBody *sdp = body.hasContentType(SIP_APPLICATION_SDP);
    if(!sdp) return;

    if(!sdp->getLen()) {
        sdp->clear();
        return;
    }

    AmSdp parser_sdp;
    if(parser_sdp.parse((const char*)sdp->getPayload())) {
        DBG("SDP parsing failed!");
        return; // FIXME: throw an exception here?
    }

    updateLocalSdp(parser_sdp, sip_msg_method, sip_msg_cseq);

    // regenerate SDP
    string n_body;
    parser_sdp.print(n_body);
    sdp->parse(sdp->getCTStr(), (const unsigned char*)n_body.c_str(), n_body.length());
}

void AmB2BSession::updateUACTransCSeq(unsigned int old_cseq, unsigned int new_cseq)
{
    if(old_cseq == new_cseq)
        return;

    TransMap::iterator t = relayed_req.find(old_cseq);
    if(t != relayed_req.end()) {
        relayed_req[new_cseq] = t->second;
        relayed_req.erase(t);
        DBG("updated relayed_req (UAC trans): CSeq %u -> %u", old_cseq, new_cseq);
    }

    if(est_invite_cseq == old_cseq) {
        est_invite_cseq = new_cseq;
        DBG("updated est_invite_cseq: CSeq %u -> %u", old_cseq, new_cseq);
    }
}

void AmB2BSession::onSipReply(const AmSipRequest& req, const AmSipReply& reply,
                              AmBasicSipDialog::Status old_dlg_status)
{
    TransMap::iterator t = relayed_req.find(reply.cseq);
    bool fwd = (t != relayed_req.end()) && (reply.code != 100);

    DBG("onSipReply: %s -> %i %s (fwd=%s), c-t=%s",
        reply.cseq_method.c_str(), reply.code,reply.reason.c_str(),
        fwd?"true":"false",reply.body.getCTStr().c_str());

    if(!a_leg && reply.cseq_method==SIP_METH_CANCEL && reply.code>=400) {
        DBG("received failure reply for CANCEL on legB. Terminate leg");
        terminateLeg();
        return;
    }

    if(!dlg->getRemoteTag().empty() && dlg->getRemoteTag() != reply.to_tag) {
        DBG("sess %p received %i reply with != to-tag: %s (remote-tag:%s)",
            this, reply.code, reply.to_tag.c_str(),dlg->getRemoteTag().c_str());
        return; // drop packet
    }

    if(((reply.cseq_method == SIP_METH_SUBSCRIBE) ||
       (reply.cseq_method == SIP_METH_NOTIFY) ||
       (reply.cseq_method == SIP_METH_REFER))
       && !subs->onReplyIn(req,reply))
    {
        DBG("subs.onReplyIn returned false");
        return;
    }

    if(fwd) {
        updateRefreshMethod(reply.hdrs);

        AmSipReply n_reply = reply;
        n_reply.cseq = t->second.cseq;

        DBG("relaying B2B SIP reply %u %s", n_reply.code, n_reply.reason.c_str());

        relayEvent(new B2BSipReplyEvent(n_reply, true, t->second.method, getLocalTag()));

        if(reply.code >= 200) {
            if((reply.code < 300) && (t->second.method == SIP_METH_INVITE)) {
                DBG("not removing relayed INVITE transaction yet...");
            } else {
                //grab cseq-mqpping in case of REFER
                if((reply.code < 300) && (reply.cseq_method == SIP_METH_REFER)) {
                    if(subs->subscriptionExists(SingleSubscription::Subscriber,
                       "refer",int2str(reply.cseq)))
                    {
                        // remember mapping for refer event package event-id
                        insertMappedReferID(reply.cseq,t->second.cseq);
                    }
                }
                relayed_req.erase(t);
            }
        }
    } else {
        AmSession::onSipReply(req, reply, old_dlg_status);

        AmSipReply n_reply = reply;
        if(est_invite_cseq == reply.cseq) {
            n_reply.cseq = est_invite_other_cseq;
        } else {
            // correct CSeq for 100 on relayed request (FIXME: why not relayed above?)
            if(t != relayed_req.end()) {
                n_reply.cseq = t->second.cseq;
            } else {
                // the reply here will not have the proper cseq for the other side.
                // We should avoid collisions of CSeqs - painful in comparsions with
                // est_invite_cseq where are compared CSeq numbers in different
                // directions. Under presumption that 0 is not used we can use it
                // as 'unspecified cseq' (according to RFC 3261 this seems to be valid
                // value so it need not to work always)
                n_reply.cseq = 0;
            }
        }
        DBG("relaying B2B SIP reply %u %s", n_reply.code, n_reply.reason.c_str());
        relayEvent(new B2BSipReplyEvent(n_reply, false, reply.cseq_method, getLocalTag()));
    }
}

void AmB2BSession::onReplySent(const AmSipRequest& req, const AmSipReply& reply)
{
    if(((reply.cseq_method == SIP_METH_SUBSCRIBE) ||
       (reply.cseq_method == SIP_METH_NOTIFY) ||
       (reply.cseq_method == SIP_METH_REFER)))
    {
        subs->onReplySent(req,reply);
    }

    if(reply.code >= 200 && reply.cseq_method != SIP_METH_CANCEL) {
        if((req.method == SIP_METH_INVITE) && (reply.code >= 300)) {
            DBG("relayed INVITE failed with %u %s", reply.code, reply.reason.c_str());
        }
        DBG3("recvd_req.erase(<%u,%s>)", req.cseq, req.method.c_str());
        recvd_req.erase(reply.cseq);
    }

    AmSession::onReplySent(req,reply);
}

void AmB2BSession::onInvite2xx(const AmSipReply& reply)
{
    TransMap::iterator it = relayed_req.find(reply.cseq);
    bool req_fwded = it != relayed_req.end();
    if(!req_fwded) {
        DBG("req not fwded");
        AmSession::onInvite2xx(reply);
    } else {
        DBG("no 200 ACK now: waiting for the 200 ACK from the other side...");
    }
}

int AmB2BSession::onSdpCompleted(const AmSdp& local_sdp, const AmSdp& remote_sdp, bool sdp_offer_owner)
{
    CLASS_DBG("AmB2BSession::onSdpCompleted(). %s SDP offer owner",
        sdp_offer_owner ? "local": "remote");

    this->sdp_offer_owner = sdp_offer_owner;

    HoldMethod method;
    if(isHoldRequest(remote_sdp,method)) {
        if(!remote_on_hold) {
            DBG("[%s] got hold request. method: %d",
                getLocalTag().c_str(),method);
            remote_on_hold = true;
            onHoldRequest();
        }
    } else if(remote_on_hold) {
        DBG("[%s] got resume request. method: %d",
            getLocalTag().c_str(),method);
        remote_on_hold = false;
        onResumeRequest();
    }

    if(rtp_relay_mode != RTP_Direct) {
        if(!media_session) {
            // report missing media session (here we get for rtp_relay_mode == RTP_Relay)
            DBG("[%s] media session is missing, can't update SDP",
                dlg?dlg->getLocalTag().c_str():"null");
        } else {
            if(rtp_stream_shared && hasRtpStream() && !media_session->isProcessingMedia()) {
                media_session->setFirstAudioPairStream(
                    a_leg,
                    RTPStream(),
                    local_sdp,
                    remote_sdp);
            }
            DBG("media_session->createUpdateStreams(a_leg, local_sdp, remote_sdp, this); aleg = %d, this = %p",a_leg,this);
            media_session->createUpdateStreams(a_leg, local_sdp, remote_sdp, this, sdp_offer_owner);
        }
    }

    if(hasRtpStream() && RTPStream()->getSdpMediaIndex() >= 0) {
        if(sip_relay_only) {
            DBG("sip_relay_only. skip AmSession::onSdpCompleted");
            return 0;
        }
        if(rtp_stream_shared) {
            DBG("rtp_stream_shared. skip AmSession::onSdpCompleted");
            return 0;
        }
        return AmSession::onSdpCompleted(local_sdp,remote_sdp,sdp_offer_owner);
    }

    return 0;
}

int AmB2BSession::relayEvent(AmEvent* ev)
{
    DBG3("AmB2BSession::relayEvent: to other_id='%s'",
        other_id.c_str());

    if(!other_id.empty()) {
        if(!AmSessionContainer::instance()->postEvent(other_id,ev))
            return -1;
    } else {
        delete ev;
    }
    return 0;
}

void AmB2BSession::onOtherBye(const AmSipRequest& /*req*/)
{
    DBG("onOtherBye()");
    terminateLeg();
}

bool AmB2BSession::onOtherReply(const AmSipReply& reply)
{
    if(reply.code >= 300)
        setStopped();

    return false;
}

void AmB2BSession::terminateLeg()
{
    setStopped();

    clearRtpReceiverRelay();

    dlg->bye("", SIP_FLAGS_VERBATIM,true);
}

void AmB2BSession::terminateOtherLeg()
{
    if(!other_id.empty())
        relayEvent(new B2BEvent(B2BTerminateLeg));
}

void AmB2BSession::onRtpTimeout()
{
    DBG("RTP Timeout, ending other leg");

    terminateOtherLeg();
    AmSession::onRtpTimeout();
}

void AmB2BSession::onSessionTimeout()
{
    DBG("Session Timer: Timeout, ending other leg");

    terminateOtherLeg();
    AmSession::onSessionTimeout();
}

void AmB2BSession::onRemoteDisappeared(const AmSipReply& reply)
{
    DBG("remote unreachable, ending other leg");

    terminateOtherLeg();
    AmSession::onRemoteDisappeared(reply);
}

void AmB2BSession::onNoAck(unsigned int cseq)
{
    DBG("OnNoAck(%u): terminate other leg.",cseq);

    terminateOtherLeg();
    AmSession::onNoAck(cseq);
}

#define skip_line                           \
    while(cmp_body_length && *cmp_body_begin != '\n') {\
        cmp_body_begin++;                   \
        cmp_body_length--;                  \
    }                                       \
    if(cmp_body_length) {                   \
        cmp_body_begin++;                   \
        cmp_body_length--;                  \
    }

bool AmB2BSession::saveSessionDescription(const AmMimeBody& body)
{
    const AmMimeBody* sdp_body = body.hasContentType(SIP_APPLICATION_SDP);
    if(!sdp_body)
        return false;

    DBG("saving session description (%s, %.*s...)",
        sdp_body->getCTStr().c_str(), 50, sdp_body->getPayload());

    established_body = *sdp_body;

    const char* cmp_body_begin = (const char*)sdp_body->getPayload();
    size_t cmp_body_length = sdp_body->getLen();

    if (cmp_body_length) {
        // for SDP, skip v and o line
        // (o might change even if SDP unchanged)
        skip_line;
        skip_line;
    }

    body_hash = hashlittle(cmp_body_begin, cmp_body_length, 0);
    return true;
}

bool AmB2BSession::updateSessionDescription(const AmMimeBody& body)
{
    const AmMimeBody* sdp_body = body.hasContentType(SIP_APPLICATION_SDP);
    if(!sdp_body)
        return false;

    const char* cmp_body_begin = (const char*)sdp_body->getPayload();
    size_t cmp_body_length = sdp_body->getLen();
    if(cmp_body_length) {
        // for SDP, skip v and o line
        // (o might change even if SDP unchanged)
        skip_line;
        skip_line;
    }

    uint32_t new_body_hash = hashlittle(cmp_body_begin, cmp_body_length, 0);

    if(body_hash != new_body_hash) {
        DBG("session description changed - saving (%s, %.*s...)",
            sdp_body->getCTStr().c_str(), 50, sdp_body->getPayload());
        body_hash = new_body_hash;
        established_body = body;
        return true;
    }

    return false;
}

#undef skip_line

int AmB2BSession::sendEstablishedReInvite()
{
    if(established_body.empty()) {
        ERROR("trying to re-INVITE with saved description, but none saved");
        return -1;
    }

    DBG("sending re-INVITE with saved session description");

    try {
        AmMimeBody body(established_body); // contains only SDP
        updateLocalBody(body, sip_method_invite_str, dlg->cseq);
        return dlg->reinvite("", &body, SIP_FLAGS_VERBATIM);
    } catch (const string& s) {
        ERROR("sending established SDP reinvite: %s", s.c_str());
    }
    return -1;
}

bool AmB2BSession::refresh(int /*flags*/)
{
    // no session refresh if not connected
    if(dlg->getStatus() != AmSipDialog::Connected)
        return false;

    DBG(" AmB2BSession::refresh: refreshing session");
    // not in B2B mode
    if(other_id.empty() ||
       // UPDATE as refresh handled like normal session
       refresh_method == REFRESH_UPDATE)
    {
        return AmSession::refresh(SIP_FLAGS_VERBATIM);
    }

    // refresh with re-INVITE
    if(dlg->getUACInvTransPending()) {
        DBG("INVITE transaction pending - not refreshing now");
        return false;
    }

    return sendEstablishedReInvite() == 0;
}

int AmB2BSession::relaySip(const AmSipRequest& req)
{
    AmMimeBody body(req.body);

    if((req.method == SIP_METH_INVITE ||
       req.method == SIP_METH_UPDATE ||
       req.method == SIP_METH_ACK ||
       req.method == SIP_METH_PRACK))
    {
        updateLocalBody(body, req.method, dlg->cseq);
    }

    if(req.method != "ACK") {
        relayed_req[dlg->cseq] = req;

        const string* hdrs = &req.hdrs;
        string m_hdrs;

        // translate RAck for PRACK
        if(req.method == SIP_METH_PRACK && req.rseq) {
            TransMap::iterator t;
            for (t=relayed_req.begin(); t != relayed_req.end(); t++) {
                if (t->second.cseq == req.rack_cseq) {
                    m_hdrs = req.hdrs +
                        SIP_HDR_COLSP(SIP_HDR_RACK) + int2str(req.rseq) +
                        " " + int2str(t->first) + " " + req.rack_method + CRLF;
                    hdrs = &m_hdrs;
                    break;
                }
            }

            if (t==relayed_req.end()) {
                WARN("Transaction with CSeq %d not found for translating RAck cseq, local_tag = %s",
                     req.rack_cseq, dlg->getLocalTag().c_str());
            }
        }

        DBG("relaying SIP request %s %s", req.method.c_str(), req.r_uri.c_str());
        int err = dlg->sendRequest(req.method, &body, *hdrs, SIP_FLAGS_VERBATIM);
        if(err < 0) {
            ERROR("dlg->sendRequest() failed, local_tag = %s",
                  dlg->getLocalTag().c_str());
            return err;
        }

        if((req.method == SIP_METH_INVITE ||
           req.method == SIP_METH_UPDATE) &&
           !req.body.empty())
        {
            saveSessionDescription(req.body);
        }
    } else {
        //its a (200) ACK
        TransMap::iterator t = relayed_req.begin();

        while(t != relayed_req.end()) {
            if(t->second.cseq == req.cseq)
                break;
            t++;
        }

        if(t == relayed_req.end()) {
            DBG("transaction for ACK not found in relayed requests");
            // FIXME: local body (if updated) should be discarded here
            return -1;
        }

        DBG("sending relayed 200 ACK");
        int err = dlg->send_200_ack(t->first, &body,
                                    req.hdrs, SIP_FLAGS_VERBATIM);
        if(err < 0) {
            ERROR("dlg->send_200_ack() failed, local_tag = %s",
                  dlg->getLocalTag().c_str());
            return err;
        }

        if (!req.body.empty() &&
            (t->second.method == SIP_METH_INVITE))
        {
            // delayed SDP negotiation - save SDP
            saveSessionDescription(req.body);
        }

        relayed_req.erase(t);
    }

    return 0;
}

int AmB2BSession::relaySip(const AmSipRequest& orig, const AmSipReply& reply)
{
    const string* hdrs = &reply.hdrs;
    string m_hdrs;
    const string method(orig.method);

    if(reply.rseq != 0) {
        m_hdrs = reply.hdrs +
            SIP_HDR_COLSP(SIP_HDR_RSEQ) + int2str(reply.rseq) + CRLF;
        hdrs = &m_hdrs;
    }

    AmMimeBody body(reply.body);
    if((orig.method == SIP_METH_INVITE ||
       orig.method == SIP_METH_UPDATE ||
       orig.method == SIP_METH_ACK ||
       orig.method == SIP_METH_PRACK))
    {
        updateLocalBody(body, orig.method, orig.cseq);
    }

    DBG("relaying SIP reply %u %s", reply.code, reply.reason.c_str());

    int flags = SIP_FLAGS_VERBATIM;
    if(reply.to_tag.empty())
        flags |= SIP_FLAGS_NOTAG;

    /*int ignore_reply_body = false;
    if(dlg &&
       dlg->getOAState()==AmOfferAnswer::OA_OfferSent &&
       body.hasContentType(SIP_APPLICATION_SDP))
    {
        DBG("got reply %d for %s with unexpected SDP payload. ignore it",
            reply.code, reply.cseq_method.c_str());
        ignore_reply_body = true;
    }*/

    int err = dlg->reply(orig,reply.code,reply.reason, &body, *hdrs, flags);
                         //ignore_reply_body ? NULL : &body, *hdrs, flags);

    if(err < 0) {
        ERROR("dlg->reply() failed");
        return err;
    }

    if((method == SIP_METH_INVITE ||
       method == SIP_METH_UPDATE) &&
       !reply.body.empty())
    {
        saveSessionDescription(reply.body);
    }

    return 0;
}

void AmB2BSession::setRtpRelayMode(RTPRelayMode mode)
{
    DBG("[%s] set RTP relay mode %d",
        getLocalTag().data(), mode);
    rtp_relay_mode = mode;
}

void AmB2BSession::setRtpStreamShare(bool shared)
{
    DBG("%sabled RTP stream sharing",shared?"en":"dis");
    rtp_stream_shared = shared;
}

void AmB2BSession::setRtpInterface(int relay_interface) {
    DBG("setting RTP interface for session '%s' to %i",
        getLocalTag().c_str(), relay_interface);
    rtp_interface = relay_interface;
}

void AmB2BSession::setRtpRelayForceSymmetricRtp(bool force_symmetric)
{
    rtp_relay_force_symmetric_rtp = force_symmetric;
}

void AmB2BSession::setRtpRelayTransparentSeqno(bool transparent)
{
    rtp_relay_transparent_seqno = transparent;
}

void AmB2BSession::setRtpRelayTransparentSSRC(bool transparent)
{
    rtp_relay_transparent_ssrc = transparent;
}

void AmB2BSession::setRtpRelayTimestampAligning(bool enable)
{
    rtp_relay_timestamp_aligning = enable;
}

void AmB2BSession::setIgnoreRelayStreams(bool ignore)
{
    ignore_relay_streams = ignore;
    if(media_session)
        media_session->setIgnoreRelayStreams(ignore_relay_streams);
}

void AmB2BSession::setEnableDtmfTranscoding(bool enable)
{
    enable_dtmf_transcoding = enable;
}

void AmB2BSession::setEnableInboundDtmfFiltering(bool enable)
{
    enable_inbound_dtmf_filtering = enable;
}

void AmB2BSession::setEnableDtmfRtpFiltering(bool enable)
{
    enable_dtmf_rtp_filtering = enable;
}

void AmB2BSession::setEnableDtmfRtpDetection(bool enable)
{
    enable_dtmf_rtp_detection = enable;
}

void AmB2BSession::setEnableRtpPing(bool enable)
{
    rtp_ping = enable;
}

void AmB2BSession::setRtpTimeout(unsigned int timeout)
{
    dead_rtp_time = timeout;
}

void AmB2BSession::setEnableDtmfForceRelay(bool enable)
{
    enable_dtmf_rtp_force_relay = enable;
}

void AmB2BSession::setEnableCNForceRelay(bool enable)
{
    enable_cn_rtp_force_relay = enable;
}

void AmB2BSession::getLowFiPLs(vector<SdpPayload>& lowfi_payloads) const
{
    lowfi_payloads = this->lowfi_payloads;
}

void AmB2BSession::setLowFiPLs(const vector<SdpPayload>& lowfi_payloads)
{
    this->lowfi_payloads = lowfi_payloads;
}

void AmB2BSession::clearRtpReceiverRelay()
{
    switch (rtp_relay_mode) {

    case RTP_Relay:
    case RTP_Transcoding:
        if(media_session) {
            media_session->stop(a_leg);
            media_session->releaseReference();
            media_session = NULL;
        }
        break;

    case RTP_Direct:
        // nothing to do
        break;
    }
}

void AmB2BSession::computeRelayMask(const SdpMedia &m, bool &enable, PayloadMask &mask, PayloadRelayMap& map)
{
    enable = false;

    mask.clear();
    map.clear();

    const AmSdp &other_remote_sdp = media_session->getRemoteSdp(!a_leg);

    DBG("m.payloads.size = %zd",m.payloads.size());
    DBG("other_remote_sdp.media.size = %zd",other_remote_sdp.media.size());

    for(const auto &local_payload: m.payloads) {
        DBG("local_payload = %s %d",local_payload.encoding_name.c_str(), local_payload.payload_type);
        if(local_payload.encoding_name=="telephone-event") {
            //never mark telephone-event for relay
            continue;
        }
        for(auto const &other_remote_media : other_remote_sdp.media) {
            if(other_remote_media.type != m.type) continue; //TODO: use explicit stream index of the other's remote media
            for(const auto &other_remote_payload : other_remote_media.payloads) {
                DBG("other_remote_payload = %s %d",other_remote_payload.encoding_name.c_str(), other_remote_payload.payload_type);
                if(local_payload.payload_type < DYNAMIC_PAYLOAD_TYPE_START) {
                    if(local_payload.payload_type ==  other_remote_payload.payload_type) {
                        CLASS_DBG("mark static payload %d for relay", local_payload.payload_type);
                        mask.set(static_cast<unsigned char>(other_remote_payload.payload_type));
                        enable = true;
                        break;
                    }
                } else if(local_payload.clock_rate == other_remote_payload.clock_rate &&
                          0==strcasecmp(local_payload.encoding_name.c_str(),
                                        other_remote_payload.encoding_name.c_str()))
                {
                    mask.set(static_cast<unsigned char>(other_remote_payload.payload_type));
                    if(other_remote_payload.payload_type != local_payload.payload_type) {
                        map.set(static_cast<unsigned char>(local_payload.payload_type),
                                static_cast<unsigned char>(other_remote_payload.payload_type));
                        CLASS_DBG("mark dynamic payload %d for relay with mapping to %d",
                                  other_remote_payload.payload_type, other_remote_payload.payload_type);
                    } else {
                        CLASS_DBG("mark dynamic payload %d for relay",other_remote_payload.payload_type);
                    }
                    enable = true;
                    break;
                }
            } //for(const auto &other_remote_payload : other_remote_media.payloads)
            break;
        } //for(auto const &other_remote_media : other_remote_sdp.media)
    }
}

void AmB2BSession::onSessionChange(AmB2BSession *new_session)
{
    //DBG("%s(new_session = %p) a_leg = %d",FUNC_NAME,new_session,a_leg);
    if(rtp_stream_shared && (new_session == NULL)) {
        DBG("clear audio on unlink from media session with shared streams");
        clearAudio();
    }
}

// 
// AmB2BCallerSession methods
//

AmB2BCallerSession::AmB2BCallerSession(const string& other_local_tag,
                                       AmSipDialog* p_dlg)
  : AmB2BSession(other_local_tag, p_dlg),
    callee_status(None), sip_relay_early_media_sdp(false)
{
    a_leg = true;
}

AmB2BCallerSession::~AmB2BCallerSession()
{}

void AmB2BCallerSession::set_sip_relay_early_media_sdp(bool r)
{
    sip_relay_early_media_sdp = r;
}

void AmB2BCallerSession::terminateLeg()
{
    AmB2BSession::terminateLeg();
}

void AmB2BCallerSession::terminateOtherLeg()
{
    AmB2BSession::terminateOtherLeg();
    callee_status = None;
}

void AmB2BCallerSession::onB2BEvent(B2BEvent* ev)
{
    bool processed = false;

    if(ev->event_id == B2BSipReply) {
        AmSipReply& reply = ((B2BSipReplyEvent*)ev)->reply;

        if(getOtherId().empty()) {
            //DBG("Discarding B2BSipReply from other leg (other_id empty)");
            DBG("B2BSipReply: other_id empty ("
                "reply code=%i; method=%s; callid=%s; from_tag=%s; "
                "to_tag=%s; cseq=%i)\n",
                reply.code,reply.cseq_method.c_str(),
                reply.callid.c_str(),reply.from_tag.c_str(),
                reply.to_tag.c_str(),reply.cseq);
            //return;
        } else if(getOtherId() != reply.from_tag) { // was: local_tag
            DBG("Dialog mismatch! (oi=%s;ft=%s)",
            getOtherId().c_str(),reply.from_tag.c_str());
            return;
        }

        DBG("%u %s reply received from other leg", reply.code, reply.reason.c_str());

        switch(callee_status) {
        case NoReply:
        case Ringing:
            if(reply.cseq == invite_req.cseq) {
                if(reply.code < 200) {
                    if ((!sip_relay_only) && sip_relay_early_media_sdp &&
                        reply.code>=180 && reply.code<=183 && (!reply.body.empty()))
                    {
                        DBG("sending re-INVITE to caller with early media SDP");
                        if(reinviteCaller(reply)) {
                            ERROR("re-INVITEing caller for early session failed - "
                                  "stopping this and other leg\n");
                            terminateOtherLeg();
                            terminateLeg();
                        }
                    }

                    callee_status = Ringing;
                } else if(reply.code < 300){
                    callee_status  = Connected;
                    DBG("setting callee status to connected");
                    if(!sip_relay_only) {
                        DBG("received 200 class reply to establishing INVITE: "
                            "switching to SIP relay only mode, sending re-INVITE to caller\n");
                        sip_relay_only = true;
                        if(reinviteCaller(reply)) {
                            ERROR("re-INVITEing caller failed - stopping this and other leg");
                            terminateOtherLeg();
                            terminateLeg();
                        }
                    }
                } else {
                    // DBG("received %i from other leg: other_id=%s; reply.local_tag=%s",
                    // reply.code,other_id.c_str(),reply.local_tag.c_str());
                    // TODO: terminated my own leg instead? (+ clear_other())
                    terminateOtherLeg();
                }
                processed = onOtherReply(reply);
            } //if(reply.cseq == invite_req.cseq)
            break;
        default:
            DBG("reply from callee: %u %s",reply.code,reply.reason.c_str());
            break;
        } //switch(callee_status)
    } //if(ev->event_id == B2BSipReply)

    if(!processed)
        AmB2BSession::onB2BEvent(ev);
}

int AmB2BCallerSession::relayEvent(AmEvent* ev)
{
    if(getOtherId().empty() && !getStopped()) {
        bool create_callee = false;
        B2BSipEvent* sip_ev = dynamic_cast<B2BSipEvent*>(ev);
        if(sip_ev && sip_ev->forward)
            create_callee = true;
        else
            create_callee = dynamic_cast<B2BConnectEvent*>(ev) != NULL;

        if(create_callee) {
            createCalleeSession();
            if(getOtherId().length()) {
                MONITORING_LOG(getLocalTag().c_str(), "b2b_leg", getOtherId().c_str());
            }
        }
    }

    return AmB2BSession::relayEvent(ev);
}

void AmB2BCallerSession::onInvite(const AmSipRequest& req)
{
    invite_req = req;
    est_invite_cseq = req.cseq;

    AmB2BSession::onInvite(req);
}

void AmB2BCallerSession::onInvite2xx(const AmSipReply& reply)
{
    invite_req.cseq = reply.cseq;
    est_invite_cseq = reply.cseq;

    AmB2BSession::onInvite2xx(reply);
}

void AmB2BCallerSession::onCancel(const AmSipRequest& /*req*/)
{
    terminateOtherLeg();
    terminateLeg();
}

void AmB2BCallerSession::onSystemEvent(AmSystemEvent* ev)
{
    if(ev->sys_event == AmSystemEvent::ServerShutdown) {
        terminateOtherLeg();
    }

    AmB2BSession::onSystemEvent(ev);
}

void AmB2BCallerSession::onRemoteDisappeared(const AmSipReply& reply)
{
    DBG("remote unreachable, ending B2BUA call");
    clearRtpReceiverRelay();

    AmB2BSession::onRemoteDisappeared(reply);
}

void AmB2BCallerSession::onBye(const AmSipRequest& req)
{
    clearRtpReceiverRelay();
    AmB2BSession::onBye(req);
}

void AmB2BCallerSession::connectCallee(const string& remote_party,
                                       const string& remote_uri,
                                       bool relayed_invite)
{
    if(callee_status != None)
        terminateOtherLeg();

    clear_other();

    if(relayed_invite) {
        // relayed INVITE - we need to add the original INVITE to
        // list of received (relayed) requests
        recvd_req.insert(std::make_pair(invite_req.cseq,invite_req));
        // in SIP relay mode from the beginning
        sip_relay_only = true;
    }

    B2BConnectEvent* ev = new B2BConnectEvent(remote_party,remote_uri);

    ev->body         = invite_req.body;
    ev->hdrs         = invite_req.hdrs;
    ev->relayed_invite = relayed_invite;
    ev->r_cseq       = invite_req.cseq;

    DBG("relaying B2B connect event to %s", remote_uri.c_str());
    relayEvent(ev);
    callee_status = NoReply;
}

int AmB2BCallerSession::reinviteCaller(const AmSipReply& callee_reply)
{
    return dlg->sendRequest(SIP_METH_INVITE,
                            &callee_reply.body,
                            "" /* hdrs */, SIP_FLAGS_VERBATIM);
}

void AmB2BCallerSession::createCalleeSession()
{
    AmB2BCalleeSession* callee_session = newCalleeSession();
    if(NULL == callee_session)
        return;

    AmSipDialog* callee_dlg = callee_session->dlg;

    setOtherId(AmSession::getNewId());

    callee_dlg->setLocalTag(getOtherId());
    if(callee_dlg->getCallid().empty())
        callee_dlg->setCallid(AmSession::getNewId());

    if(callee_dlg->getLocalParty().empty())
        callee_dlg->setLocalParty(dlg->getRemoteParty());
    callee_dlg->setRemoteParty(dlg->getLocalParty());
    callee_dlg->setRemoteUri(dlg->getLocalUri());

    if(AmConfig.log_sessions) {
        INFO("Starting B2B callee session %s",
             callee_session->getLocalTag().c_str());
    }

    MONITORING_LOG4(getOtherId().c_str(),
        "dir",  "out",
        "from", callee_dlg->getLocalParty().c_str(),
        "to",   callee_dlg->getRemoteParty().c_str(),
        "ruri", callee_dlg->getRemoteUri().c_str());

    try {
        initializeRTPRelay(callee_session);
    } catch (...) {
        delete callee_session;
        throw;
    }

    AmSessionContainer* sess_cont = AmSessionContainer::instance();
    sess_cont->addSession(getOtherId(),callee_session);

    callee_session->start();
}

AmB2BCalleeSession* AmB2BCallerSession::newCalleeSession()
{
    return new AmB2BCalleeSession(this);
}

void AmB2BSession::setMediaSession(AmB2BMedia *new_session) 
{
    // FIXME: ignore old media_session? can it be already set here?
    if(media_session) ERROR("BUG: non-empty media session overwritten");
        media_session = new_session;
    if(media_session)
        media_session->addReference(); // new reference for me
    DBG("[%s|%s] B2B media session was set to %p",
        getLocalTag().c_str(),getOtherId().c_str(), media_session);
}

void AmB2BCallerSession::initializeRTPRelay(AmB2BCalleeSession* callee_session)
{
    if (!callee_session) return;

    callee_session->setRtpRelayMode(rtp_relay_mode);
    callee_session->setEnableDtmfTranscoding(enable_dtmf_transcoding);
    callee_session->setEnableDtmfRtpFiltering(enable_dtmf_rtp_filtering);
    callee_session->setEnableDtmfRtpDetection(enable_dtmf_rtp_detection);
    callee_session->setLowFiPLs(lowfi_payloads);
    callee_session->setRtpRelayTimestampAligning(rtp_relay_timestamp_aligning);

    if ((rtp_relay_mode == RTP_Relay) || (rtp_relay_mode == RTP_Transcoding)) {
        setMediaSession(new AmB2BMedia(this, callee_session)); // we need to add our reference
        callee_session->setMediaSession(getMediaSession());
    }
}

AmB2BCalleeSession::AmB2BCalleeSession(const string& other_local_tag)
  : AmB2BSession(other_local_tag)
{
    a_leg = false;
}

AmB2BCalleeSession::AmB2BCalleeSession(const AmB2BCallerSession* caller)
  : AmB2BSession(caller->getLocalTag())
{
    a_leg = false;
    rtp_relay_mode = caller->getRtpRelayMode();
    rtp_relay_force_symmetric_rtp = caller->getRtpRelayForceSymmetricRtp();
}

AmB2BCalleeSession::~AmB2BCalleeSession()
{}

void AmB2BCalleeSession::onB2BEvent(B2BEvent* ev)
{
    if(ev->event_id == B2BConnectLeg) {
        B2BConnectEvent* co_ev = dynamic_cast<B2BConnectEvent*>(ev);
        if(!co_ev)
            return;

        MONITORING_LOG3(getLocalTag().c_str(),
            "b2b_leg", getOtherId().c_str(),
            "to", co_ev->remote_party.c_str(),
            "ruri", co_ev->remote_uri.c_str());


        dlg->setRemoteParty(co_ev->remote_party);
        dlg->setRemoteUri(co_ev->remote_uri);

        if(co_ev->relayed_invite) {
            AmSipRequest fake_req;
            fake_req.method = SIP_METH_INVITE;
            fake_req.cseq = co_ev->r_cseq;
            relayed_req[dlg->cseq] = fake_req;
        }

        AmMimeBody body(co_ev->body);
        try {
            updateLocalBody(body, sip_method_invite_str, dlg->cseq);
        } catch (const string& s) {
            relayError(SIP_METH_INVITE, co_ev->r_cseq, co_ev->relayed_invite, 500,
                       SIP_REPLY_SERVER_INTERNAL_ERROR);
            throw;
        }

        int res = dlg->sendRequest(SIP_METH_INVITE, &body,
                                   co_ev->hdrs, SIP_FLAGS_VERBATIM);
        if(res < 0) {
            DBG("sending INVITE failed, relaying back error reply");
            relayError(SIP_METH_INVITE, co_ev->r_cseq, co_ev->relayed_invite, res);

            if(co_ev->relayed_invite)
                relayed_req.erase(dlg->cseq);

            setStopped();
            return;
        }

        saveSessionDescription(co_ev->body);

        // save CSeq of establising INVITE
        est_invite_cseq = dlg->cseq - 1;
        est_invite_other_cseq = co_ev->r_cseq;

        return;
    } //if(ev->event_id == B2BConnectLeg)

    AmB2BSession::onB2BEvent(ev);
}

bool isHoldRequest(const AmSdp &sdp, HoldMethod &method)
{
    // set defaults from session parameters and attributes
    // inactive/sendonly/sendrecv/recvonly may be given as session attributes,
    // connection can be given for session as well
    bool connection_active = connectionActive(sdp.conn, false /* empty connection like inactive? */);
    MediaActivity session_activity = getMediaActivity(sdp.attributes, Sendrecv);

    for(std::vector<SdpMedia>::const_iterator m = sdp.media.begin();
        m != sdp.media.end(); ++m)
    {
        // ignore zeroed connection hold for ICE. rfc5245#section-9.1.1.1
        if(m->is_ice == false) {
            if(m->port == 0) continue; // this stream is disabled, handle like inactive (?)

            if(!connectionActive(m->conn, connection_active)) {
                method = ZeroedConnection;
                continue;
            }
        }

        switch(getMediaActivity(*m, session_activity)) {
        case Sendonly:
            method = SendonlyStream;
            continue;

        case Inactive:
            method = InactiveStream;
            continue;

        case Recvonly: // ?
        case Sendrecv:
            return false; // media stream is active
        }
    }

    if(sdp.media.empty()) {
        // no streams in the SDP, needed to set method somehow
        if (!connection_active) method = ZeroedConnection;
        else {
            switch (session_activity) {
            case Sendonly:
                method = SendonlyStream;
                break;

            case Inactive:
                method = InactiveStream;
                break;

            case Recvonly:
            case Sendrecv:
                method = InactiveStream; // well, no stream is something like InactiveStream, isn't it?
                break;
            }
        }
    }

    return true; // no active stream was found
}
/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */
