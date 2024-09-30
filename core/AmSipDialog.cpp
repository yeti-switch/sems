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

#include "AmSipDialog.h"
#include "AmSession.h"
#include "AmUtils.h"
#include "SipCtrlInterface.h"
#include "AmB2BMedia.h" // just because of statistics

static void addTranscoderStats(string &hdrs)
{
    // add transcoder statistics into request/reply headers
    if (!AmConfig.transcoder_out_stats_hdr.empty()) {
        string usage;
        B2BMediaStatistics::instance()->reportCodecWriteUsage(usage);

        hdrs += AmConfig.transcoder_out_stats_hdr + ": ";
        hdrs += usage;
        hdrs += CRLF;
    }

    if (!AmConfig.transcoder_in_stats_hdr.empty()) {
        string usage;
        B2BMediaStatistics::instance()->reportCodecReadUsage(usage);

        hdrs += AmConfig.transcoder_in_stats_hdr + ": ";
        hdrs += usage;
        hdrs += CRLF;
    }
}

AmSipDialog::AmSipDialog(AmSipDialogEventHandler* h)
  : AmBasicSipDialog(h),
    pending_invites(0),
    pending_updates(0),
    cancel_pending(false),
    cancel_final(false),
    sdp_local(),
    sdp_remote(),
    early_session_started(false),
    session_started(false),
    oa(this),
    offeranswer_enabled(true),
    rel100(this, h)
{}

AmSipDialog::~AmSipDialog()
{}

bool AmSipDialog::onRxReqSanity(const AmSipRequest& req)
{
    if (req.method == SIP_METH_ACK) {
        if (onRxReqStatus(req) && hdl)
            hdl->onSipRequest(req);
        return false;
    }

    if (req.method == SIP_METH_CANCEL) {
        if (uas_trans.find(req.cseq) == uas_trans.end()) {
            reply_error(req,481,SIP_REPLY_NOT_EXIST,string(),logger);
            return false;
        }

        if(onRxReqStatus(req) && hdl)
            hdl->onSipRequest(req);

        return false;
    }

    if (!AmBasicSipDialog::onRxReqSanity(req))
        return false;

    //INVITE: https://www.rfc-editor.org/rfc/rfc3261.html#section-14.2
    //UPDATE: https://www.rfc-editor.org/rfc/rfc3311#section-5.2
    bool invite = (req.method == SIP_METH_INVITE);
    if (invite || (req.method == SIP_METH_UPDATE)) {

        bool pending = invite ? pending_invites : pending_updates;

        DBG("AmSipDialog::onRxReqSanity: %s, pending %d",
            invite ? "INVITE" : "UPDATE", pending);

        //check for pending UAS transactions
        if(pending) {
            reply_error(
                req, 491, SIP_REPLY_PENDING,
                SIP_HDR_COLSP(SIP_HDR_RETRY_AFTER)
                    + int2str(get_random() % 10) + CRLF,
                logger);
            return false;
        }

        //check for OA state
        bool has_sdp = (req.body.hasContentType(SIP_APPLICATION_SDP) != nullptr);
        if (offeranswer_enabled &&
            (invite || has_sdp)) //skip OA checking for UPDATE without SDP
        {
            // not sure this is needed here: could be in AmOfferAnswer as well
            switch (oa.getState()) {
            case AmOfferAnswer::OA_OfferSent:
            case AmOfferAnswer::OA_OfferRecved:
                reply_error(
                    req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR,
                    SIP_HDR_COLSP(SIP_HDR_RETRY_AFTER)
                        + int2str(get_random() % 10) + CRLF,
                    logger);
                return false;
            default: break;
            }
        }

        if (invite)
            pending_invites++;
        else
            pending_updates++;
    }

    return rel100.onRequestIn(req);
}

bool AmSipDialog::onRxReqStatus(const AmSipRequest& req)
{
    switch(status) {
    case Disconnected:
        if (req.method == SIP_METH_INVITE)
            setStatus(Trying);
        break;
    case Connected:
        if (req.method == SIP_METH_BYE)
            setStatus(Disconnecting);
        break;
    case Trying:
    case Proceeding:
    case Early:
        if (req.method == SIP_METH_BYE)
            setStatus(Disconnecting);
        else if (req.method == SIP_METH_CANCEL) {
            setStatus(Cancelling);
            reply(req,200,"OK");
        }
        break;
    default: break;
    } //switch(status)

    bool cont = true;
    if (offeranswer_enabled) {
        cont = (oa.onRequestIn(req) == 0);
    }

    return cont;
}

int AmSipDialog::onSdpCompleted(bool sdp_offer_owner)
{
    if (!hdl) return 0;

    int ret = ((AmSipDialogEventHandler*)hdl)->
        onSdpCompleted(oa.getLocalSdp(), oa.getRemoteSdp(), sdp_offer_owner);

    if (!ret) {
        sdp_local = oa.getLocalSdp();
        sdp_remote = oa.getRemoteSdp();

        if ((getStatus() == Early) && !early_session_started) {
            ((AmSipDialogEventHandler*)hdl)->onEarlySessionStart();
            early_session_started = true;
        }

        if ((getStatus() == Connected) && !session_started) {
            ((AmSipDialogEventHandler*)hdl)->onSessionStart();
            session_started = true;
        }
    } else {
        oa.clear();
    }

    return ret;
}

bool AmSipDialog::getSdpOffer(AmSdp& offer)
{
    if (!hdl) return false;
    return ((AmSipDialogEventHandler*)hdl)->getSdpOffer(offer);
}

bool AmSipDialog::getSdpAnswer(const AmSdp& offer, AmSdp& answer)
{
    if (!hdl) return false;
    return ((AmSipDialogEventHandler*)hdl)->getSdpAnswer(offer,answer);
}

AmOfferAnswer::OAState AmSipDialog::getOAState()
{
    return oa.getState();
}

void AmSipDialog::setOAState(AmOfferAnswer::OAState n_st)
{
    oa.setState(n_st);
}

void AmSipDialog::setRel100State(Am100rel::State rel100_state)
{
    DBG("setting 100rel state for '%s' to %i", local_tag.c_str(), rel100_state);
    rel100.setState(rel100_state);
}

void AmSipDialog::setRel100Handler(AmSipDialogEventHandler* h)
{
    rel100.setHandler(h);
}

void AmSipDialog::setOAEnabled(bool oa_enabled)
{
    DBG("%sabling offer_answer on SIP dialog '%s'",
        oa_enabled?"en":"dis", local_tag.c_str());
    offeranswer_enabled = oa_enabled;
}

unsigned int AmSipDialog::getOAcseq()
{
    return oa.getCseq();
}

bool AmSipDialog::isOASubsequentSDP(unsigned int sip_msg_cseq, const string &sip_msg_method)
{
    return oa.isSubsequentSDP(sip_msg_cseq, sip_msg_method);
}

int AmSipDialog::onTxRequest(AmSipRequest& req, int& flags)
{
    rel100.onRequestOut(req);

    int res = 0;
    if (offeranswer_enabled) {
        if(res = oa.onRequestOut(req); res < 0)
            return res;
    }

    if (AmBasicSipDialog::onTxRequest(req,flags) < 0)
        return -1;

    // add transcoder statistics into request headers
    addTranscoderStats(req.hdrs);

    if ((req.method == SIP_METH_INVITE) && (status == Disconnected)) {
        setStatus(Trying);
    }
    else if ((req.method == SIP_METH_BYE) && (status != Disconnecting)) {
        setStatus(Disconnecting);
    }

    if ((req.method == SIP_METH_BYE) || (req.method == SIP_METH_CANCEL)) {
        flags |= SIP_FLAGS_NOCONTACT;
    }

    return 0;
}

// UAS behavior for locally sent replies
int AmSipDialog::onTxReply(const AmSipRequest& req, AmSipReply& reply, int& flags)
{
    if (offeranswer_enabled) {
        if (oa.onReplyOut(reply) < 0)
            return -1;
    }

    rel100.onReplyOut(reply);

    // update Dialog status
    switch(status) {

    case Connected:
    case Disconnected:
        break;
    case Cancelling:
        if ((reply.cseq_method == SIP_METH_INVITE) &&
            (reply.code < 200))
        {
            // refuse local provisional replies
            // when state is Cancelling
            ERROR("refuse local provisional replies when state is Cancelling");
            return -1;
        }
        // else continue with final
        // reply processing
    case Proceeding:
    case Trying:
    case Early:
        if (reply.cseq_method == SIP_METH_INVITE) {
            if (reply.code < 200) {
                setStatus(Early);
            }
            else if (reply.code < 300)
                setStatus(Connected);
            else
                drop();
        }
        break;

    case Disconnecting:
        if (reply.cseq_method == SIP_METH_BYE) {
            // Only reason for refusing a BYE:
            //  authentication (NYI at this place)
            // Also: we should not send provisionnal replies to a BYE
            if (reply.code >= 200)
                drop();
        }
        break;

    default:
        assert(0);
        break;
    } //switch(status)

    // add transcoder statistics into reply headers
    addTranscoderStats(reply.hdrs);

    // target-refresh requests and their replies need to contain Contact (1xx
    // replies only those establishing dialog, take care about them?)
    if (reply.cseq_method != SIP_METH_INVITE &&
        reply.cseq_method != SIP_METH_UPDATE)
    {
        flags |= SIP_FLAGS_NOCONTACT;
    }

    return AmBasicSipDialog::onTxReply(req,reply,flags);
}

void AmSipDialog::onReplyTxed(const AmSipRequest& req, const AmSipReply& reply)
{
    AmBasicSipDialog::onReplyTxed(req,reply);

    if (offeranswer_enabled) {
        oa.onReplySent(reply);
    }

    if (reply.code >= 200) {
        if (reply.cseq_method == SIP_METH_INVITE)
            pending_invites--;
        else if (reply.cseq_method == SIP_METH_UPDATE)
            pending_updates--;
    }
}

void AmSipDialog::onRequestTxed(const AmSipRequest& req)
{
    AmBasicSipDialog::onRequestTxed(req);

    if (offeranswer_enabled) {
        oa.onRequestSent(req);
    }
}

bool AmSipDialog::onRxReplySanity(const AmSipReply& reply)
{
    if (!getRemoteTag().empty()
        && reply.to_tag != getRemoteTag())
    {
        if (status == Early || status == Cancelling) {
            if (reply.code < 200 && !reply.to_tag.empty()) {
                return false;// DROP
            }
            //never drop responses for BYE and CANCEL to avoid sessions hangs
        } else if(reply.cseq_method == SIP_METH_BYE
            || reply.cseq_method == SIP_METH_CANCEL)
        {
            DBG("[%s] reply for %s '%d %s' is not matched with dialog. but matched with transaction. process it",
                local_tag.c_str(),
                reply.cseq_method.c_str(),reply.code,reply.reason.c_str());
            //PASS
        } else {
            // DROP
            return false;
        }
    }

    return true;
}

bool AmSipDialog::onRxReplyStatus(const AmSipReply& reply)
{
    // rfc3261 12.1
    // Dialog established only by 101-199 or 2xx
    // responses to INVITE

    if(reply.cseq_method == SIP_METH_INVITE) {

        switch(status) {
        case Trying:
        case Proceeding:
        if (reply.code < 200) {
            if (reply.code == 100 || reply.to_tag.empty()) {
                setStatus(Proceeding);
            } else {
                setStatus(Early);
                setRemoteTag(reply.to_tag);
                setRouteSet(reply.route);
            }
        } else if (reply.code < 300) {
            setStatus(Connected);
            setRouteSet(reply.route);
            if (reply.to_tag.empty()) {
                DBG("received 2xx reply without to-tag "
                    "(callid=%s): sending BYE",
                    reply.callid.c_str());
                send_200_ack(reply.cseq);
                sendRequest(SIP_METH_BYE);
            } else {
                setRemoteTag(reply.to_tag);
            }
        }

        if (reply.code >= 300) {// error reply
            drop();
        } else if (cancel_pending) {
            cancel_pending = false;
            bye();
        }
        break; //Trying | Proceeding

        case Early:
            if (reply.code < 200) {
                DBG("ignoring provisional reply in Early state");
            } else if (reply.code < 300) {
                setStatus(Connected);
                setRouteSet(reply.route);
                if (reply.to_tag.empty()) {
                    DBG("received 2xx reply without to-tag "
                        "(callid=%s): sending BYE",
                        reply.callid.c_str());
                    sendRequest(SIP_METH_BYE);
                } else {
                    setRemoteTag(reply.to_tag);
                }
            } else { // error reply
                drop();
            }
        break; //Early

        case Cancelling:
            if (reply.code < 200) {
                DBG("ignoring provisional reply in Cancelling state");
                if (!reply.to_tag.empty())
                    setRemoteTag(reply.to_tag);
            } else if (reply.code >= 300) {
                // CANCEL accepted
                DBG("CANCEL accepted, status -> Disconnected");
                drop();
            } else if (reply.code < 300) {
                // CANCEL rejected
                DBG("CANCEL rejected/too late. connect");
                setStatus(Connected);
                setRouteSet(reply.route);
                if (reply.to_tag.empty()) {
                    DBG("received 2xx reply without to-tag "
                        "(callid=%s): sending BYE",
                        reply.callid.c_str());
                    bye();
                } else {
                    setRemoteTag(reply.to_tag);
                }

                if (cancel_final) {
                    DBG("CANCEL rejected/too late. final cancelling. sending BYE");
                    bye();
                }
            }
            break; //Cancelling

        //case Connected: // late 200...
        //  TODO: if reply.to_tag != getRemoteTag()
        //        -> ACK + BYE (+absorb answer)

        default: break;
        } //switch(status)
    } //reply cseq INVITE

    if (status == Disconnecting) {
        DBG("?Disconnecting?: cseq_method = %s; code = %i",
            reply.cseq_method.c_str(), reply.code);

        if ((reply.cseq_method == SIP_METH_BYE) && (reply.code >= 200)) {
            //TODO: support the auth case here (401/403)
            drop();
        }
    }

    if (offeranswer_enabled) {
        oa.onReplyIn(reply);
    }

    bool cont = true;
    if ((reply.code >= 200) && (reply.code < 300) &&
        (reply.cseq_method == SIP_METH_INVITE))
    {
        if (hdl) ((AmSipDialogEventHandler*)hdl)->onInvite2xx(reply);
    } else {
        cont = AmBasicSipDialog::onRxReplyStatus(reply);
    }

    return cont && rel100.onReplyIn(reply);
}

void AmSipDialog::uasTimeout(AmSipTimeoutEvent* to_ev)
{
    assert(to_ev);

    switch(to_ev->type) {
    case AmSipTimeoutEvent::noACK:
        DBG("Timeout: missing ACK");
        if (offeranswer_enabled) {
            oa.onNoAck(to_ev->cseq);
        }
        if (hdl) ((AmSipDialogEventHandler*)hdl)->onNoAck(to_ev->cseq);
        break;
    case AmSipTimeoutEvent::noPRACK:
        DBG("Timeout: missing PRACK");
        rel100.onTimeout(to_ev->req, to_ev->rpl);
        break;
    case AmSipTimeoutEvent::_noEv:
    default:
        break;
    };

    to_ev->processed = true;
}

bool AmSipDialog::checkReply100rel(AmSipReply& reply)
{
    return rel100.checkReply(reply);
}

bool AmSipDialog::getUACInvTransPending()
{
    for (auto &t: uac_trans)
        if (t.second.method == SIP_METH_INVITE)
            return true;
    return false;
}

AmSipRequest* AmSipDialog::getUASPendingInv()
{
    for (auto &t: uas_trans)
        if (t.second.method == SIP_METH_INVITE)
            return &(t.second);
    return nullptr;
}

int AmSipDialog::bye(const string& hdrs, int flags, bool final)
{
    switch (status) {
    case Disconnecting:
    case Connected: {
        //finish INVITE UAC transactions before sending BYE
        vector<unsigned int> ack_trans;
        for (const auto &t: uac_trans)
            if (t.second.method == SIP_METH_INVITE)
                ack_trans.push_back(t.second.cseq);
        for (const auto &cseq: ack_trans)
            send_200_ack(cseq);

        //terminate UAS transactions
        if (final) {
            int code;
            const char *reason;
            while(!uas_trans.empty()) {
                const auto &t = uas_trans.begin();
                int req_cseq = t->first;
                const auto &req = t->second;

                if (req.method == SIP_METH_BYE) {
                    code = 200;
                    reason = "OK";
                } else {
                    code = 481;
                    reason = SIP_REPLY_NOT_EXIST;
                }

                CLASS_DBG("bye(): terminate UAS %s/%d with %d %s",
                    req.method.data(), req_cseq,
                    code, reason);

                reply(req, code, reason);
                uas_trans.erase(req_cseq);
            }
        }

        //send BYE if Connected
        if (status != Disconnecting) {
            int ret = sendRequest(SIP_METH_BYE, NULL, hdrs, flags);
            drop();
            return ret;
        } else {
            return 0;
        }
    }
    case Trying:
    case Proceeding:
    case Early:
        if (getUACInvTransPending()) {
            return cancel(final,hdrs);
        } else {
            for (TransMap::iterator it=uas_trans.begin();
                 it != uas_trans.end(); it++)
            {
                if (it->second.method == SIP_METH_INVITE) {
                    // let quit this call by sending final reply
                    return reply(
                        it->second,
                        487,"Request terminated",NULL,hdrs);
                }
            }
            // missing AmSipRequest to be able
            // to send the reply on behalf of the app.
            DBG("[%s] ignoring bye() in %s state: "
                "no UAC transaction to cancel or UAS transaction to reply.",
                local_tag.c_str(),
                getStatusStr());
            drop();
        }
        return 0;
    case Cancelling:
        for (TransMap::iterator it=uas_trans.begin();
            it != uas_trans.end(); it++)
        {
            if (it->second.method == SIP_METH_INVITE) {
                // let's quit this call by sending final reply
                return reply(it->second, 487,"Request terminated",NULL,hdrs);
            }
        }
        // missing AmSipRequest to be able
        // to send the reply on behalf of the app.
        DBG("[%s] ignoring bye() in %s state: no UAS transaction to reply",
            local_tag.c_str(),getStatusStr());
        drop();

        return 0;
    default:
        DBG("bye(): we are not connected "
            "(status=%s). do nothing!",
            getStatusStr());
        return 0;
    } //switch(status)
}

int AmSipDialog::reinvite(
    const string& hdrs,
    const AmMimeBody* body,
    int flags)
{
    if (getStatus() == Connected) {
        return sendRequest(SIP_METH_INVITE, body, hdrs, flags);
    }
    else {
        DBG("reinvite(): we are not connected "
            "(status=%s). do nothing!",
            getStatusStr());
    }

    return -1;
}

int AmSipDialog::invite(const string& hdrs, const AmMimeBody* body)
{
    if (getStatus() == Disconnected) {
        int res = sendRequest(SIP_METH_INVITE, body, hdrs);
        DBG("TODO: is status already 'trying'? status=%s",
            getStatusStr());
        //status = Trying;
        return res;
    }
    else {
        DBG("invite(): we are already connected "
            "(status=%s). do nothing!",
            getStatusStr());
    }

    return -1;
}

int AmSipDialog::update(const AmMimeBody* body, const string &hdrs)
{
    switch (getStatus()) {
    case Connected://if Connected, we should send a re-INVITE instead...
        DBG("re-INVITE should be used instead (see RFC3311, section 5.1)");
    case Trying:
    case Proceeding:
    case Early:
        return sendRequest(SIP_METH_UPDATE, body, hdrs);
    case Cancelling:
    case Disconnected:
    case Disconnecting:
    default:
        DBG("update(): dialog not connected "
        "(status=%s). do nothing!",
        getStatusStr());
    }

    return -1;
}

int AmSipDialog::refer(
    const string& refer_to,
    int expires,
    const string& referred_by)
{
    if (getStatus() == Connected) {
        string hdrs = SIP_HDR_COLSP(SIP_HDR_REFER_TO) + refer_to + CRLF;
        if (expires>=0)
            hdrs+= SIP_HDR_COLSP(SIP_HDR_EXPIRES) + int2str(expires) + CRLF;
        if (!referred_by.empty())
            hdrs+= SIP_HDR_COLSP(SIP_HDR_REFERRED_BY) + referred_by + CRLF;
        return sendRequest("REFER", NULL, hdrs);
    }
    else {
        DBG("refer(): we are not Connected."
            "(status=%s). do nothing!",
            getStatusStr());

        return 0;
    }
}

int AmSipDialog::info(const string& hdrs, const AmMimeBody* body)
{
    if (getStatus() == Connected) {
        return sendRequest("INFO", body, hdrs);
    } else {
        DBG("info(): we are not Connected."
            "(status=%s). do nothing!",
            getStatusStr());
        return 0;
    }
}

// proprietary
int AmSipDialog::transfer(const string& target)
{
    if (getStatus() == Connected) {

        setStatus(Disconnecting);

        string hdrs = "";
        AmSipDialog tmp_d(*this);
        tmp_d.route = "";
        // TODO!!!
        //tmp_d.contact_uri = SIP_HDR_COLSP(SIP_HDR_CONTACT)
        //  "<" + tmp_d.remote_uri + ">" CRLF;
        tmp_d.remote_uri = target;

        string r_set;
        if (!route.empty()) {
            hdrs = PARAM_HDR ": " "Transfer-RR=\"" + route + "\""+CRLF;
        }

        int ret = tmp_d.sendRequest("REFER",NULL,hdrs);
        if (!ret) {
            uac_trans.insert(tmp_d.uac_trans.begin(), tmp_d.uac_trans.end());
            cseq = tmp_d.cseq;
        }
        return ret;
    }

    DBG("transfer(): we are not connected "
        "(status=%i). do nothing!",
        status);

    return 0;
}

int AmSipDialog::prack(
    const AmSipReply &reply1xx,
    const AmMimeBody* body,
    const string &hdrs)
{
    switch (getStatus()) {
    case Trying:
    case Proceeding:
    case Cancelling:
    case Early:
    case Connected:
        break;
    case Disconnected:
    case Disconnecting:
        ERROR("can not send PRACK while dialog is in state '%d'.", status);
        return -1;
    default:
        ERROR("BUG: unexpected dialog state '%d'.", status);
        return -1;
    }

    string h = hdrs +
        SIP_HDR_COLSP(SIP_HDR_RACK) +
        int2str(reply1xx.rseq) + " " +
        int2str(reply1xx.cseq) + " " +
        reply1xx.cseq_method + CRLF;

    return sendRequest(SIP_METH_PRACK, body, h);
}

int AmSipDialog::cancel(bool final, const string& hdrs)
{
    for (TransMap::reverse_iterator t = uac_trans.rbegin();
        t != uac_trans.rend(); t++)
    {
        if (t->second.method == SIP_METH_INVITE) {
            cancel_final |= final;
            switch(getStatus()) {
            case Trying:
                cancel_pending = true;
                if (hdrs.length()) t->second.hdrs+=hdrs;
                return 0;
            case Cancelling:
                ERROR("INVITE transaction has already been cancelled");
                return -1;
            default:
                setStatus(Cancelling);
                return SipCtrlInterface::cancel(
                    &t->second.tt, local_tag,
                    t->first, AmConfig.max_forwards,
                    t->second.hdrs+hdrs, getRoute(true));
            } //switch(getStatus())
        }
    }
    ERROR("could not find INVITE transaction to cancel");
    return -1;
}

int AmSipDialog::drop()
{
    setStatus(Disconnected);
    remote_tag.clear();
    return 1;
}

int AmSipDialog::send_200_ack(
    unsigned int inv_cseq,
    const AmMimeBody* body,
    const string& hdrs,
    int flags)
{
    // TODO: implement missing pieces from RFC 3261:
    // "The ACK MUST contain the same credentials as the INVITE.  If
    // the 2xx contains an offer (based on the rules above), the ACK MUST
    // carry an answer in its body.  If the offer in the 2xx response is not
    // acceptable, the UAC core MUST generate a valid answer in the ACK and
    // then send a BYE immediately."

    TransMap::iterator inv_it = uac_trans.find(inv_cseq);
    if (inv_it == uac_trans.end()) {
        ERROR("trying to ACK a non-existing transaction (cseq=%i;local_tag=%s)",
            inv_cseq,local_tag.c_str());
        return -1;
    }

    AmSipRequest req;

    req.method = SIP_METH_ACK;
    req.r_uri = remote_uri;

    req.from = SIP_HDR_COLSP(SIP_HDR_FROM) + local_party;
    if (!ext_local_tag.empty())
        req.from += ";tag=" + ext_local_tag;
    else if (!local_tag.empty())
        req.from += ";tag=" + local_tag;

    req.to = SIP_HDR_COLSP(SIP_HDR_TO) + remote_party;
    if (!remote_tag.empty())
        req.to += ";tag=" + remote_tag;

    req.cseq = inv_cseq;// should be the same as the INVITE
    req.callid = callid;
    req.contact = getContactHdr();

    req.route = getRoute();

    req.max_forwards = inv_it->second.max_forwards;

    if (body != NULL)
        req.body = *body;

    if (onTxRequest(req,flags) < 0)
        return -1;

    if (!(flags&SIP_FLAGS_VERBATIM)) {
        AmLcConfig::instance().addSignatureHdr(req);
    }

    sip_target_set* targets_set = new sip_target_set((dns_priority)getResolvePriority());
    int res = SipCtrlInterface::send(
        req, local_tag,
        remote_tag.empty() || !next_hop_1st_req ? next_hop : "",
        outbound_interface, 0, targets_set, logger, sensor);

    if (res)
        return res;

    onRequestTxed(req);

    return 0;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */
