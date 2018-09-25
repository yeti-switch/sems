#include "Am100rel.h"
#include "AmLcConfig.h"

#include "AmUtils.h"
#include "AmSipHeaders.h"
#include "AmSession.h"
#include "AmSessionContainer.h"

#include "log.h"

Am100rel::Am100rel(AmSipDialog* dlg, AmSipDialogEventHandler* hdl)
  : dlg(dlg), hdl(hdl),
    rseq(0), rseq_1st(0), rseq_confirmed(false),
    initial_state(AmConfig_.rel100),
    uac_state(AmConfig_.rel100),
    uas_state(AmConfig_.rel100)
{
  // if (reliable_1xx)
  //   rseq = 0;
}

int  Am100rel::onRequestIn(const AmSipRequest& req)
{
    if (uas_state == REL100_IGNORED)
        return 1;

  /* activate the 100rel, if needed */
  if (req.method == SIP_METH_INVITE) {
        switch(uas_state) {
        case REL100_SUPPORTED: /* if support is on, enforce if asked by UAC */
        case REL100_SUPPORTED_NOT_ANNOUNCED:
            if (key_in_list(getHeader(req.hdrs, SIP_HDR_SUPPORTED, SIP_HDR_SUPPORTED_COMPACT),
                            SIP_EXT_100REL) ||
               key_in_list(getHeader(req.hdrs, SIP_HDR_REQUIRE),
                           SIP_EXT_100REL))
            {
                uas_state = REL100_REQUIRE;
                DBG(SIP_EXT_100REL " now active for callid: %s",req.callid.c_str());
            }
            break;
        case REL100_REQUIRE: /* if support is required, reject if UAC doesn't */
            if (!(key_in_list(getHeader(req.hdrs,SIP_HDR_SUPPORTED, SIP_HDR_SUPPORTED_COMPACT),
                              SIP_EXT_100REL) ||
                key_in_list(getHeader(req.hdrs, SIP_HDR_REQUIRE),
                            SIP_EXT_100REL)))
            {
                ERROR("'" SIP_EXT_100REL "' extension required, but not advertised"
                      " by peer. callid: %s",req.callid.c_str());
                AmBasicSipDialog::reply_error(
                    req, 421, SIP_REPLY_EXTENSION_REQUIRED,
                    SIP_HDR_COLSP(SIP_HDR_REQUIRE) SIP_EXT_100REL CRLF,
                    dlg->getMsgLogger());
                if (hdl) hdl->onFailure();
                return 0; // has been replied
            }
            break; // 100rel required
        case REL100_DISABLED:
            // TODO: shouldn't this be part of a more general check in SEMS?
            if (key_in_list(getHeader(req.hdrs,SIP_HDR_REQUIRE),SIP_EXT_100REL)) {
                AmBasicSipDialog::reply_error(
                    req, 420, SIP_REPLY_BAD_EXTENSION,
                    SIP_HDR_COLSP(SIP_HDR_UNSUPPORTED) SIP_EXT_100REL CRLF,
                    dlg->getMsgLogger());
                if (hdl) hdl->onFailure();
                return 0; // has been replied
            }
            break;
        default:
            ERROR("BUG: unexpected value `%d' for '" SIP_EXT_100REL "' switch. callid: %s",
                  uas_state,req.callid.c_str());
#ifndef NDEBUG
            abort();
#endif
        } // switch reliable_1xx

    } else if (req.method == SIP_METH_PRACK) {
        if (uas_state != REL100_REQUIRE) {
            WARN("unexpected PRACK received while " SIP_EXT_100REL " not active. callid: %s",
                 req.callid.c_str());
            // let if float up
        } else if (rseq_1st<=req.rseq && req.rseq<=rseq) {
            if (req.rseq == rseq) {
                rseq_confirmed = true; // confirmed
                AmSessionContainer::instance()->postEvent(
                    dlg->getLocalTag(),
                    new ProvisionalReplyConfirmedEvent());
            }
            // else: confirmation for one of the pending 1xx
            DBG("%sRSeq (%u) confirmed. callid: %s",
                (req.rseq==rseq) ? "latest " : "", rseq,
                req.callid.c_str());
        }
    }
    return 1;
}

int  Am100rel::onReplyIn(const AmSipReply& reply)
{
    if (uac_state == REL100_IGNORED)
        return 1;

    if (dlg->getStatus() != AmSipDialog::Trying &&
        dlg->getStatus() != AmSipDialog::Proceeding &&
        dlg->getStatus() != AmSipDialog::Early &&
        dlg->getStatus() != AmSipDialog::Connected)
    {
        return 1;
    }

    if (100<reply.code && reply.code<200 && reply.cseq_method==SIP_METH_INVITE) {
        switch(uac_state) {
        case REL100_SUPPORTED:
        case REL100_SUPPORTED_NOT_ANNOUNCED:
            if (key_in_list(getHeader(reply.hdrs, SIP_HDR_REQUIRE),
                            SIP_EXT_100REL))
            {
                uac_state = REL100_REQUIRE;
            }
            // no break!
            else
                break;
        case REL100_REQUIRE:
            if (!key_in_list(getHeader(reply.hdrs,SIP_HDR_REQUIRE),SIP_EXT_100REL) ||
                !reply.rseq)
            {
                ERROR(SIP_EXT_100REL " not supported or no positive RSeq value in "
                      "(reliable) 1xx. callid: %s",reply.callid.c_str());
                dlg->bye();
                if (hdl) hdl->onFailure();
            } else {
                DBG(SIP_EXT_100REL " now active. callid: %s",reply.callid.c_str());
                if (hdl) ((AmSipDialogEventHandler*)hdl)->onInvite1xxRel(reply);
            }
            break;

        case REL100_DISABLED:
            // 100rel support disabled
            break;
        default:
            ERROR("BUG: unexpected value `%d' for " SIP_EXT_100REL " switch. callid: %s",
                  uac_state,reply.callid.c_str());
#ifndef NDEBUG
            abort();
#endif
        } // switch reliable 1xx
    } else if (uas_state && reply.cseq_method==SIP_METH_PRACK) {
        if (300 <= reply.code) {
            // if PRACK fails, tear down session
            dlg->bye();
            if (hdl) hdl->onFailure();
        } else if (200 <= reply.code) {
            if (hdl)
                ((AmSipDialogEventHandler*)hdl)->onPrack2xx(reply);
        } else {
            WARN("received '%d' for " SIP_METH_PRACK " method. callid: %s",
                 reply.code,reply.callid.c_str());
        }
        // absorbe the replys for the prack (they've been dispatched through
        // onPrack2xx, if necessary)
        return 0;
    }
    return 1;
}

void Am100rel::onRequestOut(AmSipRequest& req)
{
    if(req.method!=SIP_METH_INVITE)
        return;

    switch(uac_state) {
    case REL100_DISABLED:
    case REL100_IGNORED:
    case REL100_SUPPORTED_NOT_ANNOUNCED:
        return;
    case REL100_SUPPORTED:
        if (! key_in_list(getHeader(req.hdrs, SIP_HDR_REQUIRE), SIP_EXT_100REL))
            req.hdrs += SIP_HDR_COLSP(SIP_HDR_SUPPORTED) SIP_EXT_100REL CRLF;
        break;
    case REL100_REQUIRE:
        if (! key_in_list(getHeader(req.hdrs, SIP_HDR_REQUIRE), SIP_EXT_100REL))
            req.hdrs += SIP_HDR_COLSP(SIP_HDR_REQUIRE) SIP_EXT_100REL CRLF;
        break;
    default:
        ERROR("BUG: unexpected reliability switch value of '%d'. callid: %s",
            uac_state,req.callid.c_str());
    }
}

void Am100rel::onReplyOut(AmSipReply& reply)
{
    if (uas_state == REL100_IGNORED ||
        uas_state == REL100_SUPPORTED_NOT_ANNOUNCED)
    {
        return;
    }

    if (reply.cseq_method == SIP_METH_INVITE) {
        if (100 < reply.code && reply.code < 200) {
            switch(uas_state) {
            case REL100_SUPPORTED:
                if (! key_in_list(getHeader(reply.hdrs, SIP_HDR_REQUIRE),SIP_EXT_100REL))
                    reply.hdrs += SIP_HDR_COLSP(SIP_HDR_SUPPORTED) SIP_EXT_100REL CRLF;
                break;
            case REL100_REQUIRE:
                // add Require HF
                if (! key_in_list(getHeader(reply.hdrs, SIP_HDR_REQUIRE),SIP_EXT_100REL))
                    reply.hdrs += SIP_HDR_COLSP(SIP_HDR_REQUIRE) SIP_EXT_100REL CRLF;
                // add RSeq HF
                if (getHeader(reply.hdrs, SIP_HDR_RSEQ).length())
                    // already added (by app?)
                    break;
                if (! rseq) { // only init rseq if 1xx is used
                    rseq = (get_random() & 0x3ff) + 1; // start small (<1024) and non-0
                    rseq_confirmed = false;
                    rseq_1st = rseq;
                } else {
                    if ((! rseq_confirmed) && (rseq_1st == rseq)) {
                        // refuse subsequent 1xx if first isn't yet PRACKed
                        DBG("first reliable 1xx not yet PRACKed. callid: %s",reply.callid.c_str());
                        throw AmSession::Exception(491, "first reliable 1xx not yet PRACKed");
                    }
                    rseq ++;
                }
                reply.hdrs += SIP_HDR_COLSP(SIP_HDR_RSEQ) + int2str(rseq) + CRLF;
                break;
            default:
                break;
            } //switch (reliable_1xx)
        } else if (reply.code < 300) { //code = 2xx
            if(uas_state == REL100_REQUIRE && rseq && !rseq_confirmed) {
                // reliable 1xx is pending, 2xx'ing not allowed yet
                DBG("last reliable 1xx not yet PRACKed. callid: %s",reply.callid.c_str());
                throw AmSession::Exception(491, "last reliable 1xx not yet PRACKed");
            }
            //set runtime state to the initial at the end of transaction
            uas_state = initial_state;
            DBG("sent 2xx. uas_state is set to the initial_state: %d",uas_state);
        } else {
            uas_state = initial_state;
            DBG("sent final error reply. uas_state is set to the initial_state: %d",uas_state);
        }
    } //if (reply.cseq_method == SIP_METH_INVITE)
}

void Am100rel::onTimeout(const AmSipRequest& req, const AmSipReply& rpl)
{
    if (initial_state == REL100_IGNORED)
        return;

    INFO("reply <%s> timed out (not PRACKed). callid: %s",
        rpl.print().c_str(),req.callid.c_str());
    if (100 < rpl.code && rpl.code < 200 && uas_state == REL100_REQUIRE &&
        rseq == rpl.rseq && rpl.cseq_method == SIP_METH_INVITE)
    {
        INFO("reliable %d reply timed out; rejecting request. callid: %s",
             rpl.code,req.callid.c_str());
        if(hdl) hdl->onNoPrack(req, rpl);
    } else {
        WARN("reply timed-out, but not reliable. callid: %s",req.callid.c_str()); // debugging
    }
}

bool Am100rel::checkReply(AmSipReply& reply)
{
    if (uas_state == REL100_IGNORED ||
        uas_state == REL100_SUPPORTED_NOT_ANNOUNCED)
    {
        return false;
    }

    if (reply.cseq_method == SIP_METH_INVITE) {
        if (100 < reply.code && reply.code < 200) {
            switch (uas_state) {
            case REL100_REQUIRE:
                if(rseq) {
                    if ((! rseq_confirmed) && (rseq_1st == rseq)) {
                        // refuse subsequent 1xx if first isn't yet PRACKed
                        DBG("first reliable 1xx not yet PRACKed. callid: %s",reply.callid.c_str());
                        //postponed_replies.emplace(std::make_tuple(req,reply));
                        return true;
                    }
                }
                break;
            default:
                break;
            }
        } else if (reply.code < 300 && uas_state == REL100_REQUIRE) { //code = 2xx
            if (rseq && !rseq_confirmed) {
                // reliable 1xx is pending, 2xx'ing not allowed yet
                DBG("last reliable 1xx not yet PRACKed. callid: %s",reply.callid.c_str());
                //postponed_replies.emplace(std::make_tuple(req,reply));
                return true;
            }
        }
    }

    return false;
}
