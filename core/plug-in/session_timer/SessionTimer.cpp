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

#include "SessionTimer.h"
#include "AmUtils.h"
#include "AmSipHeaders.h"
#include <confuse.h>

EXPORT_SESSION_EVENT_HANDLER_FACTORY(SessionTimerFactory);
DEFINE_FACTORY_INSTANCE(SessionTimerFactory, MOD_NAME);

int SessionTimerFactory::onLoad()
{
    return 0;
}

bool SessionTimerFactory::onInvite(const AmSipRequest &req, AmConfigReader &cfg)
{
    return checkSessionExpires(req, cfg);
}

int SessionTimerFactory::configure(const std::string &config)
{
    return cfg.readFromConfig(config);
}

int SessionTimerFactory::reconfigure(const std::string &config)
{
    return 0;
}

AmSessionEventHandler *SessionTimerFactory::getHandler(AmSession *s)
{
    return new SessionTimer(s, cfg);
}


SessionTimer::SessionTimer(AmSession *s, const AmSessionTimerConfig &conf)
    : AmSessionEventHandler()
    , session_timer_conf(conf)
    , s(s)
    , min_se(0)
    , session_interval(0)
    , session_refresher(refresh_remote)
    , accept_501_reply(true)
{
    session_interval = session_timer_conf.getSessionExpires();
    min_se           = session_timer_conf.getMinimumTimer();

    DBG("Configured session with EnableSessionTimer = %s, "
        "SessionExpires = %u, MinimumTimer = %u\n",
        session_timer_conf.getEnableSessionTimer() ? "yes" : "no", session_timer_conf.getSessionExpires(),
        session_timer_conf.getMinimumTimer());

    accept_501_reply = session_timer_conf.getAccept501Reply();
    if (session_timer_conf.haveRefreshMethod()) {
        s->refresh_method = session_timer_conf.getRefreshMethod();
    }
}

SessionTimer::~SessionTimer()
{
    if (NULL != s)
        removeTimers(s);
}

bool SessionTimer::process(AmEvent *ev)
{
    assert(ev);
    AmTimeoutEvent *timeout_ev = dynamic_cast<AmTimeoutEvent *>(ev);
    if (timeout_ev) {
        if (timeout_ev->data.get(0).asInt() >= ID_SESSION_TIMER_TIMERS_START &&
            timeout_ev->data.get(0).asInt() <= ID_SESSION_TIMER_TIMERS_END)
        {
            DBG("received timeout Event with ID %d", timeout_ev->data.get(0).asInt());
            onTimeoutEvent(timeout_ev);
        }
        return true;
    }

    return false;
}

bool SessionTimer::onSipRequest(const AmSipRequest &req)
{
    updateTimer(s, req);
    return false;
}

bool SessionTimer::onSipReply(const AmSipRequest &req, const AmSipReply &reply, AmBasicSipDialog::Status old_dlg_status)
{
    if (session_timer_conf.getEnableSessionTimer() && (reply.code == 422) &&
        ((reply.cseq_method == SIP_METH_INVITE) || (reply.cseq_method == SIP_METH_UPDATE)))
    {

        // get Min-SE
        unsigned int i_minse;
        string       min_se_hdr = getHeader(reply.hdrs, SIP_HDR_MIN_SE, true);
        if (!min_se_hdr.empty()) {
            if (str2i(strip_header_params(min_se_hdr), i_minse)) {
                WARN("error while parsing " SIP_HDR_MIN_SE " header value '%s'",
                     strip_header_params(min_se_hdr).c_str());
            } else {

                if (i_minse <= session_timer_conf.getMaximumTimer()) {
                    session_interval      = i_minse;
                    unsigned int new_cseq = s->dlg->cseq;
                    // resend request with interval i_minse
                    if (s->dlg->sendRequest(req.method, &req.body, req.hdrs) == 0) {
                        DBG("request with new Session Interval %u successfully sent.", i_minse);
                        // undo SIP dialog status change
                        if (s->dlg->getStatus() != old_dlg_status)
                            s->dlg->setStatus(old_dlg_status);

                        s->updateUACTransCSeq(reply.cseq, new_cseq);
                        // processed
                        return true;
                    } else {
                        ERROR("failed to send request with new Session Interval.");
                    }
                } else {
                    DBG("other side requests too high Min-SE: %u (our limit %u)", i_minse,
                        session_timer_conf.getMaximumTimer());
                }
            }
        }
    }

    if ((reply.cseq_method == SIP_METH_INVITE) || (reply.cseq_method == SIP_METH_UPDATE)) {

        updateTimer(s, reply);
    }

    return false;
}

bool SessionTimer::onSendRequest(AmSipRequest &req, int &flags)
{
    if (req.method == "BYE") {
        removeTimers(s);
        return false;
    }

    // if (session_timer_conf.getEnableSessionTimer() &&
    //     ((req.method == SIP_METH_INVITE) || (req.method == SIP_METH_UPDATE))) {
    // save INVITE and UPDATE so we can resend on 422 reply
    // DBG("adding %d to list of sent requests.", req.cseq);
    // sent_requests[req.cseq] = SIPRequestInfo(req.method,
    // 					     &req.body,
    // 					     req.hdrs);
    // }

    addOptionTag(req.hdrs, SIP_HDR_SUPPORTED, TIMER_OPTION_TAG);
    if ((req.method != SIP_METH_INVITE) && (req.method != SIP_METH_UPDATE))
        return false; // session-expires / min-se only in INV/UPD

    if (session_interval < min_se) {
        // https://www.rfc-editor.org/rfc/rfc4028#section-7.1
        /* If a Min-SE header is included in the
         * initial session refresh request, the value of the Session-Expires
         * MUST be greater than or equal to the value in Min-SE.*/
        session_interval = min_se;
    }

    removeHeader(req.hdrs, SIP_HDR_SESSION_EXPIRES);
    removeHeader(req.hdrs, SIP_HDR_MIN_SE);
    if (req.to_tag.empty()) {
        req.hdrs += SIP_HDR_COLSP(SIP_HDR_SESSION_EXPIRES) + int2str(session_interval) + CRLF +
                    SIP_HDR_COLSP(SIP_HDR_MIN_SE) + int2str(min_se) + CRLF;
    } else {
        req.hdrs += SIP_HDR_COLSP(SIP_HDR_SESSION_EXPIRES) + int2str(session_interval) +
                    ";refresher=" + (session_refresher == refresh_local ? "uac" : "uas") + CRLF +
                    SIP_HDR_COLSP(SIP_HDR_MIN_SE) + int2str(min_se) + CRLF;
    }

    return false;
}


bool SessionTimer::onSendReply(const AmSipRequest &req, AmSipReply &reply, int &flags)
{
    // only in 2xx responses to INV/UPD
    if (((reply.cseq_method != SIP_METH_INVITE) && (reply.cseq_method != SIP_METH_UPDATE)) || (reply.code < 200) ||
        (reply.code >= 300))
        return false;

    addOptionTag(reply.hdrs, SIP_HDR_SUPPORTED, TIMER_OPTION_TAG);

    if (((session_refresher_role == UAC) && (session_refresher == refresh_remote)) ||
        ((session_refresher_role == UAS) && remote_timer_aware))
    {
        addOptionTag(reply.hdrs, SIP_HDR_REQUIRE, TIMER_OPTION_TAG);
    } else {
        removeOptionTag(reply.hdrs, SIP_HDR_REQUIRE, TIMER_OPTION_TAG);
    }

    // remove (possibly existing) Session-Expires header
    removeHeader(reply.hdrs, SIP_HDR_SESSION_EXPIRES);

    reply.hdrs += SIP_HDR_COLSP(SIP_HDR_SESSION_EXPIRES) + int2str(session_interval) +
                  ";refresher=" + (session_refresher_role == UAC ? "uac" : "uas") + CRLF;

    return false;
}

int SessionTimer::configure(AmConfigReader &conf)
{
    if (session_timer_conf.readFromConfig(conf))
        return -1;

    session_interval = session_timer_conf.getSessionExpires();
    min_se           = session_timer_conf.getMinimumTimer();

    DBG("Configured session with EnableSessionTimer = %s, "
        "SessionExpires = %u, MinimumTimer = %u\n",
        session_timer_conf.getEnableSessionTimer() ? "yes" : "no", session_timer_conf.getSessionExpires(),
        session_timer_conf.getMinimumTimer());

    accept_501_reply = session_timer_conf.getAccept501Reply();
    if (session_timer_conf.haveRefreshMethod()) {
        s->refresh_method = session_timer_conf.getRefreshMethod();
    }

    return 0;
}

/**
 * check if UAC requests too low Session-Expires
 *   (<locally configured Min-SE)
 * Throws SessionIntervalTooSmallException if too low
 */
bool SessionTimerFactory::checkSessionExpires(const AmSipRequest &req, AmConfigReader &cfg)
{
    AmSessionTimerConfig sst_cfg;
    if (sst_cfg.readFromConfig(cfg)) {
        return false;
    }

    string session_expires = getHeader(req.hdrs, SIP_HDR_SESSION_EXPIRES, SIP_HDR_SESSION_EXPIRES_COMPACT, true);

    if (session_expires.length()) {
        unsigned int i_se;
        if (!str2i(strip_header_params(session_expires), i_se)) {
            if (i_se < sst_cfg.getMinimumTimer()) {
                throw AmSession::Exception(422, "Session Interval Too Small",
                                           SIP_HDR_COLSP(SIP_HDR_MIN_SE) + int2str(sst_cfg.getMinimumTimer()) + CRLF);
            }
        } else {
            WARN("parsing session expires '%s' failed", session_expires.c_str());
            throw AmSession::Exception(400, "Bad Request");
        }
    }

    return true;
}

void SessionTimer::updateTimer(AmSession *s, const AmSipRequest &req)
{

    if ((req.method == SIP_METH_INVITE) || (req.method == SIP_METH_UPDATE)) {

        remote_timer_aware =
            key_in_list(getHeader(req.hdrs, SIP_HDR_SUPPORTED, SIP_HDR_SUPPORTED_COMPACT), TIMER_OPTION_TAG);

        // determine session interval
        string sess_expires_hdr = getHeader(req.hdrs, SIP_HDR_SESSION_EXPIRES, SIP_HDR_SESSION_EXPIRES_COMPACT, true);

        bool         rem_has_sess_expires = false;
        unsigned int rem_sess_expires     = 0;
        if (!sess_expires_hdr.empty()) {
            if (str2i(strip_header_params(sess_expires_hdr), rem_sess_expires)) {
                WARN("error while parsing " SIP_HDR_SESSION_EXPIRES " header value '%s'",
                     strip_header_params(sess_expires_hdr).c_str()); // exception?
            } else {
                rem_has_sess_expires = true;
            }
        }

        // get Min-SE
        unsigned int i_minse    = min_se;
        string       min_se_hdr = getHeader(req.hdrs, SIP_HDR_MIN_SE, true);
        if (!min_se_hdr.empty()) {
            if (str2i(strip_header_params(min_se_hdr), i_minse)) {
                WARN("error while parsing " SIP_HDR_MIN_SE " header value '%s'",
                     strip_header_params(min_se_hdr).c_str()); // exception?
            }
        }

        // minimum limit of both
        if (i_minse > min_se)
            min_se = i_minse;

        // calculate actual se
        session_interval = session_timer_conf.getSessionExpires();

        if (rem_has_sess_expires) {
            if (rem_sess_expires <= min_se) {
                session_interval = min_se;
            } else {
                if (rem_sess_expires < session_interval)
                    session_interval = rem_sess_expires;
            }
        }

        DBG("using actual session interval %u", session_interval);

        // determine session refresher -- cf rfc4028 Table 2
        // only if the remote party supports timer and asks
        // to be refresher we will let the remote party do it.
        // if remote supports timer and does not specify,
        // could also be refresher=uac
        if ((remote_timer_aware) && (!sess_expires_hdr.empty()) &&
            (get_header_param(sess_expires_hdr, "refresher") == "uac"))
        {
            DBG("session refresher will be remote UAC.");
            session_refresher      = refresh_remote;
            session_refresher_role = UAC;
        } else {
            DBG("session refresher will be local UAS.");
            session_refresher      = refresh_local;
            session_refresher_role = UAS;
        }

        DBG("refresher is %s role %s", session_refresher == refresh_local ? "local" : "remote",
            session_refresher_role == UAC ? "uac" : "uas");

        removeTimers(s);
        setTimers(s);

    } else if (req.method == "BYE") { // remove all timers?
        removeTimers(s);
    }
}

void SessionTimer::updateTimer(AmSession *s, const AmSipReply &reply)
{
    if (!session_timer_conf.getEnableSessionTimer())
        return;

    // only update timer on positive reply, or 501 if config'd
    if (((reply.code < 200) || (reply.code >= 300)) && (!(accept_501_reply && reply.code == 501)))
        return;

    // determine session interval
    string sess_expires_hdr = getHeader(reply.hdrs, SIP_HDR_SESSION_EXPIRES, SIP_HDR_SESSION_EXPIRES_COMPACT, true);

    session_refresher      = refresh_local;
    session_refresher_role = UAC;

    if (!sess_expires_hdr.empty()) {
        unsigned int sess_i_tmp = 0;
        if (str2i(strip_header_params(sess_expires_hdr), sess_i_tmp)) {
            WARN("error while parsing " SIP_HDR_SESSION_EXPIRES " header value '%s'",
                 strip_header_params(sess_expires_hdr).c_str()); // exception?
        } else {
            // this is forbidden by rfc, but to be sure against 'rogue' proxy/uas
            if (sess_i_tmp < min_se) {
                session_interval = min_se;
            } else {
                session_interval = sess_i_tmp;
            }
        }
        if (get_header_param(sess_expires_hdr, "refresher") == "uas") {
            session_refresher      = refresh_remote;
            session_refresher_role = UAS;
        }
    }

    removeTimers(s);
    setTimers(s);
}

void SessionTimer::setTimers(AmSession *s)
{
    // set session timer
    DBG("Setting session interval timer: %ds, tag '%s'", session_interval, s->getLocalTag().c_str());

    s->setTimer(ID_SESSION_INTERVAL_TIMER, session_interval);

    // set session refresh action timer, after half the expiration
    if (session_refresher == refresh_local) {
        DBG("Setting session refresh timer: %ds, tag '%s'", session_interval / 2, s->getLocalTag().c_str());
        s->setTimer(ID_SESSION_REFRESH_TIMER, session_interval / 2);
    }
}

void SessionTimer::retryRefreshTimer(AmSession *s)
{
    DBG("Retrying session refresh timer: T-2s, tag '%s' ", s->getLocalTag().c_str());

    s->setTimer(ID_SESSION_REFRESH_TIMER, 2);
}


void SessionTimer::removeTimers(AmSession *s)
{
    s->removeTimer(ID_SESSION_REFRESH_TIMER);
    s->removeTimer(ID_SESSION_INTERVAL_TIMER);
}

void SessionTimer::onTimeoutEvent(AmTimeoutEvent *timeout_ev)
{

    int timer_id = timeout_ev->data.get(0).asInt();

    if (s->dlg->getStatus() == AmSipDialog::Disconnecting || s->dlg->getStatus() == AmSipDialog::Disconnected) {
        DBG("ignoring SST timeout event %i in Disconnecting/-ed session", timer_id);
        return;
    }

    if (timer_id == ID_SESSION_REFRESH_TIMER) {
        if (session_refresher == refresh_local) {
            DBG("Session Timer: initiating session refresh");
            if (!s->refresh()) {
                retryRefreshTimer(s);
            }
        } else {
            DBG("need session refresh but remote session is refresher");
        }
    } else if (timer_id == ID_SESSION_INTERVAL_TIMER) {
        s->onSessionTimeout();
    } else {
        DBG("unknown timeout event received.");
    }

    return;
}

AmSessionTimerConfig::AmSessionTimerConfig()
    : EnableSessionTimer(DEFAULT_ENABLE_SESSION_TIMER)
    , SessionExpires(SESSION_EXPIRES)
    , MinimumTimer(MINIMUM_TIMER)
    , MaximumTimer(MAXIMUM_TIMER)
    , HaveRefreshMethod(false)
    , Accept501Reply(true)
{
}

AmSessionTimerConfig::~AmSessionTimerConfig() {}

#define PARAM_ENABLE_SESSION_TIMER_NAME "enable_session_timer"
#define PARAM_SESSION_EXPIRES_NAME      "session_expires"
#define PARAM_MINIMUM_TIMER_NAME        "minimum_timer"
#define PARAM_MAXIMUM_TIMER_NAME        "maximum_timer"
#define PARAM_SREFRESH_METHOD_NAME      "session_refresh_method"
#define PARAM_ACCEPT_501_REPLY_NAME     "accept_501_reply"

int AmSessionTimerConfig::readFromConfig(const string &config)
{
    cfg_opt_t stmr_opt[] = { CFG_BOOL(PARAM_ENABLE_SESSION_TIMER_NAME, cfg_true, CFGF_NODEFAULT),
                             CFG_INT(PARAM_SESSION_EXPIRES_NAME, 0, CFGF_NODEFAULT),
                             CFG_INT(PARAM_MINIMUM_TIMER_NAME, 0, CFGF_NODEFAULT),
                             CFG_INT(PARAM_MAXIMUM_TIMER_NAME, 0, CFGF_NODEFAULT),
                             CFG_STR(PARAM_SREFRESH_METHOD_NAME, "", CFGF_NODEFAULT),
                             CFG_BOOL(PARAM_ACCEPT_501_REPLY_NAME, cfg_true, CFGF_NONE),
                             CFG_END() };

    cfg_t *cfg = cfg_init(stmr_opt, CFGF_NONE);
    if (!cfg)
        return -1;
    switch (cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS: break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error", MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing", MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    // enable_session_timer
    if (cfg_size(cfg, PARAM_ENABLE_SESSION_TIMER_NAME)) {
        EnableSessionTimer = cfg_getbool(cfg, PARAM_ENABLE_SESSION_TIMER_NAME);
    }
    // session_expires
    if (cfg_size(cfg, PARAM_SESSION_EXPIRES_NAME)) {
        SessionExpires = cfg_getint(cfg, PARAM_SESSION_EXPIRES_NAME);
    }

    // minimum_timer
    if (cfg_size(cfg, PARAM_MINIMUM_TIMER_NAME)) {
        MinimumTimer = cfg_getint(cfg, PARAM_MINIMUM_TIMER_NAME);
        if (MinimumTimer < MINIMUM_TIMER) {
            ERROR("invalid value %d for %s. should be >= %d", MinimumTimer, PARAM_MINIMUM_TIMER_NAME, MINIMUM_TIMER);
            cfg_free(cfg);
            return -1;
        }
    }

    if (cfg_size(cfg, PARAM_MAXIMUM_TIMER_NAME)) {
        int maximum_timer = cfg_getint(cfg, PARAM_MAXIMUM_TIMER_NAME);
        if (maximum_timer <= 0) {
            ERROR("invalid value for maximum_timer '%d'", maximum_timer);
            cfg_free(cfg);
            return -1;
        }
        MaximumTimer = (unsigned int)maximum_timer;
    }

    if (cfg_size(cfg, PARAM_SREFRESH_METHOD_NAME)) {
        string refresh_method_s = cfg_getstr(cfg, PARAM_SREFRESH_METHOD_NAME);
        if (refresh_method_s == "UPDATE") {
            RefreshMethod = AmSession::REFRESH_UPDATE;
        } else if (refresh_method_s == "UPDATE_FALLBACK_INVITE") {
            RefreshMethod = AmSession::REFRESH_UPDATE_FB_REINV;
        } else if (refresh_method_s == "INVITE") {
            RefreshMethod = AmSession::REFRESH_REINVITE;
        } else {
            ERROR("unknown setting for 'session_refresh_method' config option.");
            cfg_free(cfg);
            return -1;
        }
        HaveRefreshMethod = true;
        DBG("set session refresh method: %d.", RefreshMethod);
    } else {
        HaveRefreshMethod = false;
    }

    Accept501Reply = cfg_getbool(cfg, PARAM_ACCEPT_501_REPLY_NAME);
    cfg_free(cfg);

    if (SessionExpires < MinimumTimer) {
        ERROR("%s(%d) should be >= %s(%d)", PARAM_SESSION_EXPIRES_NAME, SessionExpires, PARAM_MINIMUM_TIMER_NAME,
              MinimumTimer);
        return -1;
    }

    return 0;
}

int AmSessionTimerConfig::readFromConfig(AmConfigReader &cfg)
{
    // enable_session_timer
    if (cfg.hasParameter("enable_session_timer")) {
        if (!setEnableSessionTimer(cfg.getParameter("enable_session_timer"))) {
            ERROR("invalid enable_session_timer specified");
            return -1;
        }
    }

    // session_expires
    if (cfg.hasParameter("session_expires")) {
        if (!setSessionExpires(cfg.getParameter("session_expires"))) {
            ERROR("invalid session_expires specified");
            return -1;
        }
    }

    // minimum_timer
    if (cfg.hasParameter("minimum_timer")) {
        if (!setMinimumTimer(cfg.getParameter("minimum_timer"))) {
            ERROR("invalid minimum_timer specified");
            return -1;
        }
    }

    if (cfg.hasParameter("maximum_timer")) {
        int maximum_timer = 0;
        if (!str2int(cfg.getParameter("maximum_timer"), maximum_timer) || maximum_timer <= 0) {
            ERROR("invalid value for maximum_timer '%s'", cfg.getParameter("maximum_timer").c_str());
            return -1;
        }
        MaximumTimer = (unsigned int)maximum_timer;
    }

    if (cfg.hasParameter("session_refresh_method")) {
        string refresh_method_s = cfg.getParameter("session_refresh_method");
        if (refresh_method_s == "UPDATE") {
            RefreshMethod = AmSession::REFRESH_UPDATE;
        } else if (refresh_method_s == "UPDATE_FALLBACK_INVITE") {
            RefreshMethod = AmSession::REFRESH_UPDATE_FB_REINV;
        } else if (refresh_method_s == "INVITE") {
            RefreshMethod = AmSession::REFRESH_REINVITE;
        } else {
            ERROR("unknown setting for 'session_refresh_method' config option.");
            return -1;
        }
        HaveRefreshMethod = true;
        DBG("set session refresh method: %d.", RefreshMethod);
    } else {
        HaveRefreshMethod = false;
    }

    Accept501Reply = str2bool(cfg.getParameter("accept_501_reply")).value_or(false);

    return 0;
}

int AmSessionTimerConfig::setEnableSessionTimer(const string &enable)
{
    if (strcasecmp(enable.c_str(), "yes") == 0) {
        EnableSessionTimer = 1;
    } else if (strcasecmp(enable.c_str(), "no") == 0) {
        EnableSessionTimer = 0;
    } else {
        return 0;
    }
    return 1;
}

int AmSessionTimerConfig::setSessionExpires(const string &se)
{
    if (sscanf(se.c_str(), "%u", &SessionExpires) != 1) {
        return 0;
    }
    DBG("setSessionExpires(%i)", SessionExpires);
    return 1;
}

int AmSessionTimerConfig::setMinimumTimer(const string &minse)
{
    if (sscanf(minse.c_str(), "%u", &MinimumTimer) != 1) {
        return 0;
    }
    DBG("setMinimumTimer(%i)", MinimumTimer);
    return 1;
}
