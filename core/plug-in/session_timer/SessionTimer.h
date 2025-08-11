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

#ifndef SessionTimer_h
#define SessionTimer_h

#include "AmApi.h"
#include "AmSession.h"

#ifndef MOD_NAME
#define MOD_NAME "session_timer"
#endif

#define TIMER_OPTION_TAG "timer"

/* Session Timer: -ssa */
class AmTimeoutEvent;
// these are the timer IDs for session timer
// Caution: do not use these for other purposes
#define ID_SESSION_TIMER_TIMERS_START -2
#define ID_SESSION_TIMER_TIMERS_END   -1

#define ID_SESSION_INTERVAL_TIMER -1
#define ID_SESSION_REFRESH_TIMER  -2

/* Session Timer default configuration: */
#define DEFAULT_ENABLE_SESSION_TIMER 1
#define SESSION_EXPIRES              300 // seconds
#define MINIMUM_TIMER                90  // seconds

#define MAXIMUM_TIMER 1800 // seconds - 30 min

/** \brief config for the session timer */
class AmSessionTimerConfig {

    /** Session Timer: enable? */
    int EnableSessionTimer;
    /** Session Timer: Desired Session-Expires */
    unsigned int SessionExpires;
    /** Session Timer: Minimum Session-Expires */
    unsigned int MinimumTimer;

    unsigned int MaximumTimer;

    bool                            HaveRefreshMethod;
    AmSession::SessionRefreshMethod RefreshMethod;

    bool Accept501Reply;

  public:
    AmSessionTimerConfig();
    ~AmSessionTimerConfig();


    /** Session Timer: Enable Session Timer?
        returns 0 on invalid value */
    int setEnableSessionTimer(const string &enable);
    /** Session Timer: Setter for Desired Session-Expires,
        returns 0 on invalid value */
    int setSessionExpires(const string &se);
    /** Session Timer: Setter for Minimum Session-Expires,
        returns 0 on invalid value */
    int setMinimumTimer(const string &minse);

    void setEnableSessionTimer(bool enable) { EnableSessionTimer = enable; }
    void setSessionExpires(unsigned int se) { SessionExpires = se; }
    void setMinimumTimer(unsigned int minse) { MinimumTimer = minse; }
    void setMaximumTimer(unsigned int maxse) { MaximumTimer = maxse; }

    bool                            getEnableSessionTimer() const { return EnableSessionTimer; }
    unsigned int                    getSessionExpires() const { return SessionExpires; }
    unsigned int                    getMinimumTimer() const { return MinimumTimer; }
    unsigned int                    getMaximumTimer() const { return MaximumTimer; }
    bool                            getAccept501Reply() const { return Accept501Reply; }
    bool                            haveRefreshMethod() const { return HaveRefreshMethod; }
    AmSession::SessionRefreshMethod getRefreshMethod() { return RefreshMethod; }

    int readFromConfig(const string &cfg);
    int readFromConfig(AmConfigReader &cfg);
};

/** \brief Factory of the session timer event handler */
class SessionTimerFactory : public AmSessionEventHandlerFactory, public AmConfigFactory {
    AmSessionTimerConfig cfg;
    bool                 checkSessionExpires(const AmSipRequest &req, AmConfigReader &cfg);

    SessionTimerFactory(const string &name)
        : AmSessionEventHandlerFactory(name)
        , AmConfigFactory(name)
    {
    }

  public:
    DECLARE_FACTORY_INSTANCE(SessionTimerFactory);

    int  configure(const std::string &config);
    int  reconfigure(const std::string &config);
    int  onLoad();
    bool onInvite(const AmSipRequest &req, AmConfigReader &cfg);

    AmSessionEventHandler *getHandler(AmSession *s);
};

struct SIPRequestInfo;

/** \brief SessionEventHandler for implementing session timer logic for a session */
class SessionTimer : public AmSessionEventHandler {
  protected:
    AmSessionTimerConfig session_timer_conf;
    AmSession           *s;

    // map to save sent requests, so we can resent in case of 422
    // std::map<unsigned int, SIPRequestInfo> sent_requests;

    enum SessionRefresher { refresh_local, refresh_remote };
    enum SessionRefresherRole { UAC, UAS };

    bool                 remote_timer_aware;
    unsigned int         min_se;
    unsigned int         session_interval;
    SessionRefresher     session_refresher;
    SessionRefresherRole session_refresher_role;
    bool                 accept_501_reply;

    void updateTimer(AmSession *s, const AmSipRequest &req);
    void updateTimer(AmSession *s, const AmSipReply &reply);

    virtual void setTimers(AmSession *s);
    void         retryRefreshTimer(AmSession *s);
    void         removeTimers(AmSession *s);

    string getReplyHeaders(const AmSipRequest &req);
    string getRequestHeaders(const string &method);

    /* Session Timer: -ssa */

    // @return true if OK
    void onTimeout();
    void onTimeoutEvent(AmTimeoutEvent *timeout_ev);

  public:
    SessionTimer(AmSession *, const AmSessionTimerConfig &);
    virtual ~SessionTimer();

    /* @see AmSessionEventHandler */
    virtual int  configure(AmConfigReader &conf);
    virtual bool process(AmEvent *);

    virtual bool onSipRequest(const AmSipRequest &);
    virtual bool onSipReply(const AmSipRequest &, const AmSipReply &, AmBasicSipDialog::Status old_dlg_status);

    virtual bool onSendRequest(AmSipRequest &req, int &flags);
    virtual bool onSendReply(const AmSipRequest &req, AmSipReply &reply, int &flags);
};


/** \brief contains necessary information for UAC auth of a SIP request */
struct SIPRequestInfo {
    string     method;
    AmMimeBody body;
    string     hdrs;

    SIPRequestInfo(const string &method, const AmMimeBody *body, const string &hdrs)
        : method(method)
        , hdrs(hdrs)
    {
        if (body)
            this->body = *body;
    }

    SIPRequestInfo() {}
};

#endif
