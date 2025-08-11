/*
 * Copyright (C) 2006 iptego GmbH
 * Copyright (C) 2011 Stefan Sayer
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

#ifndef _AmSipRegistration_h_
#define _AmSipRegistration_h_
#include <string>
using std::string;

#include "ampi/SIPRegistrarClientAPI.h"
#include "ampi/UACAuthAPI.h"
#include "AmUriParser.h"
#include "AmSessionEventHandler.h"
#include <chrono>

#include "sip/parse_uri.h"

#define DEFAULT_REGISTER_RETRY_DELAY 120
#define REGISTER_ATTEMPTS_UNLIMITED  0

struct SIPRegistrationInfo {
    string              id;
    string              domain;
    int                 port;
    string              user;
    string              name;
    string              auth_user;
    string              pwd;
    string              proxy;
    string              contact;
    string              contact_uri_params;
    string              sip_interface_name;
    map<string, string> contact_params;
    int                 expires_interval;
    int                 retry_delay;
    int                 max_attempts;
    int                 attempt;
    int                 transport_protocol_id;
    int                 proxy_transport_protocol_id;
    bool                force_expires_interval;
    int                 transaction_timeout;
    int                 srv_failover_timeout;
    dns_priority        resolve_priority;
    sip_uri::uri_scheme scheme_id;

    SIPRegistrationInfo(const string &id, const string &domain, const string &user, const string &name,
                        const string &auth_user, const string &pwd, const string &proxy, const string &contact,
                        const string &contact_uri_params, const map<string, string> &contact_params,
                        const int &expires_interval, const bool &force_expires_interval, const int &retry_delay,
                        const int &max_attempts, const int &transport_protocol_id,
                        const int &proxy_transport_protocol_id, const int &transaction_timeout,
                        const int &srv_failover_timeout, const dns_priority &resolve_priority,
                        sip_uri::uri_scheme scheme_id = sip_uri::SIP, int port = 0)
        : id(id)
        , domain(domain)
        , port(port)
        , user(user)
        , name(name)
        , auth_user(auth_user)
        , pwd(pwd)
        , proxy(proxy)
        , contact(contact)
        , contact_uri_params(contact_uri_params)
        , contact_params(contact_params)
        , expires_interval(expires_interval)
        , retry_delay(retry_delay)
        , max_attempts(max_attempts)
        , attempt(0)
        , transport_protocol_id(transport_protocol_id)
        , proxy_transport_protocol_id(proxy_transport_protocol_id)
        , force_expires_interval(force_expires_interval)
        , transaction_timeout(transaction_timeout)
        , srv_failover_timeout(srv_failover_timeout)
        , resolve_priority(resolve_priority)
        , scheme_id(scheme_id)
    {
    }
    SIPRegistrationInfo()
        : port(0)
        , expires_interval(0)
        , retry_delay(0)
        , max_attempts(0)
        , transport_protocol_id(0)
        , proxy_transport_protocol_id(0)
        , force_expires_interval(false)
        , transaction_timeout(0)
        , srv_failover_timeout(0)
        , resolve_priority(Dualstack)
        , scheme_id(sip_uri::SIP)
    {
    }

    bool init_from_amarg(const AmArg &info);
};

class AmSIPRegistration : public AmBasicSipEventHandler,
                          public DialogControl,
                          public CredentialHolder

{

    AmBasicSipDialog dlg;
    UACAuthCred      cred;

    SIPRegistrationInfo info;
    string              handle;

    // session to post events to
    string sess_link;

    AmSessionEventHandler *seh;

    AmSipRequest req;

    AmUriParser local_contact;

    unsigned int expires_interval;
    bool         force_expires_interval;

    typedef std::chrono::system_clock::time_point timep;

    sip_timers_override reg_timers_override;

    void patch_transport(string &uri, int transport_protocol_id);

  public:
    AmSIPRegistration(const string &handle, const SIPRegistrationInfo &info, const string &sess_link);
    ~AmSIPRegistration();

    void setRegistrationInfo(const SIPRegistrationInfo &_info);
    void applyInfo();

    void setSessionEventHandler(AmSessionEventHandler *new_seh);

    void setExpiresInterval(unsigned int desired_expires);
    void setForceExpiresInterval(bool force);

    bool doRegistration();
    bool doUnregister();

    bool timeToReregister(time_t now_sec);
    bool registerExpired(time_t now_sec);
    void onRegisterExpired();
    void onRegisterSendTimeout();

    bool registerSendTimeout(time_t now_sec);

    void onSendRequest(AmSipRequest &req, int &flags);
    void onSendReply(const AmSipRequest &req, AmSipReply &reply, int &flags);

    // DialogControl if
    AmBasicSipDialog *getDlg() { return &dlg; }
    // CredentialHolder
    UACAuthCred *getCredentials() { return &cred; }

    void onSipReply(const AmSipRequest &req, const AmSipReply &reply, AmBasicSipDialog::Status old_dlg_status);

    /** is this registration registered? */
    bool active;
    /** should this registration be removed from container? */
    bool remove;
    /** are we waiting for the response to a register? */
    bool waiting_result;
    /** are we unregistering? */
    bool unregistering;
    /** are we postponed */
    bool postponed;

    time_t       reg_begin;
    unsigned int reg_expires;
    time_t       reg_send_begin;
    timep        postponed_next_attempt;

    string request_contact;
    AmArg  reply_contacts;

    enum error_initiator { REG_ERROR_LOCAL = 0, REG_ERROR_REMOTE } error_initiatior;
    int    error_code;
    string error_reason;

    enum RegistrationState { RegisterPending = 0, RegisterActive, RegisterError, RegisterExpired, RegisterPostponed };
    /** return the state of the registration */
    RegistrationState getState();
    /** return the expires left for the registration */
    unsigned int getExpiresLeft();
    /** return the expires TS for the registration */
    time_t getExpiresTS();

    bool getUnregistering();

    SIPRegistrationInfo &getInfo() { return info; }
    const string        &getEventSink() { return sess_link; }
    const string        &getHandle() { return req.from_tag; }
};


#endif
