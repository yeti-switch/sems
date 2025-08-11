/*
 * Copyright (C) 2006 iptego GmbH
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

#ifndef RegisterClient_h
#define RegisterClient_h

#include "AmSipRegistration.h"
#include "AmApi.h"
#include "ampi/BusAPI.h"
#include "RegShaper.h"
#include "RpcTreeHandler.h"

#include <sys/time.h>

#include <map>
#include <string>
using std::map;
using std::string;

#define REG_CLIENT_QUEUE "reg_client"

struct SIPNewRegistrationEvent;
class SIPRemoveRegistrationEvent;

class SIPRegistrarClient : public AmDynInvokeFactory,
                           public AmConfigFactory,
                           public RpcTreeHandler<SIPRegistrarClient>,
                           public AmThread,
                           public AmEventFdQueue,
                           public AmEventHandler,
                           public StatsCountersGroupsContainerInterface {
    int               epoll_fd;
    AmTimerFd         timer;
    AmTimerFd         postponed_regs_timer;
    AmEventFd         stop_event;
    AmCondition<bool> stopped;

    // registrations container
    AmMutex reg_mut;

    typedef std::map<std::string, AmSIPRegistration *>  RegHash;
    typedef std::pair<std::string, AmSIPRegistration *> RegHashPair;

    RegHash registrations;
    RegHash registrations_by_id;

    RegShaper shaper;
    int       default_expires;
    int       shaper_min_interval_per_domain;

    bool               add_reg(const string &reg_id, AmSIPRegistration *new_reg);
    AmSIPRegistration *remove_reg(const string &reg_id);
    AmSIPRegistration *remove_reg_unsafe(const string &reg_id);
    AmSIPRegistration *get_reg(const string &reg_id);
    AmSIPRegistration *get_reg_unsafe(const string &reg_id);

    void onSipReplyEvent(AmSipReplyEvent *ev);
    void onNewRegistration(SIPNewRegistrationEvent *new_reg);
    void onRemoveRegistration(SIPRemoveRegistrationEvent *reg);
    /** flush all registrations
     *  @return registrations count before flush
     */
    size_t onFlushRegistrations();
    void   onBusEvent(BusReplyEvent *bus_event);
    void   processAmArgRegistration(AmArg &data);

    static SIPRegistrarClient *_instance;

    AmDynInvoke *uac_auth_i;

    void checkTimeouts();
    void checkPostponedRegs();
    void onServerShutdown();
    void doRegistrationWithShaper(AmSIPRegistration &reg);

  public:
    SIPRegistrarClient(const string &name);

    // Config factory
    int configure(const std::string &config) override;
    int reconfigure(const std::string &config) override;
    // DI factory
    AmDynInvoke *getInstance() override { return instance(); }
    // DI API
    static SIPRegistrarClient *instance();
    void                       init_rpc_tree() override;
    // StatCountersGroupsInterface
    void operator()(const string &name, iterate_groups_callback_type callback) override;

    bool onSipReply(const AmSipReply &rep, AmSipDialog::Status old_dlg_status);
    int  onLoad() override;
    void onShutdown() override;

    void run() override;
    void on_stop() override;
    void process(AmEvent *ev) override;

    // API
    string postSIPNewRegistrationEvent(const string &id, const string &domain, const string &user, const string &name,
                                       const string &auth_user, const string &pwd, const string &sess_link,
                                       const string &proxy, const string &contact, const int &expires_interval,
                                       bool &force_expires_interval, const int &retry_delay, const int &max_attempts,
                                       const int &transport_protocol_id, const int &proxy_transport_protocol_id,
                                       const int &transaction_timeout, const int &srv_failover_timeout,
                                       const string &handle, const dns_priority &priority,
                                       sip_uri::uri_scheme scheme_id);
    bool   hasRegistration(const string &handle);

    enum { AddRegistration, RemoveRegistration } RegEvents;

    rpc_handler createRegistration;
    rpc_handler removeRegistration;
    rpc_handler removeRegistrationById;

    rpc_handler getRegistrationState;
    rpc_handler listRegistrations;
    rpc_handler showRegistration;
    rpc_handler showRegistrationById;
    rpc_handler getRegistrationsCount;

    rpc_handler flushRegistrations;
};

struct SIPNewRegistrationEvent : public AmEvent {
    SIPNewRegistrationEvent(const SIPRegistrationInfo &info, const string &handle, const string &sess_link)
        : AmEvent(SIPRegistrarClient::AddRegistration)
        , handle(handle)
        , sess_link(sess_link)
        , info(info)
    {
    }

    string              handle;
    string              sess_link;
    SIPRegistrationInfo info;
};

class SIPRemoveRegistrationEvent : public AmEvent {
  public:
    string handle_or_id;
    bool   is_id;
    SIPRemoveRegistrationEvent(const string &handle_or_id, bool is_id = false)
        : AmEvent(SIPRegistrarClient::RemoveRegistration)
        , handle_or_id(handle_or_id)
        , is_id(is_id)
    {
    }
};

#endif
