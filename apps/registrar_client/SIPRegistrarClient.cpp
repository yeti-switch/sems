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

#include "SIPRegistrarClient.h"
#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "sip/parse_via.h"

#define MOD_NAME "registrar_client"

#include <unistd.h>

#define CFG_OPT_NAME_SHAPER_MIN_INTERVAL "min_interval_per_domain_msec"
#define CFG_OPT_NAME_DEFAULT_EXPIRES "default_expires"
#define DEFAULT_EXPIRES 1800

#define TIMEOUT_CHECKING_INTERVAL 200000 //microseconds
#define EPOLL_MAX_EVENTS    2048

//EXPORT_SIP_EVENT_HANDLER_FACTORY(SIPRegistrarClient, MOD_NAME);
//EXPORT_PLUGIN_CLASS_FACTORY(SIPRegistrarClient, MOD_NAME);

static void reg2arg(const map<string, AmSIPRegistration*>::iterator &it, AmArg &ret, const RegShaper::timep &now) {
    AmArg r;
    AmSIPRegistration *reg = it->second;
    const SIPRegistrationInfo &ri = reg->getInfo();
    AmSIPRegistration::RegistrationState state;

    if(reg->getUnregistering())
        return; //hide unregistering registrations

    state = reg->getState();

    r["handle"] = it->first;
    r["id"] = ri.id;
    r["domain"] = ri.domain;
    r["user"] = ri.user;
    r["display_name"] = ri.name;
    r["auth_user"] = ri.auth_user;
    r["proxy"] = ri.proxy;
    r["contact"] = ri.contact;
    r["expires_interval"] = ri.expires_interval;
    r["expires"] =   (int)reg->reg_expires;
    r["force_reregister"] = ri.force_expires_interval;
    r["retry_delay"] = ri.retry_delay;
    r["max_attempts"] = ri.max_attempts;
    r["attempt"] = ri.attempt;
    r["transport_protocol_id"] = ri.transport_protocol_id;
    r["proxy_transport_protocol_id"] = ri.proxy_transport_protocol_id;
    r["event_sink"] = reg->getEventSink();
    r["last_request_time"] = (int)reg->reg_send_begin;
    r["last_succ_reg_time"] = (int)reg->reg_begin;
    r["expires_left"] = (int)reg->getExpiresLeft();
    r["state_code"] = state;
    r["state"] = getSIPRegistationStateString(state);
    r["last_request_contact"] = reg->request_contact;
    r["last_reply_contacts"] = reg->reply_contacts;
    if(reg->error_code!=0) {
        r["last_error_code"] = reg->error_code;
        r["last_error_reason"] = reg->error_reason;
        r["last_error_initiator"] = getSIPRegistationErrorInitiatorString(reg->error_initiatior);
    } else {
        r["last_error_code"] = 0;
        r["last_error_reason"] = AmArg();
        r["last_error_initiator"] = AmArg();
    }
    if(reg->postponed) {
        r["postpone_timeout_msec"] =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                    reg->postponed_next_attempt-now).count();
    } else {
        r["postpone_timeout_msec"] = 0;
    }
    ret.push(r);
}

extern "C" void* plugin_class_create()
{
    SIPRegistrarClient* reg_c = SIPRegistrarClient::instance();
    assert(dynamic_cast<AmDynInvokeFactory*>(reg_c));
    return (AmPluginFactory*)reg_c;
}

//-----------------------------------------------------------
SIPRegistrarClient* SIPRegistrarClient::_instance=0;

SIPRegistrarClient* SIPRegistrarClient::instance()
{
    if(_instance == NULL){
        _instance = new SIPRegistrarClient(MOD_NAME);
    }
    return _instance;
}

SIPRegistrarClient::SIPRegistrarClient(const string& name)
  : AmEventFdQueue(this),
    uac_auth_i(NULL),
    AmDynInvokeFactory(MOD_NAME),
    stopped(false),
    default_expires(DEFAULT_EXPIRES)
{ }

void SIPRegistrarClient::run()
{
    int ret;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("sip-reg-client");

    DBG("SIPRegistrarClient starting...\n");

    AmDynInvokeFactory* uac_auth_f = AmPlugIn::instance()->getFactory4Di("uac_auth");
    if (uac_auth_f == NULL) {
        DBG("unable to get a uac_auth factory. registrations will not be authenticated.\n");
        DBG("(do you want to load uac_auth module?)\n");
    } else {
        uac_auth_i = uac_auth_f->getInstance();
    }

    AmEventDispatcher::instance()->addEventQueue(REG_CLIENT_QUEUE, this);

    /*
    while (!stop_requested.get()) {
        if (registrations.size()) {
            unsigned int cnt = 250;
            while (cnt > 0) {
                usleep(2000); // every 2 ms
                if(stop_requested.get())
                    break;
                processEvents();
                cnt--;
            }
            checkTimeouts();
        } else {
            waitForEvent();
            processEvents();
        }
    }*/

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int f = e.data.fd;

            if(!(e.events & EPOLLIN)){
                continue;
            }

            if(f==timer){
                checkTimeouts();
                timer.read();
            } else if(f== -queue_fd()){
                clear_pending();
                processEvents();
            } else if(f==stop_event){
                stop_event.read();
                running = false;
                break;
            }
        }
    } while(running);

    AmEventDispatcher::instance()->delEventQueue(REG_CLIENT_QUEUE);
    epoll_unlink(epoll_fd);
    close(epoll_fd);

    onServerShutdown();
    stopped.set(true);
}

void SIPRegistrarClient::checkTimeouts()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    RegShaper::timep now_point(std::chrono::system_clock::now());
    reg_mut.lock();
    vector<string> remove_regs;

    for (map<string, AmSIPRegistration*>::iterator it = registrations.begin();
        it != registrations.end(); it++)
    {
        AmSIPRegistration* reg = it->second;
        if (reg->postponed) {
            if(reg->postponingExpired(now_point)) {
                reg->onPostponeExpired();
            }
        } else if (reg->active) {
            if (reg->registerExpired(now.tv_sec)) {
                reg->onRegisterExpired();
            } else if (!reg->waiting_result &&
                       reg->timeToReregister(now.tv_sec))
            {
                reg->doRegistration();
            }
        } else if (reg->remove) {
            remove_regs.push_back(it->first);
        } else if (!reg->waiting_result && reg->error_code!=0 &&
                   reg->registerSendTimeout(now.tv_sec))
        {
            reg->onRegisterSendTimeout();
        }
    }

    for (vector<string>::iterator it = remove_regs.begin();
         it != remove_regs.end(); it++)
    {
        AmSIPRegistration *reg = remove_reg_unsafe(*it);
        if (reg)
            delete reg;
    }

    reg_mut.unlock();
}

bool SIPRegistrarClient::configure()
{
    if((epoll_fd = epoll_create(3)) == -1){
        ERROR("epoll_create call failed");
        return false;
    }

    epoll_link(epoll_fd);
    stop_event.link(epoll_fd);

    timer.set(TIMEOUT_CHECKING_INTERVAL);
    timer.link(epoll_fd);

    AmConfigReader cfg;
    if(cfg.loadFile(AmConfig.configs_path + string(MOD_NAME ".conf"))) {
        DBG("missed or wrong configuration file. shaper will be disabled by default");
        return true;
    }
    if(cfg.hasParameter(CFG_OPT_NAME_SHAPER_MIN_INTERVAL)) {
        int i = cfg.getParameterInt(CFG_OPT_NAME_SHAPER_MIN_INTERVAL);
        if(i) {
            DBG("set shaper min interval to %dmsec",i);
            if(i < (TIMEOUT_CHECKING_INTERVAL/1000)) {
                WARN("shaper min interval %dmsec is less than timer interval %dmsec. "
                     "set it to timer interval",
                     i,(TIMEOUT_CHECKING_INTERVAL/1000));
                i = TIMEOUT_CHECKING_INTERVAL/1000;
            }
            shaper.set_min_interval(i);
        }
    }
    default_expires = cfg.getParameterInt(CFG_OPT_NAME_DEFAULT_EXPIRES,DEFAULT_EXPIRES);
    return true;
}

int SIPRegistrarClient::onLoad()
{
    if(!instance()->configure()) {
        ERROR("registrar_client configuration error");
        return -1;
    }
    instance()->start();
    return 0;
}

void SIPRegistrarClient::onServerShutdown()
{
    // TODO: properly wait until unregistered, with timeout
    DBG("shutdown SIP registrar client: deregistering\n");
    for (std::map<std::string, AmSIPRegistration*>::iterator it=
         registrations.begin(); it != registrations.end(); it++)
    {
        it->second->doUnregister();
        AmEventDispatcher::instance()->delEventQueue(it->first);
    }
}

void SIPRegistrarClient::process(AmEvent* ev) 
{
    if (ev->event_id == E_SYSTEM) {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev){
            DBG("Session received system Event\n");
            if (sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
                stop_event.fire();
            }
            return;
        }
    }

    AmSipReplyEvent* sip_rep = dynamic_cast<AmSipReplyEvent*>(ev);
    if (sip_rep) {
        onSipReplyEvent(sip_rep);
        return;
    }

    SIPNewRegistrationEvent* new_reg = dynamic_cast<SIPNewRegistrationEvent*>(ev);
    if (new_reg) {
        onNewRegistration(new_reg);
        return;
    }

    SIPRemoveRegistrationEvent* rem_reg = dynamic_cast<SIPRemoveRegistrationEvent*>(ev);
    if (rem_reg) {
        onRemoveRegistration(rem_reg);
        return;
    }

    BusReplyEvent *bus_event = dynamic_cast<BusReplyEvent *>(ev);
    if(bus_event) {
        onBusEvent(bus_event);
        return;
    }

    DBG("got unknown event. ignore");
}

void SIPRegistrarClient::onSipReplyEvent(AmSipReplyEvent* ev)
{
    AmSIPRegistration* reg = get_reg(ev->reply.from_tag);
    if (reg != NULL) {
        reg->getDlg()->onRxReply(ev->reply);
    }
}

void SIPRegistrarClient::onNewRegistration(SIPNewRegistrationEvent* new_reg)
{
    AmSIPRegistration* reg =
        new AmSIPRegistration(new_reg->handle,
                              new_reg->info,
                              new_reg->sess_link,
                              shaper);

    if (uac_auth_i != NULL) {
        DBG("enabling UAC Auth for new registration.\n");
        // get a sessionEventHandler from uac_auth
        AmArg di_args,ret;
        AmArg a;
        a.setBorrowedPointer(reg);
        di_args.push(a);
        di_args.push(a);

        uac_auth_i->invoke("getHandler", di_args, ret);
        if (!ret.size()) {
            ERROR("Can not add auth handler to new registration!\n");
        } else {
            AmObject* p = ret.get(0).asObject();
            if (p != NULL) {
                AmSessionEventHandler* h = dynamic_cast<AmSessionEventHandler*>(p);
                if (h != NULL)
                    reg->setSessionEventHandler(h);
            }
        }
    }

    if(new_reg->info.expires_interval!=0)
        reg->setExpiresInterval(new_reg->info.expires_interval);
    else
        reg->setExpiresInterval(default_expires);

    if(new_reg->info.force_expires_interval)
        reg->setForceExpiresInterval(true);

    if(!add_reg(new_reg->handle, reg))
        return;

    reg->doRegistration();
}

void SIPRegistrarClient::onRemoveRegistration(SIPRemoveRegistrationEvent* reg)
{
    reg_mut.lock();

    RegHash::iterator it;

    if(reg->is_id) {
        RegHash::iterator id_it = registrations_by_id.find(reg->handle_or_id);
        if(id_it==registrations_by_id.end()) {
            reg_mut.unlock();
            DBG("onRemoveRegistration: remove event with not existent id: %s",
                reg->handle_or_id.c_str());
            return;
        }
        it = registrations.find(id_it->second->getHandle());
        if(it==registrations.end()) {
            ERROR("onRemoveRegistration: inconsistence. "
                  "handle %s by id %s is not exist in hash by handlers. "
                  "remove it from registrations_by_id hash",
                  id_it->second->getHandle().c_str(),
                  reg->handle_or_id.c_str());
            registrations_by_id.erase(id_it);
            reg_mut.unlock();
            return;
        }
    } else {
        it = registrations.find(reg->handle_or_id);
        if(it==registrations.end()) {
            reg_mut.unlock();
            DBG("onRemoveRegistration: remove event with not existent handle: %s",
                reg->handle_or_id.c_str());
            return;
        }
    }

    AmSIPRegistration *_reg = it->second;

    registrations_by_id.erase(_reg->getInfo().id);

    reg_mut.unlock();

    _reg->doUnregister();
}

void SIPRegistrarClient::processAmArgRegistration(AmArg &data)
{
#define DEF_AND_VALIDATE_OPTIONAL_STR(key) \
    string key; \
    if(data.hasMember(#key)) { \
        AmArg & key ## _arg = data[#key]; \
        if(!isArgCStr(key ## _arg)) { ERROR("unexpected '" #key "' type. expected string"); return; } \
        key = key ## _arg.asCStr(); \
    }

#define DEF_AND_VALIDATE_OPTIONAL_INT(key,default_value) \
    int key = default_value; \
    if(data.hasMember(#key)) { \
        AmArg & key ## _arg = data[#key]; \
        if(!isArgInt(key ## _arg)) { ERROR("unexpected '" #key "' type. expected integer"); return; } \
        key = key ## _arg.asInt(); \
    }

#define DEF_AND_VALIDATE_MANDATORY_STR(key) \
    if(!data.hasMember(#key)) { ERROR("missed '" #key "' in BusReplyEvent payload");return; } \
    AmArg & key ## _arg = data[#key]; \
    if(!isArgCStr(key ## _arg)) { ERROR("unexpected '" #key "' type. expected string"); return; } \
    string key = key ## _arg.asCStr();

    if(!isArgStruct(data)) { ERROR("unexpected payload type in BusReplyEvent"); return; }

    DEF_AND_VALIDATE_MANDATORY_STR(action);
    if(action=="create") {
        //DEF_AND_VALIDATE_MANDATORY_STR(id);
        if(!data.hasMember("id")) { ERROR("missed 'id' in BusReplyEvent payload");return; }
        AmArg &id_arg = data["id"];
        string id;
        if(isArgCStr(id_arg)) {
            id = id_arg.asCStr();
        } else if(isArgInt(id_arg)) {
            id = int2str(id_arg.asInt());
        } else {
            ERROR("unexpected 'id' type. expected string or integer");
            return;
        }

        DEF_AND_VALIDATE_MANDATORY_STR(domain);
        DEF_AND_VALIDATE_OPTIONAL_STR(user);
        DEF_AND_VALIDATE_OPTIONAL_STR(name);
        DEF_AND_VALIDATE_OPTIONAL_STR(auth_username);
        DEF_AND_VALIDATE_OPTIONAL_STR(auth_password);
        DEF_AND_VALIDATE_OPTIONAL_STR(sess_link);
        DEF_AND_VALIDATE_OPTIONAL_STR(proxy);
        DEF_AND_VALIDATE_OPTIONAL_STR(contact);
        DEF_AND_VALIDATE_OPTIONAL_STR(contact_params);
        DEF_AND_VALIDATE_OPTIONAL_STR(handle);

        DEF_AND_VALIDATE_OPTIONAL_INT(expires,0);
        DEF_AND_VALIDATE_OPTIONAL_INT(force_expires_interval,0);
        DEF_AND_VALIDATE_OPTIONAL_INT(retry_delay,DEFAULT_REGISTER_RETRY_DELAY);
        DEF_AND_VALIDATE_OPTIONAL_INT(max_attempts,REGISTER_ATTEMPTS_UNLIMITED);
        DEF_AND_VALIDATE_OPTIONAL_INT(transport_protocol_id,sip_transport::UDP);
        DEF_AND_VALIDATE_OPTIONAL_INT(proxy_transport_protocol_id,sip_transport::UDP);

        DEF_AND_VALIDATE_OPTIONAL_INT(transaction_timeout,0);
        DEF_AND_VALIDATE_OPTIONAL_INT(srv_failover_timeout,0);

        SIPRegistrarClient::instance()->postEvent(
            new SIPNewRegistrationEvent(
                SIPRegistrationInfo(
                    id,
                    domain,
                    user,
                    name,
                    auth_username,
                    auth_password,
                    proxy,
                    contact,
                    contact_params,
                    expires,
                    force_expires_interval,
                    retry_delay,
                    max_attempts,
                    transport_protocol_id,
                    proxy_transport_protocol_id,
                    transaction_timeout,
                    srv_failover_timeout),
                handle.empty() ? AmSession::getNewId() : handle,
                sess_link
            )
        );
    } else if(action=="remove") {
        if(!data.hasMember("id")) { ERROR("missed 'id' in BusReplyEvent payload");return; }
        AmArg &id_arg = data["id"];
        string id;
        if(isArgCStr(id_arg)) {
            id = id_arg.asCStr();
        } else if(isArgInt(id_arg)) {
            id = int2str(id_arg.asInt());
        } else {
            ERROR("unexpected 'id' type. expected string or integer");
            return;
        }
        removeRegistrationById(id);
    } else if(action=="flush") {
        DBG("flushRegistrations()");
        AmLock l(reg_mut);
        for(const auto &reg: registrations)
            reg.second->doUnregister();
        registrations.clear();
        registrations_by_id.clear();
    } else {
        ERROR("unknown action '%s'",action.c_str());
    }
#undef DEF_AND_VALIDATE_OPTIONAL_STR
#undef DEF_AND_VALIDATE_OPTIONAL_INT
#undef DEF_AND_VALIDATE_MANDATORY_STR
}

void SIPRegistrarClient::onBusEvent(BusReplyEvent* bus_event)
{
    try {
        AmArg &data = bus_event->data;
        if(isArgArray(data)) {
            for (size_t i = 0; i < data.size(); i ++) {
                processAmArgRegistration(data[i]);
            }
        } else {
            processAmArgRegistration(data);
        }
    } catch(AmSession::Exception &e) {
        ERROR("onBusEvent() exception: %d %s",
              e.code,e.reason.c_str());
    } catch(...) {
        ERROR("onBusEvent(0) unknown exception");
    }
}

void SIPRegistrarClient::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}


bool SIPRegistrarClient::onSipReply(const AmSipReply& rep, AmSipDialog::Status old_dlg_status)
{
    DBG("got reply with tag '%s'\n", rep.from_tag.c_str());

    if (instance()->hasRegistration(rep.from_tag)) {
        instance()->postEvent(new AmSipReplyEvent(rep));
        return true;
    } else
        return false;
}

bool SIPRegistrarClient::hasRegistration(const string& handle)
{
    return get_reg(handle) != NULL;
}

AmSIPRegistration* SIPRegistrarClient::get_reg(const string& reg_id) 
{
    DBG("get registration '%s'\n", reg_id.c_str());
    AmSIPRegistration* res = NULL;
    reg_mut.lock();
    map<string, AmSIPRegistration*>::iterator it =
        registrations.find(reg_id);
    if (it!=registrations.end())
        res = it->second;
    reg_mut.unlock();
    DBG("get registration : res = '%ld' (this = %ld)\n", (long)res, (long)this);
    return res;
}

AmSIPRegistration* SIPRegistrarClient::get_reg_unsafe(const string& reg_id) 
{
    //	DBG("get registration_unsafe '%s'\n", reg_id.c_str());
    AmSIPRegistration* res = NULL;
    map<string, AmSIPRegistration*>::iterator it =
        registrations.find(reg_id);
    if (it!=registrations.end())
        res = it->second;
    //     DBG("get registration_unsafe : res = '%ld' (this = %ld)\n", (long)res, (long)this);
    return res;
}

AmSIPRegistration* SIPRegistrarClient::remove_reg(const string& reg_id)
{
    reg_mut.lock();
    AmSIPRegistration* reg = remove_reg_unsafe(reg_id);
    reg_mut.unlock();
    return reg;
}

AmSIPRegistration* SIPRegistrarClient::remove_reg_unsafe(const string& reg_id)
{
    DBG("removing registration %s", reg_id.c_str());
    AmSIPRegistration* reg = NULL;
    map<string, AmSIPRegistration*>::iterator it =
        registrations.find(reg_id);
    if (it!=registrations.end()) {
        reg = it->second;
        registrations.erase(it);
    }
    AmEventDispatcher::instance()->delEventQueue(reg_id);
    return reg;
}

bool SIPRegistrarClient::add_reg(const string& reg_id, AmSIPRegistration* new_reg)
{
    CLASS_DBG("adding registration '%s' with id = '%s'\n",
        reg_id.c_str(), new_reg->getInfo().id.c_str());
    AmSIPRegistration* reg = NULL;
    reg_mut.lock();
    map<string, AmSIPRegistration*>::iterator it =
        registrations.find(reg_id);
    if (it!=registrations.end()) {
        reg = it->second;
    }

    std::pair<RegHash::iterator,bool> ret =
        registrations_by_id.insert(
            RegHashPair(new_reg->getInfo().id,new_reg));
    if(!ret.second) {
        reg_mut.unlock();
        ERROR("duplicate id: %s on create registration %s",
            new_reg->getInfo().id.c_str(),
            reg_id.c_str());
        delete new_reg;
        return false;
    }

    registrations[reg_id] = new_reg;

    AmEventDispatcher::instance()->addEventQueue(reg_id,this);
    reg_mut.unlock();

    if (reg != NULL)
        delete reg; // old one with the same ltag

    return true;
}


// API
string SIPRegistrarClient::createRegistration(
    const string& id,
    const string& domain,
    const string& user,
    const string& name,
    const string& auth_user,
    const string& pwd,
    const string& sess_link,
    const string& proxy,
    const string& contact,
    const int& expires_interval,
    bool &force_expires_interval,
    const int& retry_delay,
    const int& max_attempts,
    const int& transport_protocol_id,
    const int& proxy_transport_protocol_id,
    const int &transaction_timeout,
    const int &srv_failover_timeout,
    const string& handle)
{
    string l_handle = handle.empty() ? AmSession::getNewId() : handle;
    instance()->postEvent(
        new SIPNewRegistrationEvent(
            SIPRegistrationInfo(
                id,
                domain,
                user,
                name,
                auth_user,
                pwd,
                proxy,
                contact,
                string(),
                expires_interval,
                force_expires_interval,
                retry_delay,
                max_attempts,
                transport_protocol_id,
                proxy_transport_protocol_id,
                transaction_timeout,
                srv_failover_timeout),
            l_handle,
            sess_link
        )
    );
    return l_handle;
}

void SIPRegistrarClient::removeRegistration(const string& handle)
{
    instance()->postEvent(new SIPRemoveRegistrationEvent(handle));
}

void SIPRegistrarClient::removeRegistrationById(const string& id)
{
    instance()->postEvent(new SIPRemoveRegistrationEvent(id,true));
}

bool SIPRegistrarClient::getRegistrationState(
    const string& handle,
    unsigned int& state,
    unsigned int& expires_left)
{
    bool res = false;
    reg_mut.lock();

    AmSIPRegistration* reg = get_reg_unsafe(handle);
    if (reg) {
        res = true;
        state = reg->getState();
        expires_left = reg->getExpiresLeft();
    }
    reg_mut.unlock();
    return res;
}

void SIPRegistrarClient::listRegistrations(AmArg& res)
{
    res.assertArray();
    reg_mut.lock();
    RegShaper::timep now(std::chrono::system_clock::now());
    for (map<string, AmSIPRegistration*>::iterator it =
         registrations.begin(); it != registrations.end(); it++)
    {
        reg2arg(it,res,now);
    }
    reg_mut.unlock();
}

void SIPRegistrarClient::showRegistration(const string& handle, AmArg &ret)
{
    AmLock l(reg_mut);
    map<string, AmSIPRegistration*>::iterator it = registrations.find(handle);
    ret.assertArray();
    if(it!=registrations.end())
        reg2arg(it,ret,std::chrono::system_clock::now());
}

void SIPRegistrarClient::showRegistrationById(const string& id, AmArg &ret)
{
    AmLock l(reg_mut);
    RegHash::iterator it = registrations_by_id.find(id);
    ret.assertArray();
    if(it!=registrations_by_id.end())
        reg2arg(it,ret,std::chrono::system_clock::now());
}

void SIPRegistrarClient::getRegistrationsCount(AmArg& res)
{
    reg_mut.lock();
    res = registrations.size();
    reg_mut.unlock();
}

void SIPRegistrarClient::invoke(
    const string& method,
    const AmArg& args,
    AmArg& ret)
{
    if(method == "createRegistration"){
        string proxy, contact, handle;
        int expires_interval = 0,
            force = 0,
            retry_delay = DEFAULT_REGISTER_RETRY_DELAY,
            max_attempts = REGISTER_ATTEMPTS_UNLIMITED,
            transport_protocol_id = sip_transport::UDP,
            proxy_transport_protocol_id = sip_transport::UDP,
            transaction_timeout = 0,
            srv_failover_timeout = 0;
        bool force_expires_interval = false;
        size_t n = args.size();

        do {

        if (n > 7)
            proxy = args.get(7).asCStr();
        else break;

        if (n > 8)
            contact = args.get(8).asCStr();
        else break;

        if (n > 9) {
            AmArg &a = args.get(9);
            if(isArgInt(a)) {
                expires_interval = a.asInt();
            } else if(isArgCStr(a) && !str2int(a.asCStr(), expires_interval)){
                throw AmSession::Exception(500,"wrong expires_interval argument");
            }
        } else break;

        if (n > 10) {
            AmArg &a = args.get(10);
            if(isArgInt(a)) {
                force_expires_interval = a.asInt();
            } else if(isArgCStr(a) && str2int(a.asCStr(), force)){
                force_expires_interval = force;
            } else {
                throw AmSession::Exception(500,"wrong force_expires_interval argument");
            }
        } else break;

        if (args.size() > 11) {
            AmArg &a = args.get(11);
            if(isArgInt(a)) {
                retry_delay = a.asInt();
            } else if(isArgCStr(a) && !str2int(a.asCStr(), retry_delay)){
                throw AmSession::Exception(500,"wrong retry_delay argument");
            }
        } else break;

        if (args.size() > 12) {
            AmArg &a = args.get(12);
            if(isArgInt(a)) {
                max_attempts = a.asInt();
            } else if(isArgCStr(a) && !str2int(a.asCStr(), max_attempts)){
                throw AmSession::Exception(500,"wrong max_attempts argument");
            }
        } else break;

        if (args.size() > 13) {
            AmArg &a = args.get(13);
            if(isArgInt(a)) {
                transport_protocol_id = a.asInt();
            } else if(isArgCStr(a) && !str2int(a.asCStr(), transport_protocol_id)){
                throw AmSession::Exception(500,"wrong transport_protocol_id argument");
            }
        } else break;

        if (args.size() > 14) {
            AmArg &a = args.get(14);
            if(isArgInt(a)) {
                proxy_transport_protocol_id = a.asInt();
            } else if(isArgCStr(a) && !str2int(a.asCStr(), proxy_transport_protocol_id)){
                throw AmSession::Exception(500,"wrong proxy_transport_protocol_id argument");
            }
        } else break;

        if (args.size() > 15) {
            AmArg &a = args.get(15);
            if(isArgInt(a)) {
                transaction_timeout = a.asInt();
            } else if(isArgCStr(a) && !str2int(a.asCStr(), transaction_timeout)){
                throw AmSession::Exception(500,"wrong transaction_timeout argument");
            }
        } else break;

        if (args.size() > 16) {
            AmArg &a = args.get(16);
            if(isArgInt(a)) {
                srv_failover_timeout = a.asInt();
            } else if(isArgCStr(a) && !str2int(a.asCStr(), srv_failover_timeout)){
                throw AmSession::Exception(500,"wrong srv_failover_timeout argument");
            }
        } else break;

        if (args.size() > 17)
            handle = args.get(17).asCStr();
        else break;

        } while(0);

        ret.push(createRegistration(
            args.get(0).asCStr(),
            args.get(1).asCStr(),
            args.get(2).asCStr(),
            args.get(3).asCStr(),
            args.get(4).asCStr(),
            args.get(5).asCStr(),
            args.get(6).asCStr(),
            proxy,
            contact,
            expires_interval,
            force_expires_interval,
            retry_delay,
            max_attempts,
            transport_protocol_id,
            proxy_transport_protocol_id,
            transaction_timeout,
            srv_failover_timeout,
            handle
        ).c_str());
    } else if(method == "removeRegistration") {
        removeRegistration(args.get(0).asCStr());
    } else if(method == "removeRegistrationById") {
        removeRegistrationById(args.get(0).asCStr());
    } else if(method == "getRegistrationState") {
        unsigned int state;
        unsigned int expires;
        if (instance()->getRegistrationState(args.get(0).asCStr(),
            state, expires))
        {
            ret.push(1);
            ret.push((int)state);
            ret.push((int)expires);
        } else {
            ret.push(AmArg((int)0));
        }
    } else if(method == "listRegistrations") {
        listRegistrations(ret);
    } else if(method == "showRegistration") {
        showRegistration(args.get(0).asCStr(),ret);
    } else if(method == "showRegistrationById") {
        showRegistrationById(args.get(0).asCStr(),ret);
    } else if(method == "getRegistrationsCount") {
        getRegistrationsCount(ret);
    } else if(method == "_list") {
        ret.push(AmArg("createRegistration"));
        ret.push(AmArg("removeRegistration"));
        ret.push(AmArg("removeRegistrationById"));
        ret.push(AmArg("getRegistrationState"));
        ret.push(AmArg("listRegistrations"));
        ret.push(AmArg("showRegistration"));
        ret.push(AmArg("showRegistrationById"));
        ret.push(AmArg("getRegistrationsCount"));
    }  else
        throw AmDynInvoke::NotImplemented(method);
}

