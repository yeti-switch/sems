#include "ContactsSubscriptionConnection.h"
#include "AmSipMsg.h"

#define REDIS_REPLY_SUBSCRIPTION 1
#define REDIS_REPLY_CONTACTS_DATA 2

static const string CONTACT_SUBSCR_QUEUE_NAME("reg_async_redis_sub");

ContactsSubscriptionConnection::ContactsSubscriptionConnection()
  : RedisConnectionPool("reg_sub", CONTACT_SUBSCR_QUEUE_NAME),
    max_interval_drift(1),
    max_registrations_per_slot(1),
    load_contacts_script("load_contacts_script")
{}

void ContactsSubscriptionConnection::load_all_scripts(RedisConnection* conn)
{
    if(use_functions) {
        all_scripts_loaded.set(true);
        return;
    }

    if((!conn && this->conn) || (conn && conn == this->conn)) {
        all_scripts_loaded.set(false);
        load_contacts_script.load(this->conn, get_queue_name(), "/etc/sems/scripts/load_contacts.lua");
    }
}

void ContactsSubscriptionConnection::on_connect(RedisConnection* conn)
{
    load_all_scripts(conn);

    if(use_functions) {
        postRedisRequestFmt(conn,
            get_queue_name(), get_queue_name(), false, nullptr,
            REDIS_REPLY_CONTACTS_DATA, "FCALL load_contacts 0");
    }
}

void ContactsSubscriptionConnection::process_reply_event(RedisReplyEvent &event)
{
    /*DBG("ContactsSubscriptionConnection got event %d. data: %s",
        event.user_type_id, AmArg::print(event.data).c_str());*/

    switch(event.user_type_id) {
    case REDIS_REPLY_SCRIPT_LOAD:
        process_reply_script_load(event);
        break;
    case REDIS_REPLY_SUBSCRIPTION:
        if(isArgArray(event.data) &&
           event.data.size() == 3)
        {
            process_expired_key(event.data[2]);
        }
        break;
    case REDIS_REPLY_CONTACTS_DATA:
        process_loaded_contacts(event.data);
        break;
    }
}

void ContactsSubscriptionConnection::script_loaded(const RedisScript *script, const char *hash)
{
    if(script == &load_contacts_script) {
        load_contacts_script.hash = hash;
        all_scripts_loaded.set(true);

        //execute load_contacts_script
        if(!postRedisRequestFmt(conn, get_queue_name(), get_queue_name(), false,
            nullptr, REDIS_REPLY_CONTACTS_DATA,
            "EVALSHA %s 0", load_contacts_script.hash.c_str()))
        {
            ERROR("failed to execute load_contacts lua script");
        }
    }
}

void ContactsSubscriptionConnection::keepalive_ctx_data::dump(
    const std::string &key,
    const std::chrono::system_clock::time_point &now) const
{
    DBG("keepalive_context. key: '%s', "
        "aor: '%s', path: '%s', interface_id: %d, "
        "next_send-now: %d",
        key.c_str(),
        aor.data(), path.data(), interface_id,
        std::chrono::duration_cast<std::chrono::seconds>(
            next_send - now).count());
}

void ContactsSubscriptionConnection::keepalive_ctx_data::dump(
    const std::string &key, AmArg &ret,
    const std::chrono::system_clock::time_point &now) const
{
    ret["key"] = key;
    ret["aor"] = aor;
    ret["path"] = path;
    ret["interface_id"] = interface_id;
    ret["next_send_in"] =
        std::chrono::duration_cast<std::chrono::seconds>(
            next_send - now).count();
}

void ContactsSubscriptionConnection::KeepAliveContexts::dump()
{
    //AmLock l(mutex);
    auto now{std::chrono::system_clock::now()};
    DBG("%zd keepalive contexts", size());
    for(const auto &i : *this) {
        i.second.dump(i.first, now);
    }
}

void ContactsSubscriptionConnection::KeepAliveContexts::dump(AmArg &ret)
{
    ret.assertArray();
    auto now{std::chrono::system_clock::now()};
    AmLock l(mutex);
    for(const auto &i : *this) {
        ret.push(AmArg());
        i.second.dump(i.first, ret.back(), now);
    }
}

void ContactsSubscriptionConnection::process_loaded_contacts(const AmArg &data)
{
    clearKeepAliveContexts();

    if(!isArgArray(data))
        return;

    std::chrono::seconds keepalive_interval_offset{0};

    DBG("process_loaded_contacts");
    int n = static_cast<int>(data.size());
    for(int i = 0; i < n; i++) {
        AmArg &d = data[i];
        if(!isArgArray(d) || d.size() != 4) //validate
            continue;
        if(arg2int(d[0]) != AmConfig.node_id) //skip other nodes registrations
            continue;
        DBG("process contact: %s",AmArg::print(d).c_str());

        string key(d[3].asCStr());

        auto pos = key.find_first_of(':');
        if(pos == string::npos) {
            ERROR("wrong key format: %s",key.c_str());
            continue;
        }
        pos = key.find_first_of(':',pos+1);
        if(pos == string::npos) {
            ERROR("wrong key format: %s",key.c_str());
            continue;
        }
        pos++;

        createOrUpdateKeepAliveContext(
            key,
            key.substr(pos), //aor
            d[1].asCStr(),   //path
            arg2int(d[2]),   //interface_id
            keepalive_interval_offset - keepalive_interval);

        keepalive_interval_offset++;
        keepalive_interval_offset %= keepalive_interval;
    }

    //keepalive_contexts.dump();

    //subscribe to del/expire events
    if(!postRedisRequestFmt(conn,
        get_queue_name(), get_queue_name(), true,
        nullptr, REDIS_REPLY_SUBSCRIPTION,
        //"PSUBSCRIBE __keyspace@0__:c:*",
        "SUBSCRIBE __keyevent@0__:expired __keyevent@0__:del"))
    {
        ERROR("failed to subscribe");
    }
}

void ContactsSubscriptionConnection::process_expired_key(const AmArg &key_arg)
{
    if(!isArgCStr(key_arg)) //skip 'subscription' replies
        return;

    DBG("process expired/removed key: '%s'", key_arg.asCStr());

    removeKeepAliveContext(key_arg.asCStr());
}

/* Configurable */
int ContactsSubscriptionConnection::configure(cfg_t* cfg)
{
    auto reg_redis = cfg_getsec(cfg, CFG_SEC_REDIS);
    if(!reg_redis)
        return -1;

    use_functions = cfg_getbool(reg_redis, CFG_PARAM_USE_FUNCTIONS);
    keepalive_interval = std::chrono::seconds{cfg_getint(cfg, CFG_PARAM_KEEPALIVE_INTERVAL)};
    max_interval_drift = keepalive_interval/10; //allow 10% interval drift

    auto reg_redis_read = cfg_getsec(reg_redis, CFG_SEC_READ);
    if(!reg_redis_read)
        return -1;

    int ret = RedisConnectionPool::init();
    if(ret)
        return -1;

    if(init_connection(reg_redis_read, conn))
        return -1;

    return 0;
}

void ContactsSubscriptionConnection::process_sip_reply(const AmSipReplyEvent *reply_ev) {
    //DBG("got redis reply. check in local hash");
    AmLock l(uac_dlgs_mutex);
    auto it = uac_dlgs.find(reply_ev->reply.callid);
    if(it != uac_dlgs.end()) {
        //DBG("found ctx. remove dlg");
        delete it->second;
        uac_dlgs.erase(it);
    }
    return;
}

int ContactsSubscriptionConnection::init_connection(cfg_t* cfg, RedisConnection*& c)
{
    string host = cfg_getstr(cfg, CFG_PARAM_HOST);
    int port = cfg_getint(cfg, CFG_PARAM_PORT);

    c = addConnection(host, port);
    if(!c) return -1;

    if(cfg_size(cfg, CFG_PARAM_PASSWORD)) {
        string username;
        string password = cfg_getstr(cfg, CFG_PARAM_PASSWORD);
        if(cfg_size(cfg, CFG_PARAM_USERNAME))
            username = cfg_getstr(cfg, CFG_PARAM_USERNAME);
        c->set_auth_data(password, username);
    }

    return 0;
}

void ContactsSubscriptionConnection::process(AmEvent* ev)
{
    AmSipReplyEvent *reply_ev;
    if(-1 == ev->event_id && (reply_ev = dynamic_cast<AmSipReplyEvent *>(ev)))
    {
        process_sip_reply(reply_ev);
    }
    RedisConnectionPool::process(ev);
}

void ContactsSubscriptionConnection::createOrUpdateKeepAliveContext(
    const string &key,
    const string &aor,
    const string &path,
    int interface_id,
    const std::chrono::seconds &keep_alive_interval_offset)
{
    auto next_time =
        std::chrono::system_clock::now() +
        keepalive_interval + keep_alive_interval_offset;

    AmLock l(keepalive_contexts.mutex);

    auto it = keepalive_contexts.find(key);
    if(it == keepalive_contexts.end()) {
        keepalive_contexts.try_emplace(
            key,
            aor, path, interface_id, next_time);
        return;
    }

    it->second.update(aor, path, interface_id, next_time);
}

void ContactsSubscriptionConnection::removeKeepAliveContext(const std::string &key)
{
    AmLock l(keepalive_contexts.mutex);
    keepalive_contexts.erase(key);
}

void ContactsSubscriptionConnection::clearKeepAliveContexts()
{
    AmLock l(keepalive_contexts.mutex);
    keepalive_contexts.clear();
}

void ContactsSubscriptionConnection::on_keepalive_timer()
{
    auto now{std::chrono::system_clock::now()};
    uint32_t sent = 0;
    std::chrono::seconds drift_interval{0};
    auto double_max_interval_drift = max_interval_drift*2;

    //DBG("on keepalive timer");
    AmLock l(keepalive_contexts.mutex);

    for(auto &ctx_it : keepalive_contexts) {
        auto &ctx = ctx_it.second;

        if(now < ctx.next_send) continue;

        sent++;
        //send OPTIONS query for each ctx
        std::unique_ptr<AmSipDialog> dlg(new AmSipDialog());

        dlg->setRemoteUri(ctx.aor);
        dlg->setLocalParty(ctx.aor); //TODO: configurable From
        dlg->setRemoteParty(ctx.aor);

        if(!ctx.path.empty())
            dlg->setRouteSet(ctx.path);
        //dlg->setOutboundInterface(ctx.interface_id);

        dlg->setLocalTag(CONTACT_SUBSCR_QUEUE_NAME); //From-tag and queue to handle replies
        dlg->setCallid(AmSession::getNewId());

        if(0==dlg->sendRequest(SIP_METH_OPTIONS))
        {
            //add dlg to local hash
            AmLock uac_l(uac_dlgs_mutex);
            auto dlg_ptr = dlg.release();
            uac_dlgs.emplace(dlg_ptr->getCallid(), dlg_ptr);
        } else {
            ERROR("failed to send keep alive OPTIONS request for %s",
                ctx.aor.data());
        }

        ctx.next_send += keepalive_interval;

        if(sent > max_registrations_per_slot) {
            //cycle drift_interval over the range: [ 0, 2*max_interval_drift ]
            drift_interval++;
            drift_interval %= double_max_interval_drift;

            /* adjust around keepalive_interval
             * within the range: [ -max_interval_drift, max_interval_drift ] */
            ctx.next_send += drift_interval - max_interval_drift;
        }
    }
}

