#include "SipRegistrar.h"
#include "log.h"
#include "AmEventDispatcher.h"
#include "AmSipDialog.h"
#include "AmUriParser.h"
#include "AmUtils.h"
#include "sip/defs.h"
#include "sip/parse_nameaddr.h"
#include "Config.h"

#include <map>
using std::map;

#include <vector>
using std::vector;

#define EPOLL_MAX_EVENTS    2048

#define REDIS_REGISTER_TYPE_ID 0
#define REDIS_AOR_LOOKUP_TYPE_ID 1
#define REDIS_BLOCKING_REQ_CTX_TYPE_ID 2

/* SipRegistrarFactory */

class SipRegistrarFactory
  : public AmConfigFactory,
    public AmSessionFactory,
    public AmDynInvokeFactory
{
    private:
        SipRegistrarFactory(const string& name)
          : AmConfigFactory(name),
            AmSessionFactory(name),
            AmDynInvokeFactory(name)
        {
            SipRegistrar::instance();
        }
        ~SipRegistrarFactory()
        {
            SipRegistrar::dispose();
        }
    public:
        DECLARE_FACTORY_INSTANCE(SipRegistrarFactory);

        AmDynInvoke* getInstance() {
            return SipRegistrar::instance();
        }

        int onLoad() {
            return SipRegistrar::instance()->onLoad();
        }

        void on_destroy() {
            SipRegistrar::instance()->stop();
        }

        /* AmConfigFactory */

        int configure(const string& config) {
            return SipRegistrar::instance()->configure(config);
        }

        int reconfigure(const string& config) {
            return SipRegistrar::instance()->reconfigure(config);
        }

        /* AmSessionFactory */

        AmSession* onInvite(const AmSipRequest& req, const string& app_name,
                            const map<string,string>& app_params)
        {
            AmSipDialog::reply_error(req,501,"Not Implemented");
            return NULL;
        }

        void onOoDRequest(const AmSipRequest& req) {
            AmSessionContainer::instance()->postEvent(
                SIP_REGISTRAR_QUEUE,
                new SipRegistrarRegisterRequestEvent(req, string(), "17")); // !!! 17 // FIXME: need to remove 17
        }
};

EXPORT_PLUGIN_CLASS_FACTORY(SipRegistrarFactory);
EXPORT_PLUGIN_CONF_FACTORY(SipRegistrarFactory);
EXPORT_SESSION_FACTORY(SipRegistrarFactory);
DEFINE_FACTORY_INSTANCE(SipRegistrarFactory, MOD_NAME);

/* aor_lookup_reply */

struct aor_lookup_reply {
    /* reply layout:
     * [
     *   auth_id1,
     *   [
     *     contact1,
     *     path1,
     *     contact2,
     *     path2
     *   ],
     *   auth_id2,
     *   [
     *     contact3,
     *     path3,
     *   ],
     * ]
     */

    Aors aors;

    //return false on errors
    bool parse(const RedisReplyEvent &e)
    {
        if(RedisReplyEvent::SuccessReply!=e.result) {
            ERROR("error reply from redis %d %s",
                e.result,
                AmArg::print(e.data).c_str());
            return false;
        }
        if(!isArgArray(e.data) || e.data.size()%2!=0) {
            ERROR("unexpected redis reply layout: %s", AmArg::print(e.data).data());
            return false;
        }
        int n = static_cast<int>(e.data.size())-1;
        for(int i = 0; i < n; i+=2) {
            AmArg &id_arg = e.data[i];
            if(!isArgCStr(id_arg)) {
                ERROR("unexpected auth_id type. skip entry");
                continue;
            }

            RegistrationIdType reg_id = id_arg.asCStr();

            AmArg &aor_data_arg = e.data[i+1];
            if(!isArgArray(aor_data_arg) || aor_data_arg.size()%2!=0) {
                ERROR("unexpected aor_data_arg layout. skip entry");
                continue;
            }

            int m = static_cast<int>(aor_data_arg.size())-1;
            for(int j = 0; j < m; j+=2) {
                AmArg &contact_arg = aor_data_arg[j];
                AmArg &path_arg = aor_data_arg[j+1];
                if(!isArgCStr(contact_arg) || !isArgCStr(path_arg)) {
                    ERROR("unexpected contact_arg||path_arg type. skip entry");
                    continue;
                }

                auto it = aors.find(reg_id);
                if(it == aors.end()) {
                    it = aors.insert(aors.begin(),
                        std::pair<RegistrationIdType,
                                  std::list<AorData> >(reg_id,  std::list<AorData>()));
                }
                it->second.emplace_back(contact_arg.asCStr(), path_arg.asCStr());
            }
        }
        return true;
    }
};

/* RedisRequestUserData */

class RedisRequestUserData
  : public AmObject
{
  public:
    string session_id;
    std::unique_ptr<AmSipRequest> req;

    RedisRequestUserData(string session_id)
        : AmObject(),
          session_id(session_id),
          req(nullptr)
    {}

    RedisRequestUserData(string session_id, const AmSipRequest& req)
        : AmObject(),
          session_id(session_id),
          req(new AmSipRequest(req))
    {}
};

/* RedisBlockingRequestCtx */

struct RedisBlockingRequestCtx
  : public AmObject
{
  public:
    AmCondition<bool> cond;
    RedisReplyEvent::result_type result;
    AmArg data;
};

/* SipRegistrar */

SipRegistrar* SipRegistrar::_instance = NULL;

SipRegistrar* SipRegistrar::instance()
{
    if(_instance == nullptr){
        _instance = new SipRegistrar();
    }
    return _instance;
}

void SipRegistrar::dispose()
{
    if(_instance != nullptr){
        delete _instance;
    }
    _instance = nullptr;
}

SipRegistrar::SipRegistrar()
  : AmEventFdQueue(this)
{
    makeRedisInstance(false);
    AmEventDispatcher::instance()->addEventQueue(SIP_REGISTRAR_QUEUE, this);
}

SipRegistrar::~SipRegistrar()
{
    AmEventDispatcher::instance()->delEventQueue(SIP_REGISTRAR_QUEUE);
    freeRedisInstance();
}

int SipRegistrar::onLoad()
{
    if(init()){
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

int SipRegistrar::configure(const std::string& config)
{
    return SipRegistrarConfig::parse(config,
        {this, &registrar_redis, &contacts_subscription});
}

int SipRegistrar::reconfigure(const std::string& config)
{
    return configure(config);
}

int SipRegistrar::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd,true);

    init_rpc();

    registrar_redis.start();

    if(keepalive_interval) {
        contacts_subscription.start();
        keepalive_timer.link(epoll_fd);
        keepalive_timer.set(1000000 /* 1 seconds */,true);
    }

    DBG("SIPRegistrar initialized");
    return 0;
}

/* AmThread */

void SipRegistrar::run()
{
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("sip-registrar");

    running = true;
    do {
        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;

            if(p==static_cast<AmEventFdQueue *>(this)){
                processEvents();
            } else if(p==&stop_event){
                stop_event.read();
                running = false;
                break;
            }

            if(e.data.fd==keepalive_timer){
                contacts_subscription.on_keepalive_timer();
                keepalive_timer.read();
                break;
            }
        }
    } while(running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("SIPRegistrar stopped");

    stopped.set(true);
}

void SipRegistrar::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
    registrar_redis.stop();

    if(keepalive_interval)
        contacts_subscription.stop();
}

int SipRegistrar::configure(cfg_t* cfg)
{
    expires_min = cfg_getint(cfg, CFG_PARAM_EXPIRES_MIN);
    expires_max = cfg_getint(cfg, CFG_PARAM_EXPIRES_MAX);
    expires_default = cfg_getint(cfg, CFG_PARAM_EXPIRES_DEFAULT);
    keepalive_interval = cfg_getint(cfg, CFG_PARAM_KEEPALIVE_INTERVAL);
    return 0;
}

/* RPC */

void SipRegistrar::rpc_show_aors(const AmArg& arg, AmArg& ret)
{
    size_t i,j;

    RedisBlockingRequestCtx ctx;
    registrar_redis.rpc_resolve_aors(&ctx, REDIS_BLOCKING_REQ_CTX_TYPE_ID, SIP_REGISTRAR_QUEUE, arg);
    ctx.cond.wait_for();

    if(RedisReplyEvent::SuccessReply!=ctx.result)
        throw AmSession::Exception(500, AmArg::print(ctx.data));

    if(!isArgArray(ctx.data) || ctx.data.size()%2!=0)
        throw AmSession::Exception(500, "unexpected redis reply");

    DBG("%s", AmArg::print(ctx.data).c_str());
    ret.assertArray();

    for(i = 0; i < ctx.data.size(); i+=2) {
        AmArg &id_arg = ctx.data[i];
        if(!isArgCStr(id_arg)) {
            ERROR("unexpected auth_id type. skip entry");
            continue;
        }

        AmArg &aor_data_arg = ctx.data[i+1];
        if(!isArgArray(aor_data_arg)) {
                ERROR("unexpected aor_data_arg layout. skip entry");
                continue;
        }

        for(j = 0; j < aor_data_arg.size(); j++) {
            AmArg &aor_entry_arg = aor_data_arg[j];
            if(!isArgArray(aor_entry_arg) || aor_entry_arg.size() != 7) {
                ERROR("unexpected aor_entry_arg layout. skip entry");
                continue;
            }

            ret.push(AmArg());
            AmArg &r = ret.back();
            r["auth_id"] = id_arg;
            r["contact"]  = aor_entry_arg[0];
            r["expires"]  = aor_entry_arg[1];
            r["node_id"]  = aor_entry_arg[3];
            r["interface_id"]  = aor_entry_arg[4];
            r["user_agent"]  = aor_entry_arg[5];
            r["path"]  = aor_entry_arg[6];
        }
    }
}

void SipRegistrar::rpc_show_keepalive_contexts(const AmArg&, AmArg& ret)
{
    contacts_subscription.dumpKeepAliveContexts(ret);
}

void SipRegistrar::rpc_bind(const AmArg& arg, AmArg& ret)
{
    RedisBlockingRequestCtx ctx;
    registrar_redis.rpc_bind(&ctx, REDIS_BLOCKING_REQ_CTX_TYPE_ID, SIP_REGISTRAR_QUEUE, arg);
    ctx.cond.wait_for();

    if(RedisReplyEvent::SuccessReply!=ctx.result)
        throw AmSession::Exception(500, AmArg::print(ctx.data));

    if(!isArgArray(ctx.data))
        throw AmSession::Exception(500, "unexpected redis reply");

    if(ctx.data.size() == 0) {
        DBG("zero ctx.data.size reply from redis. no bindings");
        ret = "";
        return;
    }

    DBG("%s", AmArg::print(ctx.data).c_str());

    // parse data and fill ret
    int n = static_cast<int>(ctx.data.size());
    for(int i = 0; i < n; ++i) {
        AmArg &d = ctx.data[i];
        if(!isArgArray(d) || d.size()!=5) {
            ERROR("unexpected AoR layout in reply from redis: %s. skip it", AmArg::print(d).c_str());
            continue;
        }

        ret.push(AmArg());
        AmArg &r = ret.back();
        r["contact"] = d[0];
        r["expires"] = d[1];
        r["key"] = d[2];
        r["path"] = d[3];
        r["interface_id"] = d[4];

        if(keepalive_interval) {
            //update KeepAliveContexts
            contacts_subscription.createOrUpdateKeepAliveContext(
                d[2].asCStr(),  //key
                d[0].asCStr(),  //aor
                d[3].asCStr(),  //path
                arg2int(d[4])   //interface_id
            );
        }
    }
}

void SipRegistrar::rpc_unbind(const AmArg& arg, AmArg& ret)
{
    RedisBlockingRequestCtx ctx;
    registrar_redis.rpc_unbind(&ctx, REDIS_BLOCKING_REQ_CTX_TYPE_ID, SIP_REGISTRAR_QUEUE, arg);
    ctx.cond.wait_for();

    if(RedisReplyEvent::SuccessReply!=ctx.result)
        throw AmSession::Exception(500, AmArg::print(ctx.data));

    DBG("%s", AmArg::print(ctx.data).c_str());

    if(isArgUndef(ctx.data)) {
        DBG("nil reply from redis. no bindings");
        ret = "";
        return;
    }

    if(!isArgArray(ctx.data))
        throw AmSession::Exception(500, "unexpected redis reply");

    if(ctx.data.size() == 0) {
        DBG("zero ctx.data.size reply from redis. no bindings");
        ret = "";
        return;
    }

    // parse data and fill ret
    int n = static_cast<int>(ctx.data.size());
    for(int i = 0; i < n; ++i) {
        AmArg &d = ctx.data[i];
        if(!isArgArray(d) || d.size()!=5) {
            ERROR("unexpected AoR layout in reply from redis: %s. skip it", AmArg::print(d).c_str());
            continue;
        }

        ret.push(AmArg());
        AmArg &r = ret.back();
        r["contact"] = d[0];
        r["expires"] = d[1];
        r["key"] = d[2];
        r["path"] = d[3];
        r["interface_id"] = d[4];
    }
}

/* AmEventHandler */

void SipRegistrar::process(AmEvent* event)
{
    INFO("process ev %d", event->event_id);
    switch(event->event_id) {
        case E_SYSTEM: {
            AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(event);
            if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown)
                stop_event.fire();

            return;
        }

        case REDIS_REPLY_EVENT_ID:
            if(auto e = dynamic_cast<RedisReplyEvent*>(event)) {
                process_redis_reply_event(*e);
                return;
            }
            break;
    }

    switch(event->event_id) {
        case SipRegistrarEvent::RegisterRequest:
            if(auto e = dynamic_cast<SipRegistrarRegisterRequestEvent*>(event)) {
                process_register_request_event(*e);
                return;
            }
            break;

        case SipRegistrarEvent::ResolveAors:
            if(auto e = dynamic_cast<SipRegistrarResolveRequestEvent*>(event)) {
                process_resolve_request_event(*e);
                return;
            }
            break;
    }

    ERROR("got unexpected event ev %d", event->event_id);
}

/* RpcTreeHandler */

void SipRegistrar::init_rpc_tree()
{
    AmArg &show = reg_leaf(root,"show");
    reg_method(show, "aors", "show registered AoRs", &SipRegistrar::rpc_show_aors,"");
    reg_method(show, "keepalive_contexts", "show keepalive contexts",
               &SipRegistrar::rpc_show_keepalive_contexts,"");

    AmArg &request = reg_leaf(root,"request");
    reg_method(request, "bind", "bind contact", &SipRegistrar::rpc_bind,"");
    reg_method(request, "unbind", "unbind contact", &SipRegistrar::rpc_unbind,"");
}

void SipRegistrar::process_register_request_event(SipRegistrarRegisterRequestEvent& event)
{
    const AmSipRequest* req = event.req.get();
    if(!req) {
        ERROR("req is null");
        postRegisterResponse(event.session_id, nullptr, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    static string expires_param_header_name("expires");
    list<cstring> contact_list;
    vector<AmUriParser> contacts;
    bool asterisk_contact = false;

    if(parse_nameaddr_list(contact_list,
        req->contact.c_str(), static_cast<int>(req->contact.length())) < 0)
    {
        DBG("could not parse contact list");
        postRegisterResponse(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    size_t end;
    for(const auto &c: contact_list)
    {
        if(1==c.len && *c.s=='*') {
            asterisk_contact = true;
            continue;
        }
        AmUriParser contact_uri;
        if (!contact_uri.parse_contact(c2stlstr(c), 0, end)) {
            DBG("error parsing contact: '%.*s'",c.len, c.s);
            postRegisterResponse(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
            return;
        } else {
            DBG("successfully parsed contact %s@%s",
            contact_uri.uri_user.c_str(),
            contact_uri.uri_host.c_str());
            contacts.push_back(contact_uri);
        }
    }

    if(asterisk_contact && !contacts.empty()) {
        DBG("additional Contact headers with Contact: *");
        postRegisterResponse(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    if(contacts.empty() && !asterisk_contact) {
        //request bindings list
        auto* user_data = new RedisRequestUserData(event.session_id, *req);

        if(!registrar_redis.fetch_all(user_data, REDIS_REGISTER_TYPE_ID, SIP_REGISTRAR_QUEUE, event.registration_id)) {
            delete user_data;
            user_data = nullptr;

            postRegisterResponse(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }

        return;
    }

    //renew/replace/update binding
    string contact;
    bool expires_found = false;
    string expires;

    if(!asterisk_contact) {
        AmUriParser &first_contact = contacts.front();
        contact = first_contact.uri_str();
        for(auto p: first_contact.params) {
            //DBG("param: %s -> %s",p.first.c_str(),p.second.c_str());
            if(p.first==expires_param_header_name) {
                //DBG("found expires param");
                expires_found = true;
                expires = p.second;
                break;
            }
        }
    }

    if(!expires_found) {
        //try to find Expires header as failover
        size_t start_pos = 0;
        while (start_pos<req->hdrs.length()) {
            size_t name_end, val_begin, val_end, hdr_end;
            int res;
            if ((res = skip_header(req->hdrs, start_pos, name_end, val_begin,
                       val_end, hdr_end)) != 0)
            {
                break;
            }
            if(0==strncasecmp(req->hdrs.c_str() + start_pos,
                              expires_param_header_name.c_str(), name_end-start_pos))
            {
                /*DBG("matched Expires header: %.*s",
                    static_cast<int>(hdr_end-start_pos), req.hdrs.c_str()+start_pos);*/
                expires = req->hdrs.substr(val_begin, val_end-val_begin);
                expires_found = true;
                break;
            }
            start_pos = hdr_end;
        }
    }

    int expires_int = 0;
    if(expires_found) {
        if(!str2int(expires, expires_int)) {
            DBG("failed to cast expires value '%s'",expires.c_str());
            postRegisterResponse(event.session_id, req, 400, "Invalid Request");
            return;
        }

        //check min/max expires
        if(expires_min &&
           expires_int &&
           expires_int < 3600 &&
           expires_int < expires_min)
        {
            DBG("expires %d is lower than allowed min: %d. reply with 423",
                expires_int, expires_min);
            static string min_expires_header =
                SIP_HDR_COL("Min-Expires") + int2str(expires_min) + CRLF;
            postRegisterResponse(event.session_id, req, 423, "Interval Too Brief", min_expires_header);
            return;
        }
        if(expires_max && expires_int > expires_max)
        {
            DBG("expires %d is greater than allowed max: %d. set it to max",
                expires_int, expires_max);
            expires_int = expires_max;
        }
    } else {
        DBG("no either Contact param expire or header Expire. use default value");
        expires_int = expires_default;
    }
    DBG("expires: %d",expires_int);

    if(asterisk_contact) {
        if(expires_int!=0) {
            DBG("non zero expires with Contact: *");
            postRegisterResponse(event.session_id, req, 400, "Invalid Request");
            return;
        }

        //unbind all
        auto* user_data = new RedisRequestUserData(event.session_id, *req);
        if(!registrar_redis.unbind_all(user_data, REDIS_REGISTER_TYPE_ID, SIP_REGISTRAR_QUEUE, event.registration_id)) {
            delete user_data;
            user_data = nullptr;

            postRegisterResponse(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        return;
    }

    //find Path/User-Agent headers
    string path;
    string user_agent;
    size_t start_pos = 0;
    while (start_pos<req->hdrs.length()) {
        size_t name_end, val_begin, val_end, hdr_end;
        int res;
        if ((res = skip_header(req->hdrs, start_pos, name_end, val_begin,
            val_end, hdr_end)) != 0)
        {
            break;
        }
        if(0==strncasecmp(req->hdrs.c_str() + start_pos,
                          SIP_HDR_PATH, name_end-start_pos))
        {
            if(!path.empty()) path += ",";
            path += req->hdrs.substr(val_begin, val_end-val_begin);
        } else if(0==strncasecmp(req->hdrs.c_str() + start_pos,
                              SIP_HDR_USER_AGENT, name_end-start_pos))
        {
            user_agent = req->hdrs.substr(val_begin, val_end-val_begin);
        }
        start_pos = hdr_end;
    }

    // bind
    auto* user_data = new RedisRequestUserData(event.session_id, *req);
    if(!registrar_redis.bind(user_data, REDIS_REGISTER_TYPE_ID, SIP_REGISTRAR_QUEUE, event.registration_id,
        contact, expires_int, user_agent, path, req->local_if))
    {
        delete user_data;
        user_data = nullptr;

        postRegisterResponse(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
}

void SipRegistrar::process_resolve_request_event(SipRegistrarResolveRequestEvent& event)
{
    auto* user_data = new RedisRequestUserData(event.session_id);
    if(!registrar_redis.resolve_aors(user_data, REDIS_AOR_LOOKUP_TYPE_ID, SIP_REGISTRAR_QUEUE, event.aor_ids)) {
        delete user_data;
        user_data = nullptr;

        postResolveResponse(event.session_id);
    }
}

void SipRegistrar::process_redis_reply_event(RedisReplyEvent& redis_reply) {
    //DBG("redis reply user_type_id %d status %d", redis_reply->result, redis_reply->user_type_id);
    switch(redis_reply.user_type_id) {
    case REDIS_REGISTER_TYPE_ID:
        process_redis_reply_register_event(redis_reply);
        break;
    case REDIS_AOR_LOOKUP_TYPE_ID:
        process_redis_reply_aor_lookup_event(redis_reply);
        break;
    case REDIS_BLOCKING_REQ_CTX_TYPE_ID:
        process_redis_reply_blocking_req_ctx_event(redis_reply);
        break;
    default:
        ERROR("unexpected reply event with type: %d", redis_reply.user_type_id);
        break;
    }
}

void SipRegistrar::process_redis_reply_register_event(RedisReplyEvent& event) {
    auto user_data = dynamic_cast<RedisRequestUserData*>(event.user_data.get());
    const AmSipRequest* req = user_data ? user_data->req.get() : nullptr;
    const string& session_id = user_data ? user_data->session_id : string();

    // reply 'failed' response
    if(!req || event.result != RedisReplyEvent::SuccessReply) {
        if(req) {
            ERROR("error reply from redis %s. for request from %s:%hu",
                  AmArg::print(event.data).c_str(),
                  req->remote_ip.data(), req->remote_port);
        } else {
            ERROR("error reply from redis %s.", AmArg::print(event.data).c_str());
        }

        postRegisterResponse(session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    static string contact_hdr = SIP_HDR_COLSP(SIP_HDR_CONTACT);
    static string expires_param_prefix = ";expires=";

    DBG("data: %s", AmArg::print(event.data).c_str());

    if(isArgUndef(event.data)) {
        DBG("nil reply from redis. no bindings");
        postRegisterResponse(session_id, req, 200, "OK");
        return;
    }

    /* response layout:
     * [
     *   [ contact1 , expires1, contact_key1, path1, interface_id1 ]
     *   [ contact2 , expires2, contact_key2, path2, interface_id2 ]
     *   ...
     * ]
     */

    if(!isArgArray(event.data)) {
        ERROR("error/unexpected reply from redis: %s for request from %s:%hu. Contact:'%s'",
              AmArg::print(event.data).c_str(),
              req->remote_ip.data(), req->remote_port,
              req->contact.data());
        if(event.data.is<AmArg::CStr>()) {
            postRegisterResponse(session_id, req, 500, event.data.asCStr());
        } else {
            postRegisterResponse(session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        return;
    }

    string hdrs;
    int n = static_cast<int>(event.data.size());
    for(int i = 0; i < n; i++) {
        AmArg &d = event.data[i];
        if(!isArgArray(d) || d.size()!=5) {
            ERROR("unexpected AoR layout in reply from redis: %s. skip it",AmArg::print(d).c_str());
            continue;
        }
        AmArg &contact_arg = d[0];
        if(!isArgCStr(contact_arg)) {
            ERROR("unexpected contact variable type from redis. skip it");
            continue;
        }
        string contact = contact_arg.asCStr();
        if(contact.empty()) {
            ERROR("empty contact in reply from redis. skip it");
            continue;
        }

        AmArg &expires_arg = d[1];
        if(!isArgLongLong(expires_arg)) {
            ERROR("unexpected expires value in redis reply: %s, skip it",AmArg::print(expires_arg).c_str());
            continue;
        }

        AmUriParser c;
        c.uri = contact;
        if(!c.parse_uri()) {
            ERROR("failed to parse contact uri: %s, skip it",contact.c_str());
            continue;
        }

        hdrs+=contact_hdr + c.print();
        hdrs+=expires_param_prefix+longlong2str(expires_arg.asLongLong());
        hdrs+=CRLF;

        if(keepalive_interval) {
            //update KeepAliveContexts
            contacts_subscription.createOrUpdateKeepAliveContext(
                d[2].asCStr(),  //key
                contact,        //aor
                d[3].asCStr(),  //path
                arg2int(d[4])   //interface_id
            );
        }
    }

    // reply 'success'
    postRegisterResponse(session_id, req, 200, "OK", hdrs);
}

void SipRegistrar::process_redis_reply_aor_lookup_event(RedisReplyEvent& event)
{
    RedisRequestUserData* user_data = dynamic_cast<RedisRequestUserData*>(event.user_data.get());
    const string& session_id = user_data ? user_data->session_id : string();

    // reply 'failed' response
    if(event.result != RedisReplyEvent::SuccessReply) {
        ERROR("error reply from redis %s.", AmArg::print(event.data).c_str());
        postResolveResponse(session_id);
        return;
    }


    DBG("data: %s", AmArg::print(event.data).c_str());

    //preprocess redis reply data
    aor_lookup_reply r;
    if(!r.parse(event)) {
        ERROR("aor lookup parser error");
        postResolveResponse(session_id);
        return;
    }

    DBG("parsed AoRs:");
    for(const auto &aor_entry: r.aors) {
        for(const auto &d: aor_entry.second) {
            DBG("aor_id: %s, contact: '%s', path: '%s'",
                aor_entry.first.c_str(), d.contact.data(), d.path.data());
        }
    }

    postResolveResponse(session_id, r.aors);
}

void SipRegistrar::process_redis_reply_blocking_req_ctx_event(RedisReplyEvent& event)
{
    RedisBlockingRequestCtx* ctx = dynamic_cast<RedisBlockingRequestCtx *>(event.user_data.release());
    if(!ctx) return;
    ctx->data = event.data;
    ctx->result = event.result;
    DBG("ctx.cond: %p",&ctx->cond);
    ctx->cond.set(true);
}

void SipRegistrar::postRegisterResponse(const string& session_id,
    const AmSipRequest* req, int code, const string& reason, const string& hdrs)
{
    if(session_id.empty()) {
        if(req)
            AmSipDialog::reply_error(*req, code, reason, hdrs);

        return;
    }

    AmSessionContainer::instance()->postEvent(session_id,
        new SipRegistrarRegisterResponseEvent(code, reason, hdrs));
}

void SipRegistrar::postResolveResponse(const string& session_id, const Aors &aors)
{
    if(session_id.empty()) {
        return;
    }

    AmSessionContainer::instance()->postEvent(session_id,
        new SipRegistrarResolveResponseEvent(aors));
}

bool SipRegistrar::is_loaded() {
    return registrar_redis.is_all_scripts_loaded() &&
        contacts_subscription.is_all_scripts_loaded();
}

void SipRegistrar::reload() {
    registrar_redis.load_all_scripts();
    contacts_subscription.load_all_scripts();
}
