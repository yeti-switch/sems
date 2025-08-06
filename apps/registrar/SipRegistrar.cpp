#include "SipRegistrar.h"
#include "log.h"
#include "AmEventDispatcher.h"
#include "AmSipDialog.h"
#include "AmUriParser.h"
#include "AmUtils.h"
#include "sip/parse_nameaddr.h"
#include "sip/defs.h"
#include "jsonArg.h"

#include <ampi/RedisApi.h>
#include <AmSipEvent.h>

#include <vector>
#include <botan/base64.h>
using std::vector;

#define EPOLL_MAX_EVENTS    2048
#define session_container AmSessionContainer::instance()
#define event_dispatcher AmEventDispatcher::instance()
#define registrar SipRegistrar::instance()

static vector<string> fl_protos{"none", "udp", "tcp", "tls", "sctp", "ws", "wss", "other"};

std::string registration_event_channel_name("reg");

enum UserTypeId {
    Register = 0,
    ResolveAors,
    BlockingReqCtx,
    ContactSubscribe,
    ContactData,
    Unbind
};

static void repack_headers(const string& headers, AmArg& ret) {
    AmArg data;
    if(!json2arg(headers, data)) return;
    for(auto& header : data) {
        ret["header_"+header.first] = header.second;
    }
}

/* Helpers */

static int normalize_header_name(int c) {
    if(c=='-') return '_';
    return ::tolower(c);
}

bool post_request(const string &conn_id, const vector<AmArg>& args,
    AmObject *user_data = nullptr, int user_type_id = 0, bool persistent_ctx = false)
{
    return session_container->postEvent(REDIS_APP_QUEUE,
        new RedisRequest(SIP_REGISTRAR_QUEUE, conn_id, args, user_data, user_type_id, persistent_ctx));
}

std::optional<string> parseRegId(const string &str) {
    static char delim = ':';

    auto pos1 = str.find(delim, 0);
    if(pos1 == string::npos) return std::nullopt;

    auto pos2 = str.find(delim, pos1 + 1);
    if(pos2 == string::npos) return std::nullopt;

    return str.substr(pos1 + 1, pos2 - pos1 - 1);
}

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
            return registrar;
        }

        int onLoad() {
            return registrar->onLoad();
        }

        void on_destroy() {
            registrar->stop();
        }

        /* AmConfigFactory */

        int configure(const string& config) {
            return SipRegistrarConfig::parse(config, registrar);
        }

        int reconfigure(const string& config) {
            return configure(config);
        }

        /* AmSessionFactory */

        AmSession* onInvite(const AmSipRequest& req, const string& app_name,
                            const map<string,string>& app_params)
        {
            AmSipDialog::reply_error(req,501,"Not Implemented");
            return NULL;
        }

        void onOoDRequest(const AmSipRequest& req) {
            session_container->postEvent(SIP_REGISTRAR_QUEUE,
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
    bool parse(const RedisReply &e)
    {
        if(RedisReply::SuccessReply!=e.result) {
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
            if(!isArgArray(aor_data_arg) || aor_data_arg.size()%3!=0) {
                ERROR("unexpected aor_data_arg layout. skip entry");
                continue;
            }

            int m = static_cast<int>(aor_data_arg.size())-1;
            for(int j = 0; j < m; j+=3) {
                AmArg &contact_arg = aor_data_arg[j];
                AmArg &path_arg = aor_data_arg[j+1];
                AmArg &if_name_arg = aor_data_arg[j+2];
                if(!isArgCStr(contact_arg)) {
                    ERROR("unexpected contact_arg. skip entry");
                    continue;
                }

                string path;
                if(isArgCStr(path_arg)) {
                    path = path_arg.asCStr();
                } else if (isArgUndef(path_arg)) {
                    // it's expected that 'path' can be nil
                    path = "";
                } else {
                    ERROR("unexpected path_arg type. skip entry");
                    continue;
                }

                string interface_name;
                if(isArgCStr(if_name_arg)) {
                    interface_name = if_name_arg.asCStr();
                } else if (isArgUndef(if_name_arg)) {
                    // it's expected that 'interface_name' can be nil
                    interface_name = "";
                } else {
                    ERROR("unexpected if_name_arg type. skip entry");
                    continue;
                }

                auto it = aors.find(reg_id);
                if(it == aors.end()) {
                    it = aors.insert(aors.begin(),
                        std::pair<RegistrationIdType,
                                  std::list<AorData> >(reg_id,  std::list<AorData>()));
                }
                it->second.emplace_back(contact_arg.asCStr(), path.c_str(), interface_name.c_str());
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
    RedisReply::result_type result;
    AmArg data;
};

/* SipRegistrar */

SipRegistrar* SipRegistrar::_instance = NULL;

SipRegistrar* SipRegistrar::instance()
{
    if(_instance == nullptr)
        _instance = new SipRegistrar();

    return _instance;
}

void SipRegistrar::dispose()
{
    if(_instance != nullptr) {
        delete _instance;
        _instance = nullptr;
    }
}

SipRegistrar::SipRegistrar()
  : AmEventFdQueue(this),
    max_interval_drift(1),
    max_registrations_per_slot(1)
{
    event_dispatcher->addEventQueue(SIP_REGISTRAR_QUEUE, this);
}

SipRegistrar::~SipRegistrar()
{
    event_dispatcher->delEventQueue(SIP_REGISTRAR_QUEUE);
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

int SipRegistrar::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd,true);

    init_rpc();

    if(keepalive_interval.count() || process_subscriptions) {
        timer.link(epoll_fd);
        timer.set(1000000 /* 1 seconds */,true);
    }

    int ret = RegistrarClickhouse::init(epoll_fd);
    DBG("SIPRegistrar initialized");
    return ret;
}

/* AmThread */

void SipRegistrar::run()
{
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("sip-registrar");
    running = true;

    RegistrarRedisClient::connect_all();

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

            if(e.data.fd==timer){
                on_timer();
                timer.read();
            }
            if(e.data.fd==clickhouse_timer){
                RegistrarClickhouse::on_timer();
                clickhouse_timer.read();
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
}

int SipRegistrar::configure(cfg_t* cfg)
{
    expires_min = cfg_getint(cfg, CFG_PARAM_EXPIRES_MIN);
    expires_max = cfg_getint(cfg, CFG_PARAM_EXPIRES_MAX);
    expires_default = cfg_getint(cfg, CFG_PARAM_EXPIRES_DEFAULT);
    keepalive_interval = seconds{cfg_getint(cfg, CFG_PARAM_KEEPALIVE_INTERVAL)};
    max_interval_drift = keepalive_interval/10; //allow 10% interval drift
    bindings_max = cfg_getint(cfg, CFG_PARAM_BINDINGS_MAX);
    if(bindings_max <= 0) bindings_max = DEFAULT_BINDINGS_MAX;
    keepalive_failure_code = cfg_getint(cfg, CFG_PARAM_KEEPALIVE_FAILURE_CODE);
    process_subscriptions = cfg_getbool(cfg, CFG_PARAM_PROCESS_SUBSCRIPTIONS);
    for(int i = 0; i < cfg_size(cfg, CFG_PARAM_HEADERS); i++) {
        string header_name(cfg_getnstr(cfg, CFG_PARAM_HEADERS, i));
        std::transform(header_name.begin(), header_name.end(), header_name.begin(), normalize_header_name);
        headers.emplace_back(header_name);
    }
    return RegistrarRedisClient::configure(cfg) |
           RegistrarClickhouse::configure(cfg);
}

void SipRegistrar::connect(const Connection &conn)
{
    session_container->postEvent(REDIS_APP_QUEUE,
        new RedisAddConnection(SIP_REGISTRAR_QUEUE, conn.id, conn.info));
}

void SipRegistrar::on_connect(const string &conn_id, const RedisConnectionInfo &info)
{
    RegistrarRedisClient::on_connect(conn_id, info);

    if(subscr_read_conn->id == conn_id)
        load_contacts(nullptr, UserTypeId::ContactData);
}

void SipRegistrar::getSnapshot(AmArg& ret)
{
    keepalive_contexts.getSnapshot(ret);
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

static std::optional<AmArg> parse_flow_token(const string &flow_token)
{
    if(flow_token.empty())
        return std::nullopt;

    Botan::secure_vector<uint8_t> fl_decode;
    try {
        fl_decode = Botan::base64_decode(flow_token.c_str(), flow_token.size());
    } catch(Botan::Invalid_Argument &e) {
        return std::nullopt;
    }

    if(fl_decode.size() < 10)
        return std::nullopt;

    uint8_t* flc = fl_decode.data() + 10;

    sockaddr_storage ss;
    if(*flc & 0x80)
        ss.ss_family = AF_INET6;
    else
        ss.ss_family = AF_INET;

    uint8_t protoindex = *(flc++) & 0x7f;
    if(protoindex >= fl_protos.size())
        return std::nullopt;

    AmArg fl;
    fl["proto"] = fl_protos[protoindex];

    uint32_t* addr;
    if(ss.ss_family == AF_INET) {
        addr = (uint32_t*)&((struct sockaddr_in*)&ss)->sin_addr;
    } else {
        addr = (uint32_t*)&((struct sockaddr_in6*)&ss)->sin6_addr.s6_addr32;
    }

    for(int k = 0; k < (ss.ss_family == AF_INET6 ? 16 : 4); k+=4, flc+=4)
        addr[k] = *(uint32_t*)flc;
    fl["dst_addr"] = am_inet_ntop(&ss);
    fl["dst_port"] = ntohs(*(uint16_t*)flc);
    flc+=2;

    for(int k = 0; k < (ss.ss_family == AF_INET6 ? 16 : 4); k+=4, flc+=4)
        addr[k] = *(uint32_t*)flc;
    fl["src_addr"] = am_inet_ntop(&ss);
    fl["src_port"] = ntohs(*(uint16_t*)flc);

    return fl;
}

static void parse_path(const AmArg& path_arg, AmArg& pd)
{
    pd.assertArray();

    auto pathes = explode(path_arg.asCStr(), ",");
    for(auto& path : pathes) {
        AmArg pdata;

        AmUriParser r;
        if(!r.parse_nameaddr(path)) {
            pd.push(pdata);
            continue;
        }

        pdata["uri"] = r.uri_str();

        auto fl = parse_flow_token(r.uri_user);
        if(fl) {
            pdata["flow_token"] = fl.value();
        }

        pd.push(pdata);
    }
}

/* RPC */
void SipRegistrar::rpc_show_aors(const AmArg& arg, AmArg& ret)
{
    size_t i,j;

    RedisBlockingRequestCtx ctx;
    rpc_resolve_aors(&ctx, UserTypeId::BlockingReqCtx, arg);
    ctx.cond.wait_for();

    if(RedisReply::SuccessReply!=ctx.result)
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
            if(!isArgArray(aor_entry_arg) || aor_entry_arg.size() != 8) {
                ERROR("unexpected aor_entry_arg layout. skip entry");
                continue;
            }

            ret.push(AmArg());
            AmArg &r = ret.back();
            r["auth_id"] = id_arg;
            r["contact"]  = aor_entry_arg[0];
            r["expires"]  = aor_entry_arg[1];
            r["node_id"]  = aor_entry_arg[3];
            r["interface_name"]  = aor_entry_arg[4];
            r["user_agent"]  = aor_entry_arg[5];
            r["path"]  = aor_entry_arg[6];

            const AmArg& hdrs_arg = aor_entry_arg[7];
            if(isArgCStr(hdrs_arg)) {
                if(!json2arg(hdrs_arg.asCStr(), r["headers"]))
                    r["headers"].assertStruct();
            }

            parse_path(aor_entry_arg[6], r["path_decoded"]);
        }
    }
}

void SipRegistrar::rpc_show_keepalive_contexts(const AmArg&, AmArg& ret)
{
    dump_keep_alive_contexts(ret);
}

void SipRegistrar::rpc_bind(const AmArg& arg, AmArg& ret)
{
    RedisBlockingRequestCtx ctx;
    rpc_bind_(&ctx, UserTypeId::BlockingReqCtx, arg);
    ctx.cond.wait_for();

    if(RedisReply::SuccessReply!=ctx.result)
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
        if(!isArgArray(d) || d.size()<8) {
            ERROR("unexpected AoR layout in reply from redis: %s. skip it", AmArg::print(d).c_str());
            continue;
        }

        ret.push(AmArg());
        AmArg &r = ret.back();
        r["contact"] = d[0];
        r["expires"] = d[1];
        r["key"] = d[2];
        r["path"] = d[3];
        r["interface_name"] = d[4];

        if(keepalive_interval.count()) {
            //update KeepAliveContexts
            create_or_update_keep_alive_context(
                d[2].asCStr(),
                [d](AmArg& data){
                    data["path"] = d[3];
                    data["interface_name"] = d[4];
                    data["expires"] = d[1];
                    repack_headers(d[7].asCStr(), data);
                    data["node_id"] = d[5];
                    data["user_agent"] = d[6];
                });
        }
    }
}

void SipRegistrar::rpc_unbind(const AmArg& arg, AmArg& ret)
{
    RedisBlockingRequestCtx ctx;
    rpc_unbind_(&ctx, UserTypeId::BlockingReqCtx, arg);
    ctx.cond.wait_for();

    if(RedisReply::SuccessReply!=ctx.result)
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
        r["interface_name"] = d[4];
    }
}

/* AmEventHandler */

void SipRegistrar::process(AmEvent* event)
{
    switch(event->event_id) {
        case E_SYSTEM: {
            AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(event);
            if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown)
                stop_event.fire();

            return;
        }
        case -1:
            if (auto e = dynamic_cast<AmSipReplyEvent *>(event)) {
                process_sip_reply(*e);
                return;
            }
            break;
    }

    switch(event->event_id) {
        case RedisEvent::ConnectionState:
            if(auto e = dynamic_cast<RedisConnectionState*>(event)) {
                process_redis_conn_state_event(*e);
                return;
            }
            break;
        case RedisEvent::Reply:
            if(auto e = dynamic_cast<RedisReply*>(event)) {
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
        case SipRegistrarEvent::ResolveAorsSubscribe:
            if(auto e = dynamic_cast<SipRegistrarResolveAorsSubscribeEvent*>(event)) {
                process_resolve_subscribe_event(*e);
                return;
            }
            break;
        case SipRegistrarEvent::ResolveAorsUnsubscribe:
            if(auto e = dynamic_cast<SipRegistrarResolveAorsUnsubscribeEvent*>(event)) {
                process_resolve_unsubscribe_event(*e);
                return;
            }
            break;
    }

    ERROR("got unexpected event ev %d", event->event_id);
}

void SipRegistrar::process_register_request_event(SipRegistrarRegisterRequestEvent& event)
{
    const AmSipRequest* req = event.req.get();
    if(!req) {
        ERROR("req is null");
        post_register_response(event.session_id, nullptr, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
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
        post_register_response(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
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
            post_register_response(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
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
        post_register_response(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    if(contacts.empty() && !asterisk_contact) {
        //request bindings list
        auto* user_data = new RedisRequestUserData(event.session_id, *req);
        if(!fetch_all(user_data, UserTypeId::Register, event.registration_id)) {
            delete user_data; user_data = nullptr;
            post_register_response(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
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
            post_register_response(event.session_id, req, 400, "Invalid Request");
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
            post_register_response(event.session_id, req, 423, "Interval Too Brief", min_expires_header);
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
            post_register_response(event.session_id, req, 400, "Invalid Request");
            return;
        }

        //unbind all
        auto* user_data = new RedisRequestUserData(event.session_id, *req);
        if(!unbind_all(user_data, UserTypeId::Register, event.registration_id)) {
            delete user_data; user_data = nullptr;
            post_register_response(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        return;
    }

    //find Path/User-Agent and predefined config headers
    AmArg hdrs_arg;
    string path;
    string user_agent;
    size_t start_pos = 0;

    hdrs_arg.assertStruct();

    while (start_pos < req->hdrs.length()) {
        size_t name_end, val_begin, val_end, hdr_end;
        int res;
        if ((res = skip_header(req->hdrs, start_pos, name_end, val_begin,
            val_end, hdr_end)) != 0)
        {
            break;
        }

        string hdr_name = req->hdrs.substr(start_pos, name_end-start_pos);

        if(0==strncasecmp(
            hdr_name.c_str(),
            SIP_HDR_PATH, hdr_name.size()))
        {
            if(!path.empty()) path += ",";
            path += req->hdrs.substr(val_begin, val_end-val_begin);
        } else if(0==strncasecmp(
            hdr_name.c_str(),
            SIP_HDR_USER_AGENT, hdr_name.size()))
        {
            user_agent = req->hdrs.substr(val_begin, val_end-val_begin);
        } else {
            std::transform(hdr_name.begin(), hdr_name.end(), hdr_name.begin(), normalize_header_name);
            for(auto& header : headers) {
                if(hdr_name == header)
                    hdrs_arg[header] = req->hdrs.substr(val_begin, val_end-val_begin);
            }
        }

        start_pos = hdr_end;
    }

    // bind
    auto* user_data = new RedisRequestUserData(event.session_id, *req);
    auto interface_name = get_interface_name(req->local_if);
    if(!bind(user_data, UserTypeId::Register, event.registration_id,
        contact, expires_int, user_agent, path, interface_name, arg2json(hdrs_arg)))
    {
        delete user_data; user_data = nullptr;
        post_register_response(event.session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
}

void SipRegistrar::process_resolve_request_event(SipRegistrarResolveRequestEvent& event)
{
    auto* user_data = new RedisRequestUserData(event.session_id);

    if(!resolve_aors(user_data, UserTypeId::ResolveAors, event.aor_ids)) {
        delete user_data; user_data = nullptr;
        post_resolve_response(event.session_id);
    }
}

void SipRegistrar::process_resolve_subscribe_event(SipRegistrarResolveAorsSubscribeEvent& event)
{
    if(!process_subscriptions) {
        post_resolve_response(event.session_id);
        return;
    }

    for(auto &aor_id: event.aor_ids) {
        DBG("add subscription %s -> %s", aor_id.data(), event.session_id.data());
        aor_lookup_subscribers.emplace(aor_id, LookupSubscriber{event.session_id, event.timeout});
    }
}

void SipRegistrar::process_resolve_unsubscribe_event(SipRegistrarResolveAorsUnsubscribeEvent& event)
{
    for(auto &aor_id: event.aor_ids) {
        auto range = aor_lookup_subscribers.equal_range(aor_id);
        for(auto it = range.first; it != range.second;) {
            if(it->second.session_id == event.session_id) {
                DBG("erase subscription %s -> %s", aor_id.data(), it->second.session_id.data());
                it = aor_lookup_subscribers.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void SipRegistrar::process_redis_conn_state_event(RedisConnectionState& event)
{
    if(event.state == RedisConnectionState::Connected)
        on_connect(event.conn_id, event.info);
    else
        on_disconnect(event.conn_id, event.info);
}

void SipRegistrar::process_redis_reply_event(RedisReply& redis_reply)
{
    //DBG("redis reply user_type_id %d status %d", redis_reply->result, redis_reply->user_type_id);
    switch(redis_reply.user_type_id) {
    case UserTypeId::Register:
        process_redis_reply_register_event(redis_reply);
        break;
    case UserTypeId::ResolveAors:
        process_redis_reply_resolve_aors_event(redis_reply);
        break;
    case UserTypeId::BlockingReqCtx:
        process_redis_reply_blocking_req_ctx_event(redis_reply);
        break;
    case UserTypeId::ContactSubscribe:
        process_redis_reply_contact_subscribe_event(redis_reply);
        break;
    case UserTypeId::ContactData:
        process_redis_reply_contact_data_event(redis_reply);
        break;
    case UserTypeId::Unbind:
        process_redis_reply_unbind_event(redis_reply);
        break;
    default:
        ERROR("unexpected reply event with type: %d", redis_reply.user_type_id);
        break;
    }
}

void SipRegistrar::process_redis_reply_register_event(RedisReply& event) {
    auto user_data = dynamic_cast<RedisRequestUserData*>(event.user_data.get());
    const AmSipRequest* req = user_data ? user_data->req.get() : nullptr;
    const string& session_id = user_data ? user_data->session_id : string();

    // reply 'failed' response
    if(!req || event.result != RedisReply::SuccessReply) {
        if(req) {
            ERROR("redis %s(%s) for request from %s:%hu. ci:%s",
                RedisReply::resultStr(event.result).data(),
                event.data.print().c_str(),
                req->remote_ip.data(), req->remote_port,
                req->callid.data());
        } else {
            ERROR("redis %s(%s)",
                RedisReply::resultStr(event.result).data(),
                event.data.print().c_str());
        }

        post_register_response(session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        return;
    }

    static string contact_hdr = SIP_HDR_COLSP(SIP_HDR_CONTACT);
    static string expires_param_prefix = ";expires=";

    DBG("data: %s", AmArg::print(event.data).c_str());

    if(isArgUndef(event.data)) {
        DBG("nil reply from redis. no bindings");
        post_register_response(session_id, req, 200, "OK");
        return;
    }

    /* response layout:
     * [
     *   [ contact1 , expires1, contact_key1, path1, interface_name1, node_id1 ]
     *   [ contact2 , expires2, contact_key2, path2, interface_name2, node_id2 ]
     *   ...
     * ]
     */

    if(!isArgArray(event.data)) {
        ERROR("error/unexpected reply from redis: %s for request from %s:%hu. Contact:'%s'",
              AmArg::print(event.data).c_str(),
              req->remote_ip.data(), req->remote_port,
              req->contact.data());
        if(event.data.is<AmArg::CStr>()) {
            post_register_response(session_id, req, 500, event.data.asCStr());
        } else {
            post_register_response(session_id, req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
        return;
    }

    string hdrs;
    int n = static_cast<int>(event.data.size());
    for(int i = 0; i < n; i++) {
        AmArg &d = event.data[i];
        if(!isArgArray(d) || d.size()<8) {
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

        if(keepalive_interval.count() && arg2int(d[5]) == AmConfig.node_id) {
            //update KeepAliveContexts
            create_or_update_keep_alive_context(
                d[2].asCStr(),  //key
                [d](AmArg& data)
                {
                    data["path"] = d[3];
                    data["interface_name"] = d[4];
                    data["expires"] = d[1];
                    repack_headers(d[7].asCStr(), data);
                    data["node_id"] = d[5];
                    data["user_agent"] = d[6];
                });
        }
    }

    // reply 'success'
    post_register_response(session_id, req, 200, "OK", hdrs);
}

void SipRegistrar::process_redis_reply_resolve_aors_event(RedisReply& event)
{
    RedisRequestUserData* user_data = dynamic_cast<RedisRequestUserData*>(event.user_data.get());
    const string& session_id = user_data ? user_data->session_id : string();

    // reply 'failed' response
    if(event.result != RedisReply::SuccessReply) {
        ERROR("error reply from redis %s.", AmArg::print(event.data).c_str());
        post_resolve_response(session_id);
        return;
    }

    DBG("data: %s", AmArg::print(event.data).c_str());

    //preprocess redis reply data
    aor_lookup_reply r;
    if(!r.parse(event)) {
        ERROR("aor lookup parser error");
        post_resolve_response(session_id);
        return;
    }

    DBG("parsed AoRs:");
    for(const auto &aor_entry: r.aors) {
        for(const auto &d: aor_entry.second) {
            DBG("aor_id: %s, contact: '%s', path: '%s'",
                aor_entry.first.c_str(), d.contact.data(), d.path.data());
        }
    }

    /*if (process_push_tokens &&
        r.aors.empty() &&
        user_data &&
        !user_data->push_data.empty() &&
        !session_id.empty())
    {
        DBG("no registrations. try to send push notification and subscribe to reg events");
        for(const auto &p: user_data->push_data) {
            DBG("%s -> %s", p.aor_id.data(), session_id.data());
            aor_lookup_subscribers.emplace(p.aor_id, session_id);
        }
        return;
    }*/

    post_resolve_response(session_id, r.aors);
}

void SipRegistrar::process_redis_reply_blocking_req_ctx_event(RedisReply& event)
{
    RedisBlockingRequestCtx* ctx = dynamic_cast<RedisBlockingRequestCtx *>(event.user_data.release());
    if(!ctx) return;
    ctx->data = event.data;
    ctx->result = event.result;
    DBG("ctx.cond: %p",&ctx->cond);
    ctx->cond.set(true);
}

void SipRegistrar::process_redis_reply_contact_subscribe_event(RedisReply& event)
{
    if(isArgArray(event.data) && event.data.size() == 3) {
        if(!isArgCStr(event.data[2])) //skip 'subscription' replies
            return;

        if(registration_event_channel_name==event.data[1].asCStr()) {
            process_redis_reply_contact_subscribe_reg_channel_event(event);
            return;
        }

        DBG("process expired/removed key: '%s'", event.data[2].asCStr());
        remove_keep_alive_context(event.data[2].asCStr());
    }
}

void SipRegistrar::process_redis_reply_contact_subscribe_reg_channel_event(RedisReply& event)
{
    if(!process_subscriptions)
        return;

    AmArg reg_data;

    if(!json2arg(event.data[2].asCStr(), reg_data)) {
        DBG("failed to decode reg data: %s", event.data[2].asCStr());
        return;
    }

    DBG("got reg event with data: %s", reg_data.print().data());

    aor_lookup_reply r;
    event.data = reg_data;
    if(!r.parse(event)) {
        ERROR("reg aor data parser error for: %s",
            event.data.print().data());
        return;
    }

    if(r.aors.empty()) {
        ERROR("empty aors after parsing for: %s",
            event.data.print().data());
        return;
    }

    const auto &aor_id = r.aors.begin()->first;

    auto range = aor_lookup_subscribers.equal_range(aor_id);
    for(auto it = range.first; it != range.second; ++it) {
        DBG("send reg_id %s resolving reply to the session_id: %s",
            aor_id.data(), it->second.session_id.data());
        post_resolve_response(it->second.session_id, r.aors);
    }
    aor_lookup_subscribers.erase(range.first, range.second);
}

void SipRegistrar::process_redis_reply_contact_data_event(RedisReply& event)
{
    clear_keep_alive_contexts();

    if(!isArgArray(event.data))
        return;

    seconds keepalive_interval_offset{0};

    DBG("process_loaded_contacts");
    int n = static_cast<int>(event.data.size());
    for(int i = 0; i < n; i++) {
        AmArg &d = event.data[i];
        if(!isArgArray(d) || d.size() < 7) //validate
            continue;
        if(arg2int(d[0]) != AmConfig.node_id) //skip other nodes registrations
            continue;
        DBG("process contact: %s",AmArg::print(d).c_str());

        create_or_update_keep_alive_context(
            d[3].asCStr(),
            [d](AmArg& data) {
                    data["path"] = d[1];
                    data["interface_name"] = d[2];
                    data["expires"] = d[6];
                    repack_headers(d[5].asCStr(), data);
                    data["node_id"] = d[0];
                    data["user_agent"] = d[4];
            },
            keepalive_interval_offset - keepalive_interval);

        keepalive_interval_offset++;
        keepalive_interval_offset %= keepalive_interval;
    }

    //keepalive_contexts.dump();

    if(!subscribe(UserTypeId::ContactSubscribe))
        ERROR("failed to subscribe");
}

void SipRegistrar::process_redis_reply_unbind_event(RedisReply& event) {
    DBG("data: %s", AmArg::print(event.data).c_str());
}

void SipRegistrar::process_sip_reply(const AmSipReplyEvent &event)
{
    auto dlg_it = uac_dlgs.find(event.reply.callid);
    if(dlg_it != uac_dlgs.end()) {
        const auto & key = dlg_it->second.first;

        {
            AmLock l(keepalive_contexts.mutex);
            auto it = keepalive_contexts.find(key);
            if(it != keepalive_contexts.end()) {
                auto &ctx = it->second;

                ctx.last_reply_code = event.reply.code;
                ctx.last_reply_reason = event.reply.reason;

                if(event.reply.local_reply)
                    ctx.last_reply_rtt_ms = milliseconds{0};
                else
                    ctx.last_reply_rtt_ms = std::chrono::duration_cast<milliseconds>(system_clock::now() - it->second.last_sent);

                if(event.reply.code == keepalive_failure_code) {
                    if(auto reg_id = parseRegId(key); reg_id) {
                        DBG("unbind %s, %s", reg_id.value().c_str(), ctx.aor.c_str());
                        bind(nullptr/*user data*/, UserTypeId::Unbind,
                             reg_id.value(), ctx.aor.c_str(),
                             0/*expires*/, std::string()/*user agent*/, std::string()/*path*/,
                             ctx.interface_name, "");
                    }
                }
            }
        }

        uac_dlgs.erase(dlg_it);
    }
}

void SipRegistrar::post_register_response(const string& session_id,
    const AmSipRequest* req, int code, const string& reason, const string& hdrs)
{
    if(session_id.empty()) {
        if(req)
            AmSipDialog::reply_error(*req, code, reason, hdrs);

        return;
    }

    session_container->postEvent(session_id, new SipRegistrarRegisterResponseEvent(code, reason, hdrs));
}

void SipRegistrar::post_resolve_response(const string& session_id, const Aors &aors)
{
    if(session_id.empty() == false)
        session_container->postEvent(session_id, new SipRegistrarResolveResponseEvent(aors));
}

/* Command Requests */

bool SipRegistrar::fetch_all(AmObject* user_data, int user_type_id, const string &registration_id)
{
    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL", "register", 1, registration_id.c_str()};
    else
    {
        auto script = write_conn->script(REGISTER_SCRIPT);
        if(!script || !script->is_loaded()) {
            ERROR("%s script is not loaded", REGISTER_SCRIPT);
            return false;
        }

        args = {"EVALSHA", script->hash.c_str(), 1, registration_id.c_str()};
    }

    return post_request(write_conn->id, args, user_data, user_type_id);
}

bool SipRegistrar::unbind_all(AmObject* user_data, int user_type_id, const string &registration_id)
{
    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL", "register", 1, registration_id.c_str(), 0};
    else
    {
        auto script = write_conn->script(REGISTER_SCRIPT);
        if(!script || !script->is_loaded()) {
            ERROR("%s script is not loaded", REGISTER_SCRIPT);
            return false;
        }

        args = {"EVALSHA", script->hash.c_str(), 1, registration_id.c_str(), 0};
    }

    return post_request(write_conn->id, args, user_data, user_type_id);
}

bool SipRegistrar::bind(AmObject *user_data, int user_type_id,
    const string &registration_id, const string &contact, int expires,
    const string &user_agent, const string &path,
    const string &interface_name, const string& headers)
{
    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL", "register", 1, registration_id.c_str(), expires, contact.c_str(),
            AmConfig.node_id, interface_name.c_str(),
            user_agent.c_str(), path.c_str(), headers.c_str(), bindings_max};
    else
    {
        auto script = write_conn->script(REGISTER_SCRIPT);
        if(!script || !script->is_loaded()) {
            ERROR("%s script is not loaded", REGISTER_SCRIPT);
            return false;
        }

        args = {"EVALSHA", script->hash.c_str(), 1, registration_id.c_str(), expires,
            contact.c_str(), AmConfig.node_id, interface_name.c_str(),
            user_agent.c_str(), path.c_str(), headers.c_str(), bindings_max};
    }

    return post_request(write_conn->id, args, user_data, user_type_id);
}

bool SipRegistrar::resolve_aors(AmObject *user_data, int user_type_id, std::set<string> aor_ids)
{
    DBG("got %ld AoR ids to resolve", aor_ids.size());

    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL_RO", "aor_lookup", (int)aor_ids.size()};
    else
    {
        auto script = read_conn->script(AOR_LOOKUP_SCRIPT);
        if(!script || !script->is_loaded()) {
            ERROR("%s script is not loaded", AOR_LOOKUP_SCRIPT);
            return false;
        }

        args = {"EVALSHA",  script->hash.c_str(), (int)aor_ids.size()};
    }

    for(const auto &id : aor_ids)
        args.emplace_back(id.c_str());

    return post_request(read_conn->id, args, user_data, user_type_id);
}

bool SipRegistrar::load_contacts(AmObject *user_data, int user_type_id)
{
    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL_RO", "load_contacts", 0};
    else
    {
        auto script = subscr_read_conn->script(LOAD_CONTACTS_SCRIPT);
        if(!script || !script->is_loaded()) {
            ERROR("%s script is not loaded", LOAD_CONTACTS_SCRIPT);
            return false;
        }

        args = {"EVALSHA", script->hash.c_str(), 0};
    }

    return post_request(subscr_read_conn->id, args, user_data, user_type_id);
}

bool SipRegistrar::subscribe(int user_type_id)
{
    vector<AmArg> channels{
        "SUBSCRIBE",
        "__keyevent@0__:expired",
        "__keyevent@0__:del",
    };
    if(process_subscriptions) {
        channels.push_back(registration_event_channel_name);
    }
    return post_request(subscr_read_conn->id, channels, nullptr, user_type_id, true);
}

void SipRegistrar::rpc_bind_(AmObject *user_data, int user_type_id, const AmArg &arg)
{
    const string registration_id = arg2str(arg[0]);
    const string contact = arg2str(arg[1]);
    int expires = arg2int(arg[2]);
    const string path = arg.size() > 3 ? arg2str(arg[3]) : "";
    const string user_agent = arg.size() > 4 ? arg2str(arg[4]) : "";
    string interface_name = arg.size() > 5 ? arg2str(arg[5]) : 0;
    const string headers = arg.size() > 6 ? arg2str(arg[6]) : "";

    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL", "register", 1, registration_id.c_str(), expires, contact.c_str(),
            AmConfig.node_id, interface_name, user_agent.c_str(), path.c_str(), headers, bindings_max};
    else
    {
        auto script = write_conn->script(REGISTER_SCRIPT);
        if(!script || !script->is_loaded())
            throw AmSession::Exception(500,"registrar is not enabled");

        args = {"EVALSHA", script->hash.c_str(), 1, registration_id.c_str(), expires,
            contact.c_str(), AmConfig.node_id, interface_name, user_agent.c_str(), path.c_str(), headers, bindings_max};
    }

    if(post_request(write_conn->id, args, user_data, user_type_id) == false)
        throw AmSession::Exception(500, "failed to post bind request");
}

void SipRegistrar::rpc_unbind_(AmObject *user_data, int user_type_id, const AmArg &arg)
{
    const string registration_id = arg2str(arg[0]);

    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL", "register", 1, registration_id.c_str(), 0}; // expires 0
    else
    {
        auto script = write_conn->script(REGISTER_SCRIPT);
        if(!script || !script->is_loaded())
            throw AmSession::Exception(500,"registrar is not enabled");

        args = {"EVALSHA", script->hash.c_str(), 1, registration_id.c_str(), 0}; // expires 0
    }

    if(arg.size() > 1)
        args.emplace_back(arg2str(arg[1])); // contact

    if(post_request(write_conn->id, args, user_data, user_type_id) == false)
        throw AmSession::Exception(500, "failed to post unbind request");
}

void SipRegistrar::rpc_resolve_aors(AmObject *user_data, int user_type_id, const AmArg &arg)
{
    vector<AmArg> args;
    if(use_functions)
        args = {"FCALL_RO", "rpc_aor_lookup", (int)arg.size()};
    else
    {
        auto script = read_conn->script(RPC_AOR_LOOKUP_SCRIPT);
        if(!script || !script->is_loaded())
            throw AmSession::Exception(500,"registrar is not enabled");

        args = {"EVALSHA", script->hash.c_str(), (int)arg.size()};
    }

    for(auto i = 0U; i < arg.size(); ++i)
        args.emplace_back(arg2str(arg[i])); // contact

    if(post_request(read_conn->id, args, user_data, user_type_id) == false)
        throw AmSession::Exception(500, "failed to post resolve_aors request");
}

void SipRegistrar::on_timer()
{
    auto now{system_clock::now()};
    uint32_t sent = 0;
    seconds drift_interval{0};
    auto double_max_interval_drift = max_interval_drift*2;

    //subscriptions
    for(auto it = aor_lookup_subscribers.begin(); it!= aor_lookup_subscribers.end();) {
        const auto &sub = it->second;
        /*DBG("check subscription: %s -> %s",
            it->first.data(), sub.session_id.data());*/
        if(now - sub.created_at >  sub.timeout_interval) {
            DBG("subscription timeout: %s -> %s", it->first.data(), sub.session_id.data());
            //generate SipRegistrarResolveResponseEvent with empty AoRs
            post_resolve_response(it->second.session_id);
            it = aor_lookup_subscribers.erase(it);
        } else {
            ++it;
        }
    }

    //keepalive
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

        if(ctx.interface_name.empty() == false) {
            dlg->resetOutboundIf();
            dlg->setOutboundInterfaceName(ctx.interface_name);
        }

        dlg->setLocalTag(SIP_REGISTRAR_QUEUE); //From-tag and queue to handle replies
        dlg->setCallid(AmSession::getNewId());

        if(0==dlg->sendRequest(SIP_METH_OPTIONS))
        {
            ctx.last_sent = system_clock::now();
            //add dlg to local hash
            auto dlg_ptr = dlg.release();
            uac_dlgs.emplace(dlg_ptr->getCallid(), pair{ctx_it.first, dlg_ptr});
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

SipRegistrar::keepalive_ctx_data::keepalive_ctx_data(const string &aor, const string &path,
    const string &interface_name, const system_clock::time_point &next_send)
    : aor(aor), path(path), interface_name(interface_name),
      next_send(next_send), last_sent(),
      last_reply_code(0), last_reply_reason(), last_reply_rtt_ms()
{}

void SipRegistrar::keepalive_ctx_data::update(const string &_aor, const string &_path,
    const string &_interface_name, const system_clock::time_point &_next_send)
{
    aor = _aor;
    path = _path;
    interface_name = _interface_name;
    next_send = _next_send;
}

void SipRegistrar::keepalive_ctx_data::dump(const string &key, const system_clock::time_point &now) const
{
    DBG("keepalive_context. key: '%s', "
        "aor: '%s', path: '%s', interface_name: %s, "
        "next_send-now: %d",
        key.c_str(),
        aor.data(), path.data(), interface_name.c_str(),
        std::chrono::duration_cast<seconds>(next_send - now).count());
}

void SipRegistrar::keepalive_ctx_data::dump(const string &key, AmArg &ret, const system_clock::time_point &now) const
{
    ret["key"] = key;
    ret["aor"] = aor;
    ret["path"] = path;
    ret["interface_name"] = interface_name;
    ret["next_send_in"] = std::chrono::duration_cast<seconds>(next_send - now).count();
    ret["last_reply_code"] = last_reply_code;
    ret["last_reply_reason"] = last_reply_reason;
    ret["last_reply_rtt_ms"] = last_reply_rtt_ms.count();
}

void SipRegistrar::KeepAliveContexts::dump()
{
    //AmLock l(mutex);
    auto now{system_clock::now()};
    DBG("%zd keepalive contexts", size());
    for(const auto &i : *this)
        i.second.dump(i.first, now);
}

void SipRegistrar::KeepAliveContexts::dump(AmArg &ret)
{
    ret.assertArray();
    auto now{system_clock::now()};
    AmLock l(mutex);
    for(const auto &i : *this) {
        ret.push(AmArg());
        i.second.dump(i.first, ret.back(), now);
    }
}

void SipRegistrar::KeepAliveContexts::getSnapshot(AmArg &ret)
{
    AmLock l(mutex);
    for(const auto &i : *this)
        ret.push(i.second.clickhouse_data);
}

void SipRegistrar::create_or_update_keep_alive_context(const string &key,
                                                       std::function<void(AmArg& data)> f_load,
                                                       const seconds &keep_alive_interval_offset)
{
    size_t begin = key.find(":");
    if(begin == string::npos){
        ERROR("attempt add registrar`s keep alive context: incorrect contact key");
        return;
    }
    size_t end = key.find(":", begin + 1);
    if(end == string::npos){
        ERROR("attempt add registrar`s keep alive context: incorrect contact key");
        return;
    }

    AmArg data;
    f_load(data);
    string contact = string(key.begin() + end + 1, key.end());
    data["auth_id"] = string(key.begin() + begin + 1, key.begin() + end);
    data["contact"] = contact;
    if(!data.hasMember("path") ||
       !data.hasMember("interface_name")){
        ERROR("attempt add registrar`s keep alive context: absent mandatory parameters");
        return;
    }

    auto next_time = system_clock::now() + keepalive_interval + keep_alive_interval_offset;
    AmLock l(keepalive_contexts.mutex);
    auto it = keepalive_contexts.find(key);
    keepalive_ctx_data* ctx;
    if(it == keepalive_contexts.end()) {
        ctx = &keepalive_contexts.try_emplace(key, contact,
                                                   data["path"].asCStr(),
                                                   data["interface_name"].asCStr(),
                                                   next_time).first->second;
    } else {
        ctx = &it->second;
        ctx->update(contact, data["path"].asCStr(), data["interface_name"].asCStr(), next_time);
    }
    data.erase("path");
    ctx->clickhouse_data = data;
}

void SipRegistrar::remove_keep_alive_context(const string &key)
{
    AmLock l(keepalive_contexts.mutex);
    keepalive_contexts.erase(key);
}

void SipRegistrar::clear_keep_alive_contexts()
{
    AmLock l(keepalive_contexts.mutex);
    keepalive_contexts.clear();
}

string SipRegistrar::get_interface_name(int interface_id) {
    for (const auto& [iface_name,iface_id]: AmConfig.sip_if_names)
        if (iface_id == interface_id)
            return iface_name;

    return string();
}
