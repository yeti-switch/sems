#include "RedisApp.h"
#include "log.h"
#include "RedisScript.h"

#define session_container AmSessionContainer::instance()
#define redis_app RedisApp::instance()

/* RedisAppFactory */

class RedisAppFactory
  : public AmConfigFactory
{
    private:
        RedisAppFactory(const string& name)
          : AmConfigFactory(name)
        {
            RedisApp::instance();
        }
        ~RedisAppFactory()
        {
            RedisApp::dispose();
        }
    public:
        DECLARE_FACTORY_INSTANCE(RedisAppFactory);

        int onLoad() {
            return redis_app->onLoad();
        }

        void on_destroy() {
            redis_app->stop();
        }

        /* AmConfigFactory */

        int configure(const string& config) {
            return RedisAppConfig::parse(config, redis_app);
        }

        int reconfigure(const string& config) {
            return configure(config);
        }
};

EXPORT_PLUGIN_CONF_FACTORY(RedisAppFactory);
DEFINE_FACTORY_INSTANCE(RedisAppFactory, MOD_NAME);

/* RedisApp */

RedisApp* RedisApp::_instance = NULL;

RedisApp* RedisApp::instance()
{
    if(_instance == nullptr)
        _instance = new RedisApp();

    return _instance;
}

void RedisApp::dispose()
{
    if(_instance != nullptr)
        delete _instance;

    _instance = nullptr;
}

RedisApp::RedisApp()
  : RedisConnectionPool("redis_app", REDIS_APP_QUEUE)
{
    makeRedisInstance();
}

RedisApp::~RedisApp()
{
    freeRedisInstance();
}

int RedisApp::onLoad()
{
    if(init()){
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void RedisApp::on_retry_reqs_timer() {
    for(auto& conn : connections)
        if(conn.is_connected())
            process_retry_reqs(&conn);
}

RedisApp::Connection* RedisApp::find_conn(const string& id) {
    for(auto& conn : connections)
        if(conn.id == id)
            return &conn;

    return nullptr;
}

RedisApp::Connection* RedisApp::find_conn(const RedisConnection* c) {
    for(auto& conn : connections)
        if(conn.redis_conn == c)
            return &conn;

    return nullptr;
}

/* AmEventHandler */

void RedisApp::process(AmEvent* event)
{
    switch(event->event_id) {
        case RedisEvent::AddConnection:
            if(auto e = dynamic_cast<RedisAddConnection*>(event)) {
                process_redis_add_connection_event(*e);
                return;
            }
            break;

        case RedisEvent::Request:
            if(auto e = dynamic_cast<RedisRequest*>(event)) {
                process_redis_request_event(*e);
                return;
            }
            break;
    }

    RedisConnectionPool::process(event);
}

void RedisApp::process_redis_add_connection_event(RedisAddConnection &e)
{
    // check is connection already exists
    for(auto conn : connections) {
        if(conn.id != e.conn_id)
            continue;

        if(!conn.is_connected() && conn.redis_conn->is_connected())
            conn.on_connect();

        return;
    }

    auto redis_conn = addConnection(e.info.host, e.info.port);

    if(!redis_conn) {
        DBG("Failed to add connection.");
        session_container->postEvent(e.session_id,
            new RedisConnectionState(e.conn_id, RedisConnectionState::Disconnected, e.info));
        return;
    }

    const auto & conn = connections.emplace_back(e.conn_id, e.info, e.session_id, redis_conn);

    if(conn.info.password.empty() == false)
        redis_conn->set_auth_data(conn.info.password, conn.info.username);
}

void RedisApp::process_redis_request_event(RedisRequest &event)
{
    auto conn = find_conn(event.conn_id);
    if(!conn) return;

    if(conn->is_connected()) {
        process_request_event(event, conn->redis_conn);
        return;
    }

    // put request to retry_reqs queue
    auto & queue = retry_reqs[conn];
    if(queue.size() < max_queue_size) {
        queue.emplace(event);
        conn->retry_reqs_count_stat.set(queue.size());
        return;
    }

    // drop request
    if(event.session_id.empty() == false)
        session_container->postEvent(event.session_id,
            new RedisReply(event.conn_id, RedisReply::NotConnected, AmArg(), event.user_data, event.user_type_id));

    conn->dropped_reqs_count_stat.inc();
}

void RedisApp::process_internal_reply(const RedisConnection *c, int result, const AmObject *user_data, const AmArg &data)
{
    auto conn = find_conn(c);
    if(!conn)
        return;

    auto script_req = dynamic_cast<const RedisScriptLoadRequest *>(user_data);
    if(!script_req) {
        conn->on_disconnect();
        return;
    }

    auto script = script_req->script;
    if(data.getType() != AmArg::CStr) {
        ERROR("script '%s' loaded hash with wrong type", script.name.c_str());
        conn->on_disconnect();
        return;
    }

    const char* hash = data.asCStr();
    if(!hash) {
        ERROR("script '%s' loaded hash is nil", script.name.c_str());
        conn->on_disconnect();
        return;
    }

    DBG("script '%s' loaded with hash '%s'", script.name.c_str(), hash);
    conn->on_script_loaded(script, hash);
}

void RedisApp::process_retry_reqs(Connection *conn)
{
    auto res = retry_reqs.find(conn);
    if(res == retry_reqs.end()) return;
    auto & queue = res->second;

    for(int i = 0; i < max_batch_size && queue.size(); ++i) {
        process_request_event(queue.front(), conn->redis_conn);
        queue.pop();
    }

    conn->retry_reqs_count_stat.set(queue.size());

    if(queue.empty())
        retry_reqs.erase(conn);
    else
        init_retry_reqs_timer(batch_timeout.count());
}

/* RedisConnectionStateListener */

void RedisApp::on_connect(RedisConnection* c)
{
    if(auto conn = find_conn(c))
        conn->on_connect();
}

void RedisApp::on_disconnect(RedisConnection* c)
{
    if(auto conn = find_conn(c))
        conn->on_disconnect();
}

/* Configurable */

int RedisApp::configure(cfg_t* cfg)
{
    max_batch_size = cfg_getint(cfg, CFG_PARAM_MAX_BATCH_SIZE);
    batch_timeout = milliseconds{cfg_getint(cfg, CFG_PARAM_BATCH_TIMEOUT)};
    max_queue_size = cfg_getint(cfg, CFG_PARAM_MAX_QUEUE_SIZE);
    return 0;
}

/* Connection */

void RedisApp::Connection::on_connect()
{
    if(is_scripts_loaded() == false) {
        load_scripts();
        return;
    }

    post_conn_state(RedisConnectionState::Connected);
    redis_app->process_retry_reqs(this);
    connected_stat.set(1);
}

void RedisApp::Connection::on_disconnect()
{
    drop_data();
    post_conn_state(RedisConnectionState::Disconnected);
    connected_stat.set(0);
}

bool RedisApp::Connection::is_connected()
{
    return redis_conn->is_connected() && is_scripts_loaded();
}

void RedisApp::Connection::on_script_loaded(const RedisScript& script, const char *hash)
{
    set_script_hash(script, hash);

    if(is_scripts_loaded())
        on_connect();
}

bool RedisApp::Connection::is_scripts_loaded()
{
    for(auto s : info.scripts)
        if(s.is_loaded() == false)
            return false;

    return true;
}

void RedisApp::Connection::set_script_hash(const RedisScript& script, const char *hash)
{
    for(auto &s : info.scripts) {
        if(s.name != script.name)
            continue;

        s.hash = hash;
        break;
    }
}

void RedisApp::Connection::load_scripts()
{
    for(const auto & s : info.scripts) {
        if(s.is_loaded())
            continue;

        string data;
        if(Utils::read_file_data(s.path, data) < 0) {
            on_disconnect();
            break;
        }

        redis_app->process_internal_request(redis_conn,
            new RedisScriptLoadRequest(s), "SCRIPT LOAD %s", data.c_str());
    }
}

void RedisApp::Connection::drop_data()
{
    for(auto &s : info.scripts)
        s.hash = "";
}

void RedisApp::Connection::post_conn_state(RedisConnectionState::RedisConnState state)
{
    session_container->postEvent(session_id, new RedisConnectionState(id, state, info));
}
