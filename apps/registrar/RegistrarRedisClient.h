#pragma once

#include <string>
#include <vector>
#include <memory>

using std::string;
using std::vector;
using std::unique_ptr;

#include <ampi/RedisApi.h>

#include "SipRegistrarConfig.h"

#define REG_READ_CONN_ID            "registrar_read"
#define REG_SUBSCR_READ_CONN_ID     "subscription_read"
#define REG_WRITE_CONN_ID           "registrar_write"

#define REGISTER_SCRIPT             "register"
#define LOAD_CONTACTS_SCRIPT        "load_contacts"
#define AOR_LOOKUP_SCRIPT           "aor_lookup"
#define RPC_AOR_LOOKUP_SCRIPT       "rpc_aor_lookup"

class RegistrarTest;

class RegistrarRedisClient
  : public Configurable
{
  protected:
    friend RegistrarTest;

    bool use_functions;
    string scripts_dir;

    struct Connection {
        string id;
        RedisConnectionInfo info;
        enum State{
            None,
            Connected,
            Disconnected
        } state;

        Connection(const string &id);
        virtual ~Connection();
        const RedisScript* script(const string &name);
    };

    Connection* read_conn;
    Connection* subscr_read_conn;
    Connection* write_conn;
    vector<unique_ptr<Connection>> connections;

    virtual void connect(const Connection &conn) = 0;
    virtual void on_connect(const string &conn_id, const RedisConnectionInfo &info);
    virtual void on_disconnect(const string &conn_id, const RedisConnectionInfo &info);

    string get_script_path(const string &sript_name);

  public:
    RegistrarRedisClient();
    virtual ~RegistrarRedisClient() {}
    virtual void connect_all();
    int configure(cfg_t* cfg) override;
};
