#pragma once

#include <string>
#include <vector>
#include <memory>

using std::string;
using std::vector;
using std::unique_ptr;

#include <ampi/RedisApi.h>

#include "SipRegistrarConfig.h"

#define REG_READ_CONN_ID "registrar_read"
#define REG_SUBSCR_READ_CONN_ID "subscription_read"
#define REG_WRITE_CONN_ID "registrar_write"

#define REGISTER_SCRIPT "register_script"
#define LOAD_CONTACTS_SCRIPT "load_contacts_script"
#define AOR_LOOKUP_SCRIPT "aor_lookup_script"
#define RPC_AOR_LOOKUP_SCRIPT "rpc_aor_lookup_script"

class RegistrarRedisClient
  : public Configurable
{
  protected:
    bool use_functions;

    struct Connection {
        string id;
        RedisConnectionInfo info;
        bool is_connected;

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

  public:
    RegistrarRedisClient();
    virtual ~RegistrarRedisClient() {}
    virtual void connect_all();
    int configure(cfg_t* cfg) override;
    bool is_connected();
};
