#ifndef WS_RPC_PEER_H
#define WS_RPC_PEER_H

#include "RpcPeer.h"
#include <wslay/wslay.h>
#include "sip/sip_parser.h"

class WsRpcPeer : public JsonrpcNetstringsConnection
{
    bool ws_connected;
    wslay_event_context_ptr ctx_;
    static struct wslay_event_callbacks callbacks;
    cstring          ws_accept;
    cstring          ws_key;
    list<char>       ws_resv_buffer;

    cstring get_sec_ws_accept_data(const cstring& key);
protected:
    static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len, int flags, void *user_data);
    static void on_msg_recv_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data);
    static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data);
    static int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data);
    ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len, int flags);
    void on_msg_recv(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg);
    ssize_t on_send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags);

    int parse_input(sip_msg* s_msg);
    void send_reply(sip_msg* req, int reply_code, const string& reason);
public:
    WsRpcPeer(const std::string& id);
    ~WsRpcPeer();

    int connect(const std::string & host, int port, std::string & res_str) override;

    int read_data(char* data, int size) override;
    int netstringsRead() override;

    int send_data(char* data, int size) override;
    int netstringsBlockingWrite() override;
};

#endif/*WS_RPC_PEER_H*/
