#ifndef WS_RPC_PEER_H
#define WS_RPC_PEER_H

#include "RpcPeer.h"
#include <wslay/wslay.h>
#include "sip/sip_parser.h"
#include "sip/sip_parser_async.h"

class WsRpcPeer : public JsonrpcNetstringsConnection {
  protected:
    bool                                ws_connected;
    wslay_event_context_ptr             ctx_;
    static struct wslay_event_callbacks callbacks;
    cstring                             ws_accept;
    cstring                             ws_key;
    std::vector<char>                   ws_resv_buffer;
    std::vector<char>                   ws_send_buffer;
    parser_state                        pst;

    cstring get_sec_ws_accept_data(const cstring &key);
    cstring get_sec_ws_key_data();

  protected:
    static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len, int flags, void *user_data);
    static void    on_msg_recv_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg,
                                        void *user_data);
    static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags,
                                 void *user_data);
    static int     genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data);
    ssize_t        recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len, int flags);
    void           on_msg_recv(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg);
    ssize_t        on_send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags);

    void init_wslay(bool server);

    virtual int ws_recv_data(uint8_t *data, size_t len);
    virtual int ws_send_data(const uint8_t *data, size_t len);
    int         parse_input(sip_msg *s_msg);
    void        send_reply(sip_msg *req, int reply_code, const std::string &reason);
    void        send_request();

  public:
    WsRpcPeer(const std::string &id);
    ~WsRpcPeer();

    int connect(const std::string &host, int port, std::string &res_str) override;

    int read_data(char *data, int size) override;
    int netstringsRead() override;

    int send_data(char *data, int size) override;
    int netstringsBlockingWrite() override;

    void addMessage(const char *data, size_t len) override;
    void clearMessage() override;
};

#endif /*WS_RPC_PEER_H*/
