#include "ws_trsp.h"

#include "ip_util.h"
#include "parse_common.h"
#include "sip_parser.h"
#include "trans_layer.h"
#include "hash.h"
#include "parse_via.h"
#include "msg_fline.h"
#include "msg_hdrs.h"
#include "defs.h"

#include "botan/sha160.h"
#include "botan/base64.h"

#include "AmUtils.h"

#include <netdb.h>
#include <event2/event.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <AmLcConfig.h>

//avoid sockets in WAITING state. close() will send RST and immediately remove entry from hashtable
#define TCP_STATIC_CLIENT_PORT_CLOSE_NOWAIT 1
#define MAX_DATE_TIME 80
#define KEY_LEN 16  //see rfc6455 sec.4.1
#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

ssize_t ws_input::recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len,
                      int flags, void *user_data)
{
    ws_input* input = (ws_input*)user_data;
    int ret = input->recv_callback(ctx, data, len, flags);
    if(!ret) {
        return WSLAY_ERR_WOULDBLOCK;
    }
    return ret;
}

ssize_t ws_input::send_callback(wslay_event_context_ptr ctx,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data)
{
    ws_input* input = (ws_input*)user_data;
    return input->on_send_callback(ctx, data, len, flags);
}

void ws_input::on_msg_recv_callback(wslay_event_context_ptr ctx,
                        const struct wslay_event_on_msg_recv_arg *arg,
                        void *user_data)
{
    ws_input* input = (ws_input*)user_data;
    input->on_msg_recv(ctx, arg);
}

int ws_input::genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data)
{
    ws_input* input = (ws_input*)user_data;
    for(int i = 0; i < len; i++) {
        buf[i] = get_random() & 0xff;
    }
    return 0;
}

struct wslay_event_callbacks ws_input::callbacks = {
    ws_input::recv_callback,
    ws_input::send_callback,
    ws_input::genmask_callback,
    NULL, /* on_frame_recv_start_callback */
    NULL, /* on_frame_recv_callback */
    NULL, /* on_frame_recv_end_callback */
    ws_input::on_msg_recv_callback
};

ws_input::ws_input(ws_output* output_, bool server)
: ws_connected(false)
, ws_input_len(0), ws_input_pos(0)
, is_server(server), output(output_)
{

    Botan::SHA_1 sha;
    size_t size = Botan::base64_encode_max_output(sha.output_length());
    ws_accept.set(new char[size], size);
    size = Botan::base64_encode_max_output(KEY_LEN);
    ws_key.set(new char[size], size);
    if(server)
        wslay_event_context_server_init(&ctx_, &callbacks, this);
    else
        wslay_event_context_client_init(&ctx_, &callbacks, this);
}

ws_input::~ws_input()
{
    delete ws_accept.s;
    delete ws_key.s;
    wslay_event_context_free(ctx_);
}

int ws_input::send(tcp_base_trsp::msg_buf* msg)
{
    {
        AmLock lock(sock_mut);
        send_q.push_back(msg);
    }
    if(!ws_connected && !is_server)
        return send_request();
    return 0;
}

void ws_input::pre_write()
{
    if(!send_q.empty()) {
        tcp_base_trsp::msg_buf* msg = send_q.front();
        wslay_event_msg e_msg = {
            .opcode = WSLAY_TEXT_FRAME,
            .msg = (uint8_t*)msg->cursor,
            .msg_length = (size_t)msg->bytes_left()
        };
        msg->cursor += msg->msg_len;
        int ret = 0;
        if((ret = wslay_event_queue_msg(ctx_, &e_msg)) != 0) {
            WARN("wslay_event_queue_msg return error %d. restore queue", ret);
            msg->cursor = msg->msg;
            return;
        }
        wslay_event_send(ctx_);
    }
}

void ws_input::post_write()
{
    tcp_base_trsp::msg_buf* msg = 0;
    while(!send_q.empty()) {
        msg = send_q.front();
        if(msg->bytes_left() == 0) {
            send_q.pop_front();
            delete msg;
        } else {
            break;
        }
    }
}

int ws_input::on_input(tcp_base_trsp* trsp)
{
    if(ws_connected) {
        return wslay_event_recv(ctx_);
    } else {
        return parse_input(trsp);
    }
}

unsigned char*   ws_input::get_input() {
    if(!ws_connected)
        return trsp_base_input::get_input();
    else
        return ws_input_buf + ws_input_pos + ws_input_len;
}

int ws_input::get_input_free_space() {
    if(!ws_connected)
        return trsp_base_input::get_input_free_space();
    else {
        if(ws_input_len > MAX_TCP_MSGLEN) return 0;
        return MAX_TCP_MSGLEN - ws_input_len;
    }
}
void ws_input::reset_input() {
    ws_input_len = 0;
    ws_input_pos = 0;
}

void ws_input::add_input_len(int len) {
    if(!ws_connected)
        return trsp_base_input::add_input_len(len);
    else
        ws_input_len += len;
}

void ws_input::on_parsed_received_msg(tcp_base_trsp* trsp, sip_msg* s_msg)
{
    if(!ws_connected) {
        char* err_msg=0;
        int err = parse_http_msg(s_msg, err_msg);
        if(err){
            DBG("parse_sip_msg returned %i\n",err);

            if(!err_msg){
                err_msg = (char*)"unknown parsing error";
            }

            DBG("parsing error: %s\n",err_msg);

            DBG("Message was: \"%.*s\"\n",s_msg->len,s_msg->buf);

            if((err != MALFORMED_FLINE) &&
               (s_msg->type == HTTP_REQUEST) &&
               (s_msg->u.request->method != sip_request::GET)){
                    send_reply(s_msg,400,cstring(err_msg));
            }

        } else {
            static char sip[] = "sip";
            static size_t sip_len = strlen(sip);
            if(s_msg->sec_ws_protocol &&
                (s_msg->sec_ws_protocol->value.len != sip_len || 
                lower_cmp(s_msg->sec_ws_protocol->value.s, sip, sip_len))) {
                send_reply(s_msg,400,cstring("Incorrect Protocol"));
            }

            static char websocket[] = "websocket";
            static size_t websocket_len = strlen(websocket);
            static char upgrade[] = "upgrade";
            static size_t upgrade_len = strlen(upgrade);
            if(s_msg->upgrade->value.len != websocket_len ||
               lower_cmp(s_msg->upgrade->value.s, websocket, websocket_len)) {
                if(s_msg->type == HTTP_REQUEST)
                    send_reply(s_msg,426,cstring("Upgrade Required"));
            } else if(s_msg->connection->value.len != upgrade_len ||
               lower_cmp(s_msg->connection->value.s, upgrade, upgrade_len)) {
                if(s_msg->type == HTTP_REQUEST)
                    send_reply(s_msg,400,cstring("Incorrect Connection Header"));
            } else if(s_msg->type == HTTP_REQUEST) {
                send_reply(s_msg,101,cstring("Switching Protocols"));
                ws_connected = true;
                output->on_ws_connected();
            } else if(s_msg->type == HTTP_REPLY) {
                get_sec_ws_accept_data(ws_key);
                if(ws_accept == s_msg->sec_ws_accept->value) {
                    ws_connected = true;
                    output->on_ws_connected();
                }
            }
        }

        delete s_msg;
    } else {
        trsp_base_input::on_parsed_received_msg(trsp, s_msg);
    }
}

ssize_t ws_input::recv_callback(wslay_event_context_ptr ctx, uint8_t* data, size_t len, int flags)
{
    ssize_t ret = (ws_input_len < len) ? ws_input_len : len;
    memcpy(data, ws_input_buf, ret);
    ws_input_len -= ret;
    ws_input_pos += ret;
    if(!ws_input_len)
        reset_input();
    return ret;
}

void ws_input::on_msg_recv(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg* arg)
{
    if(arg->opcode == WSLAY_TEXT_FRAME ||
       arg->opcode == WSLAY_CONTINUATION_FRAME) {
        memcpy(trsp_base_input::get_input(), arg->msg, arg->msg_length);
        trsp_base_input::add_input_len(arg->msg_length);
        parse_input(dynamic_cast<tcp_base_trsp*>(output));
    } else if(arg->opcode == WSLAY_CONNECTION_CLOSE) {
        output->on_ws_close();
    }
}

ssize_t ws_input::on_send_callback(wslay_event_context_ptr ctx, const uint8_t* data, size_t len, int flags)
{
    DBG("on_send_callback %ld", len);
    output->send_data((char*)data, len, flags);
    return len;
}

cstring ws_input::get_sec_ws_key_data()
{
    uint8_t data[KEY_LEN];
    for(int i = 0; i < KEY_LEN; i++) {
        data[i] = get_random() & 0xff;
    }
    std::string encData = Botan::base64_encode(data, KEY_LEN);
    memcpy((void*)ws_key.s, encData.c_str(), ws_key.len);
    return ws_key;
}

cstring ws_input::get_sec_ws_accept_data(const cstring& key)
{
    cstring guid(WEBSOCKET_GUID, strlen(WEBSOCKET_GUID));
    uint8_t* data = new uint8_t[key.len + guid.len];
    memcpy(data, key.s, key.len);
    memcpy(data + key.len, guid.s, guid.len);
    Botan::SHA_1 sha;
    Botan::secure_vector<uint8_t> hash = sha.process(data, key.len + guid.len);
    delete []data;
    std::string encData = Botan::base64_encode(hash.data(), hash.size());
    memcpy((void*)ws_accept.s, encData.c_str(), ws_accept.len);
    return ws_accept;
}

int ws_input::send_reply(sip_msg* req, int reply_code, const cstring& reason)
{
    static char close[] = "close";
    static int close_len = strlen(close);
    static char keepalive[] = "keep-alive";
    static int keepalive_len = strlen(keepalive);

    static cstring cstr_server("Server", strlen("Server"));
    static cstring cstr_sems("sems", strlen("sems"));
    static cstring cstr_date("Date", strlen("Date"));

    assert(req);
    int  reply_len = http_status_line_len(reason);
    char time_data[MAX_DATE_TIME];
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = gmtime(&rawtime);
    int time_d_len = strftime(time_data, MAX_DATE_TIME, "%a, %d %b %Y %X %Z", timeinfo);
    sip_header connection = *req->connection;
    sip_header upgrade = *req->upgrade;
    sip_header server(sip_header::H_OTHER, cstr_server, cstr_sems);
    sip_header date(sip_header::H_OTHER, cstr_date, cstring(time_data, time_d_len));
    sip_header sec_ws_accept(sip_header::H_SEC_WS_ACCEPT, cstring(HTTP_HDR_SEC_WS_ACCEPT, SIP_HDR_LEN(HTTP_HDR_SEC_WS_ACCEPT)), get_sec_ws_accept_data(req->sec_ws_key->value));
    reply_len += copy_hdr_len(&server);
    reply_len += copy_hdr_len(&date);
    if(reply_code >= 400) {
        connection.value.set(close, close_len);
        reply_len += copy_hdr_len(&connection);
    } else if(reply_code == 101) {
        reply_len += copy_hdr_len(&connection);
        reply_len += copy_hdr_len(&upgrade);
        reply_len += copy_hdr_len(req->sec_ws_version);
        reply_len += copy_hdr_len(&sec_ws_accept);
        if(req->sec_ws_protocol)
            reply_len += copy_hdr_len(req->sec_ws_protocol);
    } else {
        connection.value.set(keepalive, keepalive_len);
        reply_len += copy_hdr_len(&connection);
    }

    reply_len += 2/*CRLF*/;

    // Allocate buffer for the reply
    //
    char* reply_buf = new char[reply_len];
    char* c = reply_buf;

    http_status_line_wr(&c, reply_code, reason);
    copy_hdr_wr(&c, &date);
    copy_hdr_wr(&c, &server);
    copy_hdr_wr(&c, &connection);
    if(reply_code == 101) {
        copy_hdr_wr(&c, &upgrade);
        copy_hdr_wr(&c, req->sec_ws_version);
        copy_hdr_wr(&c, &sec_ws_accept);
        if(req->sec_ws_protocol)
            copy_hdr_wr(&c, req->sec_ws_protocol);
    }

    *c++ = CR;
    *c++ = LF;

    assert(output);
    int err = output->send(reply_buf,reply_len,0);
    delete [] reply_buf;
    return err;
}

int ws_input::send_request()
{
    static cstring get_method("GET", strlen("GET"));
    static cstring uri("/", strlen("/"));

    static cstring cstr_ws_version("13", strlen("13"));
    static cstring cstr_ws_protocol("sip", strlen("sip"));
    static cstring cstr_upgrade("upgrade", strlen("upgrade"));
    static cstring cstr_websocket("websocket", strlen("websocket"));
    static cstring cstr_host("Host", strlen("Host"));

    sip_header sec_ws_key(sip_header::H_SEC_WS_KEY, cstring(HTTP_HDR_SEC_WS_KEY, SIP_HDR_LEN(HTTP_HDR_SEC_WS_KEY)), get_sec_ws_key_data());
    sip_header sec_ws_version(sip_header::H_SEC_WS_VERSION, cstring(HTTP_HDR_SEC_WS_VERSION, SIP_HDR_LEN(HTTP_HDR_SEC_WS_VERSION)), cstr_ws_version);
    sip_header sec_ws_protocol(sip_header::H_SEC_WS_PROTOCOL, cstring(HTTP_HDR_SEC_WS_PROTOCOL, SIP_HDR_LEN(HTTP_HDR_SEC_WS_PROTOCOL)), cstr_ws_protocol);
    sip_header connection(sip_header::H_CONNECTION, cstring(HTTP_HDR_CONNECTION, SIP_HDR_LEN(HTTP_HDR_CONNECTION)), cstr_upgrade);
    sip_header upgrade(sip_header::H_UPGRADE, cstring(HTTP_HDR_UPGRADE, SIP_HDR_LEN(HTTP_HDR_UPGRADE)), cstr_websocket);
    sip_header host(sip_header::H_OTHER, cstr_host, output->get_host());
    sip_header origin(sip_header::H_ORIGIN, cstring(HTTP_HDR_ORIGIN, SIP_HDR_LEN(HTTP_HDR_ORIGIN)), output->get_host());

    int  req_len = http_request_line_len(get_method, uri);
    req_len += copy_hdr_len(&host);
    req_len += copy_hdr_len(&origin);
    req_len += copy_hdr_len(&upgrade);
    req_len += copy_hdr_len(&connection);
    req_len += copy_hdr_len(&sec_ws_version);
    req_len += copy_hdr_len(&sec_ws_key);
    req_len += copy_hdr_len(&sec_ws_protocol);
    req_len += 2/*CRLF*/;

    char* req_buf = new char [req_len];
    char* c = req_buf;
    http_request_line_wr(&c, get_method, uri);
    copy_hdr_wr(&c, &host);
    copy_hdr_wr(&c, &origin);
    copy_hdr_wr(&c, &upgrade);
    copy_hdr_wr(&c, &connection);
    copy_hdr_wr(&c, &sec_ws_version);
    copy_hdr_wr(&c, &sec_ws_key);
    copy_hdr_wr(&c, &sec_ws_protocol);
    *c++ = CR;
    *c++ = LF;

    assert(output);
    int err = output->send(req_buf, req_len, 0);
    delete [] req_buf;
    return err;
}

int wss_input::on_tls_record(tcp_base_trsp* trsp, const uint8_t data[] , size_t size)
{
    memcpy(input.get_input(), data, size);
    input.add_input_len(size);
    return input.on_input(trsp);
}

void wss_input::pre_write()
{
    input.pre_write();
}

void wss_input::post_write()
{
    input.post_write();
}

int wss_input::send(tcp_base_trsp::msg_buf* buf)
{
    return input.send(buf);
}

bool wss_input::is_connected()
{
    return input.is_connected();
}

ws_trsp_socket::ws_trsp_socket(trsp_server_socket* server_sock,
				 trsp_worker* server_worker,
				 int sd, const sockaddr_storage* sa,
                 trsp_socket::socket_transport transport, struct event_base* evbase)
  : tcp_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase, new ws_input(this, sd != -1))
{}

ws_trsp_socket::~ws_trsp_socket()
{}

int ws_trsp_socket::send_data(const char* msg, const int msg_len, unsigned int flags)
{
    send_q.push_back(new msg_buf(&peer_addr,(char*)msg,msg_len));

    if(connected) {
        add_write_event();
        DBG("write event added...");
    }
    return 0;
}

void ws_trsp_socket::on_ws_connected()
{
    DBG("************ on_ws_connect() ***********");
    DBG("new WS connection from %s:%u",
        get_peer_ip().c_str(),
        get_peer_port());
    add_write_event();
    DBG("write event added...");
}

void ws_trsp_socket::on_ws_close()
{
    close();
}

void ws_trsp_socket::pre_write()
{
    if(static_cast<ws_input*>(input)->is_connected())
        static_cast<ws_input*>(input)->pre_write();
    tcp_trsp_socket::pre_write();
}

void ws_trsp_socket::post_write()
{
    if(static_cast<ws_input*>(input)->is_connected())
        static_cast<ws_input*>(input)->post_write();
    tcp_trsp_socket::post_write();
}

int ws_trsp_socket::send(const sockaddr_storage* sa, const char* msg, const int msg_len, unsigned int flags)
{
  if(closed || (check_connection() < 0))
    return -1;

  DBG("add msg to send deque/from %s:%i to %s:%i\n--++--\n%.*s--++--\n",
            actual_ip.c_str(), actual_port,
            get_addr_str(sa).c_str(),
            am_get_port(sa),
            msg_len,msg);

  static_cast<ws_input*>(input)->send(new msg_buf(sa,msg,msg_len));

  if(connected) {
    add_write_event();
    DBG("write event added...");
  }

  return 0;
}

ws_socket_factory::ws_socket_factory(tcp_base_trsp::socket_transport transport)
 : trsp_socket_factory(transport)
{}

tcp_base_trsp* ws_socket_factory::create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker,
                                                int sd, const sockaddr_storage* sa, event_base* evbase)
{
    return new ws_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase);
}

ws_server_socket::ws_server_socket(short unsigned int if_num, short unsigned int proto_idx, unsigned int opts, socket_transport transport)
: trsp_server_socket(if_num, proto_idx, opts, new ws_socket_factory(transport))
{
}


wss_trsp_socket::wss_trsp_socket(trsp_server_socket* server_sock,
				 trsp_worker* server_worker,
				 int sd, const sockaddr_storage* sa,
                 trsp_socket::socket_transport transport, struct event_base* evbase)
  : tls_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase, new wss_input(this, sd != -1))
{}

wss_trsp_socket::~wss_trsp_socket()
{}

int wss_trsp_socket::send_data(const char* msg, const int msg_len, unsigned int flags)
{
    orig_send_q.push_back(new msg_buf(&peer_addr,(char*)msg,msg_len));

    if(connected) {
        add_write_event();
        DBG("write event added...");
    }
    return 0;
}

void wss_trsp_socket::on_ws_connected()
{
    DBG("************ on_wss_connect() ***********");
    DBG("new WSS connection from %s:%u",
        get_peer_ip().c_str(),
        get_peer_port());
    add_write_event();
    DBG("write event added...");
}

void wss_trsp_socket::on_ws_close()
{
    close();
}

void wss_trsp_socket::pre_write()
{
    if(static_cast<wss_input*>(input)->is_connected())
        static_cast<wss_input*>(input)->pre_write();
    tls_trsp_socket::pre_write();
}

void wss_trsp_socket::post_write()
{
    if(static_cast<wss_input*>(input)->is_connected())
        static_cast<wss_input*>(input)->post_write();
    tls_trsp_socket::post_write();
}

int wss_trsp_socket::send(const sockaddr_storage* sa, const char* msg, const int msg_len, unsigned int flags)
{
  if(closed || (check_connection() < 0))
    return -1;

  DBG("add msg to send deque/from %s:%i to %s:%i\n--++--\n%.*s--++--\n",
            actual_ip.c_str(), actual_port,
            get_addr_str(sa).c_str(),
            am_get_port(sa),
            msg_len,msg);

  static_cast<wss_input*>(input)->send(new msg_buf(sa,msg,msg_len));

  if(connected) {
    add_write_event();
    DBG("write event added...");
  }

  return 0;
}

wss_socket_factory::wss_socket_factory(tcp_base_trsp::socket_transport transport)
 : trsp_socket_factory(transport)
{}

tcp_base_trsp* wss_socket_factory::create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker,
                                                int sd, const sockaddr_storage* sa, event_base* evbase)
{
    return new wss_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase);
}

wss_server_socket::wss_server_socket(short unsigned int if_num, short unsigned int proto_idx,
                                     unsigned int opts, socket_transport transport,
                                     const tls_conf& s_client,
                                     const tls_conf& s_server)
: trsp_server_socket(if_num, proto_idx, opts, new wss_socket_factory(transport))
, tls_trsp_settings(s_client, s_server)
{
}
