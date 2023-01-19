#include "WsRpcPeer.h"
#include "AmUtils.h"

#include "botan/sha160.h"
#include "botan/base64.h"

#include "sip/parse_common.h"
#include "sip/parse_header.h"
#include "sip/msg_fline.h"
#include "sip/defs.h"
#include "sip/msg_hdrs.h"
#include "JsonRPC.h"

#define MAX_DATE_TIME 80
#define KEY_LEN 16  //see rfc6455 sec.4.1
#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

struct wslay_event_callbacks WsRpcPeer::callbacks = {
    WsRpcPeer::recv_callback,
    WsRpcPeer::send_callback,
    WsRpcPeer::genmask_callback,
    NULL, /* on_frame_recv_start_callback */
    NULL, /* on_frame_recv_callback */
    NULL, /* on_frame_recv_end_callback */
    WsRpcPeer::on_msg_recv_callback
};

WsRpcPeer::WsRpcPeer(const std::string& id) 
: JsonrpcNetstringsConnection(id), ws_connected(false)
, ctx_(0) {
    Botan::SHA_1 sha;
    size_t size = Botan::base64_encode_max_output(sha.output_length());
    ws_accept.set(new char[size], size);
    size = Botan::base64_encode_max_output(KEY_LEN);
    ws_key.set(new char[size], size);
    pst.reset((char*)msgbuf);
}

WsRpcPeer::~WsRpcPeer() {
    delete ws_accept.s;
    delete ws_key.s;
    if(ctx_)
        wslay_event_context_free(ctx_);
}

int WsRpcPeer::connect(const std::string& host, int port, std::string& res_str) {
    int ret = JsonrpcNetstringsConnection::connect(host, port, res_str);
    if(conn_type == PEER_TCP || ret) return ret;

    wslay_event_context_client_init(&ctx_, &callbacks, this);
    send_request();
    return 0;
}

int WsRpcPeer::netstringsRead() {
    if(conn_type == PEER_TCP)
        return JsonrpcNetstringsConnection::netstringsRead();

    if(!ws_connected) {
        int r = read_data(msgbuf, 1);
        if (!r) {
            DBG("closing connection [%p/%d] on peer hangup", this, fd);
            close();
            return REMOVE;
        }

        if ((r<0 && errno == EAGAIN) ||
            (r<0 && errno == EWOULDBLOCK))
                return CONTINUE;

        if (r != 1) {
            INFO("socket error on connection [%p/%d]: %s",
                this, fd, strerror(errno));
            close();
            return REMOVE;
        }

        rcvd_size += 1;

        if(conn_type != PEER_WS && conn_type != PEER_WSS)
            return CONTINUE;

        rcvd_size += read_data(msgbuf + 1, MAX_RPC_MSG_SIZE - 1);
        int err = skip_sip_msg_async(&pst, (char*)(msgbuf+rcvd_size));
        if(err) {
            if(err == UNEXPECTED_EOT) {
                return CONTINUE;
            } else {
                ERROR("parsing error %d",err);
                close();
                return REMOVE;
            }
        }

        DBG("received message [%p/%d]\n%.*s", this, fd, rcvd_size, msgbuf);
        std::auto_ptr<sip_msg> s_msg(new sip_msg((const char*)msgbuf, rcvd_size));
        resetRead();
        char* err_msg=0;
        err = parse_http_msg(s_msg.get(), err_msg);
        if(err){
            DBG("parse_http_msg returned %i",err);

            if(!err_msg){
                err_msg = (char*)"unknown parsing error";
            }
            DBG("parsing error: %s",err_msg);

            if((err != MALFORMED_FLINE) &&
            (s_msg->type == HTTP_REQUEST) &&
            (s_msg->u.request->method != sip_request::GET)){
                    send_reply(s_msg.get(),400,err_msg);
            }
            return REMOVE;
        }

        if(parse_input(s_msg.get()))
            return REMOVE;
    } else {
        int r = read_data(msgbuf, MAX_RPC_MSG_SIZE);
        if (!r) {
            DBG("closing connection [%p/%d] on peer hangup", this, fd);
            close();
            return REMOVE;
        }

        if ((r<0 && errno == EAGAIN) ||
            (r<0 && errno == EWOULDBLOCK))
                return CONTINUE;

        msg_size = r;
        return DISPATCH;
    }
    return CONTINUE;
}

int WsRpcPeer::netstringsBlockingWrite() {
    if(conn_type == PEER_TCP)
        return JsonrpcNetstringsConnection::netstringsBlockingWrite();

    if(!send_data(msgbuf, msg_size)) return REMOVE;
    rcvd_size = 0;
    msg_size = 0;
    return CONTINUE;
}

int WsRpcPeer::send_data(char* data, int size) {
    if(conn_type == PEER_TCP || !ws_connected)
        return JsonrpcNetstringsConnection::send_data(data, size);

    wslay_event_msg e_msg = {
        .opcode = WSLAY_TEXT_FRAME,
        .msg = (uint8_t*)data,
        .msg_length = (size_t)size
    };
    int ret = 0;
    if((ret = wslay_event_queue_msg(ctx_, &e_msg)) != 0) {
        WARN("wslay_event_queue_msg return error %d. restore queue", ret);
        return 0;
    }
    wslay_event_send(ctx_);
    return size;
}


cstring WsRpcPeer::get_sec_ws_accept_data(const cstring& key)
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

void WsRpcPeer::send_reply(sip_msg* req, int reply_code, const std::string& reason) {
    static char close[] = "close";
    static int close_len = strlen(close);
    static char keepalive[] = "keep-alive";
    static int keepalive_len = strlen(keepalive);

    static cstring cstr_server("Server", strlen("Server"));
    static cstring cstr_sems("sems", strlen("sems"));
    static cstring cstr_date("Date", strlen("Date"));

    assert(req);
    msg_size = http_status_line_len(cstring(reason.c_str(), reason.size()));
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
    msg_size += copy_hdr_len(&server);
    msg_size += copy_hdr_len(&date);
    if(reply_code >= 400) {
        connection.value.set(close, close_len);
        msg_size += copy_hdr_len(&connection);
    } else if(reply_code == 101) {
        msg_size += copy_hdr_len(&connection);
        msg_size += copy_hdr_len(&upgrade);
        msg_size += copy_hdr_len(req->sec_ws_version);
        msg_size += copy_hdr_len(&sec_ws_accept);
        if(req->sec_ws_protocol)
            msg_size += copy_hdr_len(req->sec_ws_protocol);
    } else {
        connection.value.set(keepalive, keepalive_len);
        msg_size += copy_hdr_len(&connection);
    }

    msg_size += 2/*CRLF*/;

    // Allocate buffer for the reply
    //
    char* c = msgbuf;

    http_status_line_wr(&c, reply_code, cstring(reason.c_str(), reason.size()));
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
    DBG("send message [%p/%d]\n%.*s", this, fd, msg_size, msgbuf);
    netstringsBlockingWrite();
}

int WsRpcPeer::read_data(char* data, int size) {
    if(conn_type == PEER_UNKNOWN) {
        if(size != 1) {
            ERROR("incorrect reading size of peer in initial state");
            return 0;
        }
        int recv_size = read(fd, data, 1);
        if(recv_size != 1) return recv_size;
        // http request(websocket)
        if(*data == 'G') {
            conn_type = PEER_WS;
            wslay_event_context_server_init(&ctx_, &callbacks, this);
        // netstrings 
        } else if(*data >= '0' && *data <= '9') {
            conn_type = PEER_TCP;
        } else return 0;
        return 1;
    } else if(conn_type == PEER_TCP || !ws_connected) {
        return JsonrpcNetstringsConnection::read_data(data, size);
    }

    if(ws_resv_buffer.empty() && wslay_event_recv(ctx_)) return 0;
    int read_size = size > ws_resv_buffer.size() ? ws_resv_buffer.size() : size;
    for(int i = 0; i < read_size; i++) {
        data[i] = ws_resv_buffer.front();
        ws_resv_buffer.pop_front();
    }
    return read_size;
}

int WsRpcPeer::genmask_callback(wslay_event_context_ptr ctx, uint8_t* buf, size_t len, void* user_data) {
    (void)user_data;
    for(size_t i = 0; i < len; i++) {
        buf[i] = get_random() & 0xff;
    }
    return 0;
}

void WsRpcPeer::on_msg_recv(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg* arg) {
    if(arg->opcode == WSLAY_TEXT_FRAME ||
       arg->opcode == WSLAY_CONTINUATION_FRAME) {
        for(int i = 0; i< arg->msg_length; i++) {
            ws_resv_buffer.push_back(arg->msg[i]);
        }
    } else if(arg->opcode == WSLAY_CONNECTION_CLOSE) {
        close();
    }
}

void WsRpcPeer::on_msg_recv_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg* arg, void* user_data) {
    WsRpcPeer* input = (WsRpcPeer*)user_data;
    input->on_msg_recv(ctx, arg);
}

ssize_t WsRpcPeer::recv_callback(wslay_event_context_ptr ctx, uint8_t* data, size_t len, int flags) {
    (void) flags;
    int recv_size = read(fd, data, len);
    if(!recv_size ||
       (recv_size<0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
        wslay_event_set_error(ctx, WSLAY_ERR_NO_MORE_MSG);
    }

    return recv_size;
}

ssize_t WsRpcPeer::recv_callback(wslay_event_context_ptr ctx, uint8_t* data, size_t len, int flags, void* user_data) {
    WsRpcPeer* input = (WsRpcPeer*)user_data;
    int ret = input->recv_callback(ctx, data, len, flags);
    if(!ret) {
        return WSLAY_ERR_WOULDBLOCK;
    }
    return ret;
}

ssize_t WsRpcPeer::send_callback(wslay_event_context_ptr ctx, const uint8_t* data, size_t len, int flags, void* user_data) {
    WsRpcPeer* input = (WsRpcPeer*)user_data;
    return input->on_send_callback(ctx, data, len, flags);
}

ssize_t WsRpcPeer::on_send_callback(wslay_event_context_ptr ctx, const uint8_t* data, size_t len, int flags) {
    return JsonrpcNetstringsConnection::send_data((char*)data, len);
}

int WsRpcPeer::parse_input(sip_msg* s_msg) {
    static char websocket[] = "websocket";
    static size_t websocket_len = strlen(websocket);
    static char upgrade[] = "upgrade";
    static size_t upgrade_len = strlen(upgrade);
    if(s_msg->upgrade->value.len != websocket_len ||
        lower_cmp(s_msg->upgrade->value.s, websocket, websocket_len)) {
        if(s_msg->type == HTTP_REQUEST) {
            send_reply(s_msg,426,string("Upgrade Required"));
            return -1;
        }
    } else if(s_msg->connection->value.len != upgrade_len ||
        lower_cmp(s_msg->connection->value.s, upgrade, upgrade_len)) {
        if(s_msg->type == HTTP_REQUEST) {
            send_reply(s_msg,400,string("Incorrect Connection Header"));
            return -1;
        }
    } else if(s_msg->type == HTTP_REQUEST) {
        send_reply(s_msg,101,string("Switching Protocols"));
        ws_connected = true;
    } else if(s_msg->type == HTTP_REPLY) {
        get_sec_ws_accept_data(ws_key);
        if(ws_accept == s_msg->sec_ws_accept->value.s) {
            ws_connected = true;
            string data;
            std::for_each(ws_send_buffer.begin(), ws_send_buffer.end(), [&data](char c){data.push_back(c);});
            JsonrpcNetstringsConnection::addMessage(data.c_str(), data.size());
            netstringsBlockingWrite();
        } else {
            return -1;
        }
    }
    return 0;
}

cstring WsRpcPeer::get_sec_ws_key_data() {
    uint8_t data[KEY_LEN];
    for(int i = 0; i < KEY_LEN; i++) {
        data[i] = get_random() & 0xff;
    }
    std::string encData = Botan::base64_encode(data, KEY_LEN);
    memcpy((void*)ws_key.s, encData.c_str(), ws_key.len);
    return ws_key;
}

void WsRpcPeer::send_request() {
    static cstring get_method("GET", strlen("GET"));
    static cstring uri("/", strlen("/"));

    static cstring cstr_ws_version("13", strlen("13"));
    static cstring cstr_upgrade("upgrade", strlen("upgrade"));
    static cstring cstr_websocket("websocket", strlen("websocket"));
    static cstring cstr_host("Host", strlen("Host"));

    string hoststr = JsonRPCServerModule::instance()->host;
    hoststr += ":";
    char portstr[10] = {0};
    sprintf(portstr, "%d", JsonRPCServerModule::instance()->port);
    hoststr += portstr;

    sip_header sec_ws_key(sip_header::H_SEC_WS_KEY, cstring(HTTP_HDR_SEC_WS_KEY, SIP_HDR_LEN(HTTP_HDR_SEC_WS_KEY)), get_sec_ws_key_data());
    sip_header sec_ws_version(sip_header::H_SEC_WS_VERSION, cstring(HTTP_HDR_SEC_WS_VERSION, SIP_HDR_LEN(HTTP_HDR_SEC_WS_VERSION)), cstr_ws_version);
    sip_header connection(sip_header::H_CONNECTION, cstring(HTTP_HDR_CONNECTION, SIP_HDR_LEN(HTTP_HDR_CONNECTION)), cstr_upgrade);
    sip_header upgrade(sip_header::H_UPGRADE, cstring(HTTP_HDR_UPGRADE, SIP_HDR_LEN(HTTP_HDR_UPGRADE)), cstr_websocket);
    sip_header host(sip_header::H_OTHER, cstr_host, cstring(hoststr.c_str(), hoststr.size()));
    sip_header origin(sip_header::H_ORIGIN, cstring(HTTP_HDR_ORIGIN, SIP_HDR_LEN(HTTP_HDR_ORIGIN)), cstring(hoststr.c_str(), hoststr.size()));

    msg_size = http_request_line_len(get_method, uri);
    msg_size += copy_hdr_len(&host);
    msg_size += copy_hdr_len(&origin);
    msg_size += copy_hdr_len(&upgrade);
    msg_size += copy_hdr_len(&connection);
    msg_size += copy_hdr_len(&sec_ws_version);
    msg_size += copy_hdr_len(&sec_ws_key);
    msg_size += 2/*CRLF*/;

    char* c = msgbuf;
    http_request_line_wr(&c, get_method, uri);
    copy_hdr_wr(&c, &host);
    copy_hdr_wr(&c, &origin);
    copy_hdr_wr(&c, &upgrade);
    copy_hdr_wr(&c, &connection);
    copy_hdr_wr(&c, &sec_ws_version);
    copy_hdr_wr(&c, &sec_ws_key);
    *c++ = CR;
    *c++ = LF;

    INFO("send message [%p/%d]\n%.*s", this, fd, msg_size, msgbuf);
    netstringsBlockingWrite();
}

void WsRpcPeer::addMessage(const char* data, size_t len) {
    if(conn_type == PEER_TCP || ws_connected) JsonrpcNetstringsConnection::addMessage(data, len);
    for(int i = 0; i< len; i++) {
        ws_send_buffer.push_back(data[i]);
    }
}

void WsRpcPeer::clearMessage() {
    if(conn_type == PEER_TCP || ws_connected) JsonrpcNetstringsConnection::clearMessage();
    ws_send_buffer.clear();
}
