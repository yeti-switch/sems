/*
 * $Id: ModMysql.cpp 1764 2010-04-01 14:33:30Z peter_lemenkov $
 *
 * Copyright (C) 2010 TelTech Systems Inc.
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#pragma once

#include "AmEvent.h"
#include "AmArg.h"
#include "AmSessionContainer.h"

#include <string>
using std::string;

#define JSONRPC_MSG_REQUEST  0
#define JSONRPC_MSG_RESPONSE 1
#define JSONRPC_MSG_ERROR    2
class JsonrpcNetstringsConnection;

#define JSONRPC_EVENT_ID   122
#define JSONRPC_QUEUE_NAME "jsonrpc"

struct JsonRpcEvent : public AmEvent {
    string connection_id;

    JsonRpcEvent()
        : AmEvent(JSONRPC_EVENT_ID)
    {
    }

    JsonRpcEvent(const string &connection_id)
        : AmEvent(JSONRPC_EVENT_ID)
        , connection_id(connection_id)
    {
    }

    virtual ~JsonRpcEvent() {}
};

struct JsonRpcResponse {
    string id;
    AmArg  data;
    bool   is_error;

    JsonRpcResponse(bool is_error, string id, const AmArg &data)
        : id(id)
        , data(data)
        , is_error(is_error)
    {
    }

    JsonRpcResponse(bool is_error, string id)
        : id(id)
        , is_error(is_error)
    {
    }

    ~JsonRpcResponse() {}
};

struct JsonRpcResponseEvent : public JsonRpcEvent {
    JsonRpcResponse response;
    AmArg           udata;

    JsonRpcResponseEvent(bool is_error, string id, const AmArg &data, const AmArg &udata)
        : response(is_error, id, data)
        , udata(udata)
    {
    }

    JsonRpcResponseEvent(bool is_error, string id)
        : response(is_error, id)
    {
    }

    ~JsonRpcResponseEvent() {}
};

struct JsonRpcRequestEvent : public JsonRpcEvent {
    string method;
    int    method_id;

    AmArg id;
    bool  is_notify;
    AmArg params;

    // notification without parameters
    JsonRpcRequestEvent(string method)
        : method(method)
    {
    }

    // notification with parameters
    JsonRpcRequestEvent(string method, AmArg params)
        : method(method)
        , is_notify(true)
        , params(params)
    {
    }

    // request without parameters
    JsonRpcRequestEvent(const string &method, const AmArg &id, bool is_notify)
        : method(method)
        , id(id)
        , is_notify(is_notify)
    {
    }

    // request with connection_id w/o parameters
    JsonRpcRequestEvent(const string &connection_id, const string &method, const AmArg &id, bool is_notify)
        : JsonRpcEvent(connection_id)
        , method(method)
        , id(id)
        , is_notify(is_notify)
    {
    }

    // request with parameters
    JsonRpcRequestEvent(const string &method, const AmArg &id, bool is_notify, const AmArg &params)
        : method(method)
        , id(id)
        , is_notify(is_notify)
        , params(params)
    {
    }

    // request with connection_id with parameters
    JsonRpcRequestEvent(const string &connection_id, const string &method, const AmArg &id, bool is_notify,
                        const AmArg &params)
        : JsonRpcEvent(connection_id)
        , method(method)
        , id(id)
        , is_notify(is_notify)
        , params(params)
    {
    }

    // request with method_id with parameters
    JsonRpcRequestEvent(const string &connection_id, const AmArg &id, bool is_notify, int method_id,
                        const AmArg &params)
        : JsonRpcEvent(connection_id)
        , method_id(method_id)
        , id(id)
        , is_notify(is_notify)
        , params(params)
    {
    }

    bool isNotification() { return is_notify; }
};

struct JsonRpcConnectionEvent : public JsonRpcEvent {
    enum { DISCONNECT = 0 };

    int    what;
    string connection_id;

    JsonRpcConnectionEvent(int what, const string &connection_id)
        : what(what)
        , connection_id(connection_id)
    {
    }

    ~JsonRpcConnectionEvent() {}
};


// events used internally:

struct JsonServerEvent : public AmEvent {
    enum EventType { StartReadLoop = 0, SendMessage };

    JsonrpcNetstringsConnection *conn;
    string                       connection_id;

    JsonServerEvent(JsonrpcNetstringsConnection *c, EventType ev_type)
        : AmEvent(ev_type)
        , conn(c)
    {
    }

    JsonServerEvent(const string &connection_id, EventType ev_type)
        : AmEvent(ev_type)
        , conn(nullptr)
        , connection_id(connection_id)
    {
    }

    ~JsonServerEvent() {}
};

struct JsonServerSendMessageEvent : public JsonServerEvent {
    bool   is_reply;
    string method;
    AmArg  id;
    AmArg  params;
    string reply_link;
    bool   is_error;
    AmArg  udata;

    JsonServerSendMessageEvent(const string &connection_id, bool is_reply, const string &method, const AmArg &id,
                               const AmArg &params, const AmArg &udata = AmArg(), const string &reply_link = "")
        : JsonServerEvent(connection_id, SendMessage)
        , is_reply(is_reply)
        , method(method)
        , id(id)
        , params(params)
        , reply_link(reply_link)
        , udata(udata)
    {
    }

    // reply
    JsonServerSendMessageEvent(const string &connection_id, const AmArg &id, const AmArg &params, bool is_error = false)
        : JsonServerEvent(connection_id, SendMessage)
        , is_reply(true)
        , id(id)
        , params(params)
        , is_error(is_error)
    {
    }

    JsonServerSendMessageEvent(const JsonServerSendMessageEvent &e, JsonrpcNetstringsConnection *conn)
        : JsonServerEvent(conn, SendMessage)
        , is_reply(e.is_reply)
        , method(e.method)
        , id(e.id)
        , params(e.params)
        , reply_link(e.reply_link)
        , is_error(e.is_error)
        , udata(e.udata)
    {
        connection_id = e.connection_id;
    }
};

// async jsonrpc helpers
inline void postJsonRpcReply(const string &connection_id, const AmArg &request_id, const AmArg &params,
                             bool is_error = false)
{
    AmSessionContainer::instance()->postEvent(
        JSONRPC_QUEUE_NAME, new JsonServerSendMessageEvent(connection_id, request_id, params, is_error));
}

inline void postJsonRpcReply(const JsonRpcRequestEvent &request, const AmArg &params, bool is_error = false)
{
    postJsonRpcReply(request.connection_id, request.id, params, is_error);
}

inline void postJsonRpcRequestEvent(const string &queue_name, const string &connection_id, const AmArg &request_id,
                                    bool is_notify, int method_id, const AmArg &params)
{
    if (!AmSessionContainer::instance()->postEvent(
            queue_name, new JsonRpcRequestEvent(connection_id, request_id, is_notify, method_id, params)))
    {
        postJsonRpcReply(connection_id, request_id, "queue not found", true);
    }
}
