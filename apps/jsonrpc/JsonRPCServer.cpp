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

#include "JsonRPCServer.h"
#include "RpcPeer.h"
#include "JsonRPCEvents.h"
#include "jsonArg.h"

#include "AmEventDispatcher.h"
#include "AmPlugIn.h"
#include "log.h"
#include "AmApi.h"
#include "AmSession.h"
#include "AmUtils.h"

std::map<std::string, std::string> JsonRpcServer::rpc_methods_mapping;

int JsonRpcServer::createRequest(const string& evq_link, const string& method, 
				 AmArg& params, JsonrpcNetstringsConnection* peer, 
				 const AmArg& udata,
				 bool is_notification) {
  AmArg rpc_params;
  rpc_params["jsonrpc"] = "2.0";
  rpc_params["method"] = method;
  rpc_params["params"] = params;
  if (!is_notification) {
    peer->req_id++;
    string req_id = int2str(peer->req_id);
    rpc_params["id"] = req_id;

    if (!evq_link.empty()) 
      peer->replyReceivers[req_id] = make_pair(evq_link, udata);
    DBG("registering reply sink '%s' for id %s", 
	evq_link.c_str(), req_id.c_str());

  }

  string rpc_params_json = arg2json(rpc_params);
  if (rpc_params_json.length() > MAX_RPC_MSG_SIZE) {
    ERROR("internal error: message exceeded MAX_RPC_MSG_SIZE (%d)", 
	  MAX_RPC_MSG_SIZE);
    return -3;
  }

  DBG("RPC message: >>%.*s<<", (int)rpc_params_json.length(), rpc_params_json.c_str());
  peer->addMessage(rpc_params_json.c_str(), rpc_params_json.length());
  // set peer connection up for sending
  peer->msg_recv = false;
  return 0;
}

int JsonRpcServer::createReply(
    JsonrpcNetstringsConnection* peer,
    const AmArg &id,
    AmArg& result, bool is_error)
{

  AmArg rpc_res;
  rpc_res["id"] = id;
  rpc_res["jsonrpc"] = "2.0";
  if (is_error)
    rpc_res["error"] = result;
  else
    rpc_res["result"] = result;

  string res_s = arg2json(rpc_res);
  if (res_s.length() > MAX_RPC_MSG_SIZE) {
    ERROR("internal error: reply exceeded MAX_RPC_MSG_SIZE (%d)",
	  MAX_RPC_MSG_SIZE);
    return -3;
  }

  DBG("created RPC reply: >>%.*s<<", (int)res_s.length(), res_s.c_str());
  peer->addMessage(res_s.c_str(), res_s.length());

  return 0;
}

void generate_error_reply(string &msgbuf, const string &id, bool id_is_int,
                                  int error_code, const char *error_message, ...)
{
    va_list args;
    size_t offset;
    int size = snprintf(0, 0,
        "{ \"jsonrpc\": \"2.0\", \"id\": %s%s%s, \"error\": { \"code\": %d, \"message\": \"",
        id_is_int ? "": "\"", id.data(), id_is_int ? "": "\"",
        error_code);
    va_start (args, error_message);
    size += vsnprintf(0, 0,
        error_message, args);
    va_end (args);
    size += snprintf(0, 0, "\" }}");

    msgbuf.resize(size);
    char* buf = (char*)msgbuf.c_str();
    offset = snprintf(buf, MAX_RPC_MSG_SIZE,
        "{ \"jsonrpc\": \"2.0\", \"id\": %s%s%s, \"error\": { \"code\": %d, \"message\": \"",
        id_is_int ? "": "\"", id.data(), id_is_int ? "": "\"",
        error_code);

    va_start (args, error_message);
    offset += vsnprintf(buf+offset, MAX_RPC_MSG_SIZE-offset,
        error_message, args);
    va_end (args);

    offset += snprintf(buf+offset, MAX_RPC_MSG_SIZE-offset, "\" }}");
}

void generate_reply(string &msgbuf, const string &id, bool id_is_int,
                                  const char *fmt, ...)
{
    va_list args;
    size_t offset;
    size_t size = snprintf(0, 0,
        "{ \"jsonrpc\": \"2.0\", \"id\": %s%s%s, \"result\": ",
        id_is_int ? "": "\"", id.data(), id_is_int ? "": "\"");
    va_start (args, fmt);
    size += vsnprintf(0,0,fmt, args);
    va_end (args);
    size += snprintf(0,0, "}");

    msgbuf.resize(size);
    char* buf = (char*)msgbuf.c_str();
    offset = snprintf(buf, MAX_RPC_MSG_SIZE,
        "{ \"jsonrpc\": \"2.0\", \"id\": %s%s%s, \"result\": ",
        id_is_int ? "": "\"", id.data(), id_is_int ? "": "\"");

    va_start (args, fmt);
    offset += vsnprintf(buf+offset, MAX_RPC_MSG_SIZE-offset,
        fmt, args);
    va_end (args);

    offset += snprintf(buf+offset, MAX_RPC_MSG_SIZE-offset, "}");
}
int JsonRpcServer::processMessage(const char* msgbuf, unsigned int msg_size,
                                 JsonrpcPeerConnection* peer)
{
    //DBG("parsing message ...");
    // const char* txt = "{\"jsonrpc\": \"2.0\", \"result\": 19, \"id\": 1}";
    AmArg rpc_params;
    if (!json2arg(msgbuf, rpc_params)) {
        INFO("Error parsing message '%.*s'", (int)msg_size, msgbuf);
        return -1;
    }

    if(!rpc_params.hasMember("jsonrpc") ||
       !isArgCStr(rpc_params["jsonrpc"]) ||
       strcmp(rpc_params["jsonrpc"].asCStr(), "2.0")) {
        INFO("wrong json-rpc version received; only 2.0 supported!");
        return -2; // todo: check value, reply with error?
    }

    bool is_request = (rpc_params.hasMember("method") && isArgCStr(rpc_params["method"]));
    if(!is_request) {
        // todo: move this to  peer->processReply(rpc_params);

        // process reply
        if (!rpc_params.hasMember("id") || !isArgCStr(rpc_params["id"])
            || rpc_params["id"] == "")
        {
            INFO("Error parsing jsonrpc message: no id in reply!");
            return -2;// todo: check value, reply with error?
        }
        string id = rpc_params["id"].asCStr();

        std::map<std::string, std::pair<std::string, AmArg > >::iterator
        rep_recv_q = peer->replyReceivers.find(id);
        if (rep_recv_q == peer->replyReceivers.end()) {
            DBG("received reply for unknown request");
            peer->clearMessage();

            if (peer->flags & JsonrpcPeerConnection::FL_CLOSE_WRONG_REPLY) {
                INFO("closing connection after unknown reply id %s received", id.c_str());
                return -2;
            }
            return 0;
        }

        const AmArg& udata = rep_recv_q->second.second;
        const string& event_queue_id = rep_recv_q->second.first;

        JsonRpcResponseEvent* resp_ev = NULL; 
        if (rpc_params.hasMember("result")) {
            resp_ev = new JsonRpcResponseEvent(false, id, rpc_params["result"], udata);
        } else {
            if (!rpc_params.hasMember("error")) {
                INFO("protocol error: reply does not have error nor result!");
                return -2;
            }
            resp_ev = new JsonRpcResponseEvent(true, id, rpc_params["error"], udata);
        }

        resp_ev->connection_id = peer->id;
        bool posted = AmEventDispatcher::instance()->
            post(event_queue_id, resp_ev);
        if (!posted) {
            DBG("receiver event queue does not exist (any more)");
            peer->replyReceivers.erase(rep_recv_q);
            peer->clearMessage();
            if (peer->flags & JsonrpcPeerConnection::FL_CLOSE_NO_REPLYLINK) {
                INFO("closing connection where reply link missing");
                return -2;
            }
            return 0;
        }

        DBG("successfully posted reply to event queue");
        peer->replyReceivers.erase(rep_recv_q);
        // don't send a reply
        peer->clearMessage();
        return 0;

    } //if(!is_request)

    //process request
    AmArg id;
    bool is_notify;
    if (rpc_params.hasMember("id")) {
        id = rpc_params["id"];
        is_notify = false;
    } else {
        is_notify = true;
        DBG("received notification");
    }

    if(peer->flags & JsonrpcPeerConnection::FL_REJECTED) {
        JsonrpcNetstringsConnection* conn = dynamic_cast<JsonrpcNetstringsConnection*>(peer);
        assert(conn);
        AmArg result("forbidden");
        createReply(conn, id, result, true);
        return 0;
    }

    // process set notification/request receiver methods
    const auto &method = rpc_params["method"];
    static AmArg set_notify_sink_arg("jsonrpc.setNotifySink");
    static AmArg set_request_sink_arg("jsonrpc.setRequestSink");
    if(method == set_notify_sink_arg) {
        AmArg &params = rpc_params["params"];
        if(!isArgCStr(params)) {
            string reply;
            generate_error_reply(
                reply,
                arg2str(id), isArgInt(id),
                500, "wrong 'params' type %s for method %s. expected string",
                params.getTypeStr(), method.asCStr());
            peer->addMessage(reply.c_str(), reply.size());
            return 0;
        }

        string reply;
        generate_reply(
            reply,
            arg2str(id), isArgInt(id),
            "\"changed '%s' -> '%s'\"",
            peer->notificationReceiver.data(), params.asCStr());
        peer->addMessage(reply.c_str(), reply.size());

        peer->notificationReceiver = params.asCStr();
        return 0;
    } else if(method == set_request_sink_arg) {
        AmArg &params = rpc_params["params"];
        if(!isArgCStr(params)) {
            string reply;
            generate_error_reply(
                reply,
                arg2str(id), isArgInt(id),
                500, "wrong 'params' type %s for method %s. expected string",
                params.getTypeStr(), method.asCStr());
            peer->addMessage(reply.c_str(), reply.size());
            return 0;
        }

        string reply;
        generate_reply(
            reply,
            arg2str(id), isArgInt(id),
            "\"changed '%s' -> '%s'\"",
            peer->requestReceiver.data(), params.asCStr());
        peer->addMessage(reply.c_str(), reply.size());

        peer->requestReceiver = params.asCStr();
        return 0;
    }

    // send directly to event queue
    if ((is_notify && !peer->notificationReceiver.empty()) ||
        (!is_notify && !peer->requestReceiver.empty()))
    {
        // don't send a reply
        peer->clearMessage();

        string dst_evqueue = is_notify ?
            peer->notificationReceiver.c_str() : peer->requestReceiver.c_str();

        DBG("directly passing %s to event queue '%s'",
            is_notify ? "notification":"request",
            dst_evqueue.c_str());

        AmArg none_params;
        AmArg& params = none_params;
        if (rpc_params.hasMember("params")) {
            params = rpc_params["params"];
        }

        JsonRpcRequestEvent* request_ev =
            new JsonRpcRequestEvent(rpc_params["method"].asCStr(), id, is_notify, params);

        request_ev->connection_id = peer->id;

        bool posted = AmEventDispatcher::instance()->
            post(dst_evqueue, request_ev);

        if(!posted) {
            DBG("%s receiver event queue '%s' does not exist (any more)",
                is_notify ? "notification":"request",
                dst_evqueue.c_str());

            delete request_ev;

            if (is_notify && (peer->flags & JsonrpcPeerConnection::FL_CLOSE_NO_NOTIF_RECV)) {
                INFO("closing connection on missing notification receiver queue");
                return -1; // todo: reply error?
            }

            if (!is_notify && (peer->flags & JsonrpcPeerConnection::FL_CLOSE_NO_REQUEST_RECV)) {
                INFO("closing connection on missing request receiver queue");
                return -1; // todo: reply error?
            }
        } else {
            DBG("successfully posted %s to event queue '%s'",
            is_notify ? "notification":"request",
            dst_evqueue.c_str());
        }
        return 0;
    }

    AmArg rpc_res;
    if(execRpc(peer->id, rpc_params, rpc_res)) {
        DBG3("request consumed by async invocation");
        peer->clearMessage();
        return 0;
    }

    if(!is_notify) {
        rpc_res["id"] = id;
        rpc_res["jsonrpc"] = "2.0";
    }

    string res_s = arg2json(rpc_res);
    if (res_s.length() > MAX_RPC_MSG_SIZE) {
        ERROR("internal error: reply exceeded MAX_RPC_MSG_SIZE (%d)",
              MAX_RPC_MSG_SIZE);
        return -3;
    }

    //DBG("RPC result: >>%.*s<<", (int)res_s.length(), res_s.c_str());
    peer->addMessage(res_s.c_str(), res_s.length());
    return 0;
}

/** rpc_params must contain "method" member as string */
bool JsonRpcServer::execRpc(const string &connection_id, const AmArg& rpc_params, AmArg& rpc_res) {
    AmArg none_params;
    AmArg& params = none_params;
    if (rpc_params.hasMember("params")) {
      params = rpc_params["params"];
    }

    string method = rpc_params["method"].asCStr();

    AmArg id;
    if (rpc_params.hasMember("id")) {
        id = rpc_params["id"];
    }

    if(rpc_methods_mapping.contains(method))
        method = rpc_methods_mapping[method];

    return execRpc(connection_id, method, id, params, rpc_res);
}

static bool traverse_tree(AmDynInvoke* di,const string &method, AmArg args, AmArg &ret) {
    AmArg methods_list;
    try {

        if(di->is_methods_tree()) {
            di->get_methods_tree(ret);
            return true;
        }

        if(method.empty()) di->invoke("_list",args,methods_list);
        else di->invoke(method,args,methods_list);

        if(!isArgArray(methods_list))
            return false;

        for(size_t i = 0; i < methods_list.size(); i++) {
            AmArg &entry = methods_list[i];
            if(isArgArray(entry)) {
                //non-dotted RpcTreeHandler inheritors
                if(entry.size()>0 && isArgCStr(entry[0])) {
                    AmArg a = args;
                    if(a.size()) {
                        a.pop_back();
                        a.push(entry[0].asCStr());
                    }
                    a.push("_list");
                    AmArg &r = ret[entry[0].asCStr()];
                    traverse_tree(di,method.empty() ? entry[0].asCStr() : method,a,r);
                }
            } else if(isArgCStr(entry)) {
                //old factories with plain methods layout
                //aviod to call recursive _list for them
                ret[entry.asCStr()] = AmArg();
            }
        }
        return true;
    } catch(...) {
        return false;
    }
}

bool JsonRpcServer::execRpc(const string &connection_id, const string& method, const AmArg& id, const AmArg& params, AmArg& rpc_res) {

try  {

    if(method=="_list") {
        AmPlugIn::instance()->listFactories4Di(rpc_res["result"]);
        rpc_res["id"] = id;
        rpc_res["jsonrpc"] = "2.0";
        return false;
    }

    if(method=="_tree") {
        AmArg ret;
        AmArg fake_args;
        fake_args.assertArray();
        AmDynInvoke* di_inst;
        AmDynInvokeFactory* fact;

        AmPlugIn::instance()->listFactories4Di(ret);
        if(!isArgArray(ret))
            return false;

        AmArg &result = rpc_res["result"];
        for(size_t i = 0; i < ret.size(); i++) {
            AmArg &factory_name = ret[i];
            if(!isArgCStr(factory_name))
                continue;
            fact = AmPlugIn::instance()->getFactory4Di(factory_name.asCStr());
            if (fact==NULL)
                continue;
            di_inst = fact->getInstance();
            if(!di_inst)
                continue;
            //DBG("process factory: %s",factory_name.asCStr());
            if(!traverse_tree(di_inst,string(),fake_args,result[factory_name.asCStr()]))
                result.erase(factory_name.asCStr());
        }
        return false;
    }

    size_t dot_pos = method.find('.');
    if (dot_pos == string::npos || dot_pos == method.length()) {
        throw JsonRpcError(-32601, "Method not found",
            "use module.method as rpc method name");
    }
    string factory = method.substr(0, method.find('.'));
    string fact_meth = method.substr(method.find('.')+1);

    try {
        DBG3("searching for factory '%s' method '%s'",
            factory.c_str(), fact_meth.c_str());
        AmDynInvokeFactory* fact =
            AmPlugIn::instance()->getFactory4Di(factory);
        if (fact==NULL) {
            throw JsonRpcError(-32601, "Method not found",
                "module not loaded");
        }
        AmDynInvoke* di_inst = fact->getInstance();
        if(!di_inst) {
            throw JsonRpcError(-32601, "Method not found",
                "failed to instanciate module");
        }

        if((!connection_id.empty()) && di_inst->invoke_async(
            connection_id, id,
            fact_meth, params))
        {
            return true;
        }

        di_inst->invoke(fact_meth, params, rpc_res["result"]);
    } catch (const AmDynInvoke::NotImplemented& ni) {
        DBG("not implemented DI function '%s'",
            ni.what.c_str());
        throw JsonRpcError(-32601, "Method not found",
            "function unknown in module");
    } catch (const AmDynInvoke::Exception& e) {
        DBG("got AmDynInvoke exception in RPC DI call. method: %s, params: %s, "
            "code: %d, reason: %s",
            method.c_str(),AmArg::print(params).c_str(),
            e.code,e.reason.c_str());
        throw JsonRpcError(e.code,e.reason,AmArg());
    } catch (const AmArg::OutOfBoundsException& oob) {
        DBG("out of bounds in  RPC DI call");
        throw JsonRpcError(-32602, "Invalid params",
            "out of bounds in function call");
    } catch (const AmArg::TypeMismatchException& oob) {
        DBG("type mismatch  in  RPC DI call");
        throw JsonRpcError(-32602, "Invalid params",
            "parameters type mismatch in function call");
    } catch (const JsonRpcError& e) {
        throw;
    } catch (AmSession::Exception &e) {
        DBG("got AmSession exception in RPC DI call. method: %s, params: %s, "
            "code: %d, reason: %s",
            method.c_str(),AmArg::print(params).c_str(),
            e.code,e.reason.c_str());
        throw JsonRpcError(e.code,e.reason,AmArg());
    } catch (...) {
        DBG("unexpected Exception in RPC DI call. method: %s, params: %s",
            method.c_str(),AmArg::print(params).c_str());
        throw JsonRpcError(-32000, "Server error",
            "unexpected Exception");
    }
    // todo: notification!
    rpc_res["id"] = id;
    rpc_res["jsonrpc"] = "2.0";
} catch (const JsonRpcError& e) {
    INFO("got JsonRpcError. code %d, message '%s', data: '%s', method: %s, id: %s, params: '%s'",
        e.code, e.message.c_str(), AmArg::print(e.data).c_str(),
        method.c_str(), isArgCStr(id) ? id.asCStr() : int2str(id.asInt()).c_str(),
        AmArg::print(params).c_str());
    rpc_res["error"] = AmArg(); 
    rpc_res["error"]["code"] = e.code;
    rpc_res["error"]["message"] = e.message;
    rpc_res["error"]["data"] = e.data;
    // todo: notification!
    rpc_res["id"] = id;
    rpc_res["jsonrpc"] = "2.0";
    rpc_res.erase("result");
    return false;
}
    return false;
}

#if 0
void JsonRpcServer::runCoreMethod(const string& method, const AmArg& params, AmArg& res) {
  if (method == "_list") {
    AmPlugIn::instance()->listFactories4Di(res);
  } else if (method == "calls") {
    res[0] = (int)AmSession::getSessionNum();
  } else if (method == "set_loglevel") {
    assertArgArray(params);
    assertArgInt(params[0]);
    log_level = params[0].asInt();
    DBG("set log_level to %d", log_level);
  } else if (method == "get_loglevel") {
    res[0] = log_level;
    DBG("get_log_level returns %d", log_level);
  } else {
    throw JsonRpcError(-32601, "Method not found",
		       "function unknown in core");
  }
}
#endif
