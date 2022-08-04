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

#include "JsonRPC.h"
#include "JsonRPCServer.h"
#include <AmLcConfig.h>

#include <netinet/tcp.h>

JsonRPCServerModule* JsonRPCServerModule::_instance = NULL;

string JsonRPCServerModule::host = DEFAULT_JSONRPC_SERVER_HOST;
int JsonRPCServerModule::port = DEFAULT_JSONRPC_SERVER_PORT;
int JsonRPCServerModule::threads = DEFAULT_JSONRPC_SERVER_THREADS;
trsp_acl JsonRPCServerModule::acl;
string JsonRPCServerModule::tcp_md5_password;

EXPORT_PLUGIN_CLASS_FACTORY(JsonRPCServerModule)
EXPORT_PLUGIN_CONF_FACTORY(JsonRPCServerModule)
JsonRPCServerModule* JsonRPCServerModule::instance()
{
  if(_instance == NULL){
    _instance = new JsonRPCServerModule(MOD_NAME);
  }
  return _instance;
}

JsonRPCServerModule::JsonRPCServerModule(const string& mod_name) 
  : AmDynInvokeFactory(mod_name), AmConfigFactory(mod_name)
{
}

JsonRPCServerModule::~JsonRPCServerModule() {
    JsonRPCServerLoop::instance()->stop(true);
    JsonRPCServerLoop::dispose();
}

int JsonRPCServerModule::onLoad() {
  return instance()->load();
}


int JsonRPCServerModule::configure(const std::string & config)
{
    static const char opt_address[] = "address";
    static const char opt_port[] = "port";
    static const char opt_whitelist[] = "whitelist";
    static const char opt_method[] = "method";
    static const char opt_server_threads[] = "server_threads";
    static const char opt_tcp_md5_password[] = "tcp_md5_password";
    static const char sec_listen[] = "listen";
    static const char sec_acl[] = "acl";

    static cfg_opt_t acl_sec[]
    {
        CFG_STR_LIST(opt_whitelist, 0, CFGF_NODEFAULT),
        CFG_STR(opt_method, "", CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t listen_sec[] = {
        CFG_STR(opt_address, DEFAULT_JSONRPC_SERVER_HOST, CFGF_NONE),
        CFG_INT(opt_port, DEFAULT_JSONRPC_SERVER_PORT, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opt[] = {
        CFG_SEC(sec_listen,listen_sec, CFGF_NONE),
        CFG_SEC(sec_acl,acl_sec, CFGF_NODEFAULT),
        CFG_INT(opt_server_threads, DEFAULT_JSONRPC_SERVER_THREADS, CFGF_NONE),
        CFG_STR(opt_tcp_md5_password, NULL, CFGF_NONE),
        CFG_END()
    };

    cfg_t *cfg = cfg_init(opt, CFGF_NONE);
    if(!cfg) return -1;
    switch(cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error",MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing",MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    cfg_t *listen = cfg_getsec(cfg, sec_listen);
    host = cfg_getstr(listen, opt_address);
    port = cfg_getint(listen, opt_port);
    threads = cfg_getint(cfg, opt_server_threads);
    if(cfg_getstr(cfg,opt_tcp_md5_password)) {
        tcp_md5_password = cfg_getstr(cfg,opt_tcp_md5_password);
        if(tcp_md5_password.size() > TCP_MD5SIG_MAXKEYLEN) {
            ERROR("tcp_md5_password is too long (TCP_MD5SIG_MAXKEYLEN %u)", TCP_MD5SIG_MAXKEYLEN);
            return -1;
        }
    }
    if(cfg_size(cfg, sec_acl)) {
        cfg_t* cfg_acl = cfg_getsec(cfg, sec_acl);
        int networks = 0;
        for(unsigned int j = 0; j < cfg_size(cfg_acl, opt_whitelist); j++) {
            AmSubnet net;
            std::string host = cfg_getnstr(cfg_acl, opt_whitelist, j);
            if(!net.parse(host)) {
                return -1;
            }
            acl.add_network(net);
            networks++;
        }

        DBG("parsed %d networks",networks);

        std::string method = cfg_getstr(cfg_acl, opt_method);
        if(method == "drop"){
            acl.set_action(trsp_acl::Drop);
        } else if(method == "reject") {
            acl.set_action(trsp_acl::Reject);
        } else {
            ERROR("unknown acl method '%s'", method.c_str());
            return -1;
        }
    }

    cfg_free(cfg);
    return 0;
}

int JsonRPCServerModule::reconfigure(const std::string& config)
{
    JsonRPCServerLoop::instance()->stop(true);
    int ret = configure(config);
    if(ret) return ret;
    if(JsonRPCServerLoop::instance()->configure())
        return 1;
    JsonRPCServerLoop::instance()->start();
    return ret;
}

int JsonRPCServerModule::load() {
  DBG("using server listen address %s", host.c_str());
  DBG("using server port %d", port);
  DBG("using %d server threads", threads);
  if(tcp_md5_password.size()) {
    DBG("use tcp md5 password");
  }
  DBG("starting server loop thread");
  server_loop = JsonRPCServerLoop::instance();
  if(server_loop->configure())
      return 1;
  server_loop->start();
  
  return 0;
}

void JsonRPCServerModule::invoke(const string& method, 
				 const AmArg& args, AmArg& ret) {
  if (method == "execRpc"){

    // todo: add connection id
    args.assertArrayFmt("sssisis");   // evq_link, notificationReceiver, requestReceiver, 
                                      // flags(i), host, port (i), method, [params]
    if (args.size() > 7)  {
      if (!isArgArray(args.get(7)) && !isArgStruct(args.get(7))) {
	ERROR("internal error: params to JSON-RPC must be struct or array");
	throw AmArg::TypeMismatchException();
      }
    }
    execRpc(args, ret);
    // sendRequestList(args, ret);
  } else if (method == "sendMessage"){
    args.assertArrayFmt("sisss");          // conn_id, type, method, id, reply_sink, [params]
    if (args.size() > 5) {
      if (!isArgArray(args.get(5)) && !isArgStruct(args.get(5))) {
	ERROR("internal error: params to JSON-RPC must be struct or array");
	throw AmArg::TypeMismatchException();
      }
    }
    sendMessage(args, ret);
  } else if (method == "execServerFunction"){ 
    args.assertArrayFmt("ss");          // method, id, params
    JsonRpcServer::execRpc(string(), args.get(0).asCStr(), args.get(1).asCStr(), args.get(2), ret);
    // JsonRpcServer::execRpc(args, ret);
  } else if (method == "getServerPort"){
    ret.push(port);
  } else if(method == "_list"){ 
    ret.push(AmArg("execRpc"));
    ret.push(AmArg("sendMessage"));
    ret.push(AmArg("getServerPort"));
    ret.push(AmArg("execServerFunction"));
    ret.push(AmArg("setNotifySink"));
    ret.push(AmArg("setRequestSink"));
    // ret.push(AmArg("newConnection"));
    // ret.push(AmArg("sendRequest"));
    // ret.push(AmArg("sendRequestList"));
  }  else
    throw AmDynInvoke::NotImplemented(method);  
}

void JsonRPCServerModule::execRpc(const AmArg& args, AmArg& ret) {
  AmArg none_params;
  AmArg& params = none_params;
  if (args.size()>7)
    params = args.get(7);

  AmArg u_none_params;
  AmArg& udata = u_none_params;
  if (args.size()>8)
    udata = args.get(8);

  JsonRPCServerLoop::execRpc(// evq_link, notification_link, request_link
			     args.get(0).asCStr(), args.get(1).asCStr(),
			     args.get(2).asCStr(), 
			     // flags
			     args.get(3).asInt(), 
			     // host, port, method
			     args.get(4).asCStr(), 
			     args.get(5).asInt(), args.get(6).asCStr(), 
			     params, udata, ret);
}

void JsonRPCServerModule::sendMessage(const AmArg& args, AmArg& ret) {
  AmArg none_params;
  AmArg& params = none_params;
  if (args.size()>5)
    params = args.get(5);
  AmArg u_none_params;
  AmArg& udata = u_none_params;
  if (args.size()>6)
    udata = args.get(6);

  JsonRPCServerLoop::sendMessage(args.get(0).asCStr(), // conn_id, 
				 args.get(1).asInt(),  // type, (0 == reply)
				 args.get(2).asCStr(), // method,
				 args.get(3).asCStr(), // id
				 args.get(4).asCStr(), // reply_sink
				 params, udata, ret);
}
