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
tls_server_settings JsonRPCServerModule::server_settings;
tls_client_settings JsonRPCServerModule::client_settings;

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
  : AmDynInvokeFactory(mod_name), AmConfigFactory(mod_name), use_tls(false)
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

    static const char opt_tls_protocols[] = "protocols";
    static const char opt_tls_certificate[] = "certificate";
    static const char opt_tls_certificate_key[] = "certificate_key";
    static const char opt_tls_verify_certchain[] = "verify_certificate_chain";
    static const char opt_tls_verify_certcn[] = "verify_certificate_cn";
    static const char opt_tls_ca_list[] = "ca_list";
    static const char opt_tls_verify_client_cert[] = "verify_client_certificate";
    static const char opt_tls_require_client_cert[] = "require_client_certificate";
    static const char opt_tls_ciphers[] = "ciphers";
    static const char opt_tls_macs[] = "macs";
    static const char opt_tls_dhparam[] = "dhparam";

    static const char sec_listen[] = "listen";
    static const char sec_acl[] = "acl";
    static const char sec_tls[] = "tls";
    static const char sec_server_tls[] = "server";
    static const char sec_client_tls[] = "client";

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

    static cfg_opt_t tls_client[] =
    {
        CFG_STR_LIST(opt_tls_protocols, 0, CFGF_NODEFAULT),
        CFG_STR(opt_tls_certificate, "", CFGF_NONE),
        CFG_STR(opt_tls_certificate_key, "", CFGF_NONE),
        CFG_BOOL(opt_tls_verify_certchain, cfg_true, CFGF_NONE),
        CFG_BOOL(opt_tls_verify_certcn, cfg_true, CFGF_NONE),
        CFG_STR_LIST(opt_tls_ca_list, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t tls_server[] =
    {
        CFG_STR_LIST(opt_tls_protocols, 0, CFGF_NODEFAULT),
        CFG_STR(opt_tls_certificate, "", CFGF_NONE),
        CFG_STR(opt_tls_certificate_key, "", CFGF_NONE),
        CFG_BOOL(opt_tls_verify_client_cert, cfg_true, CFGF_NONE),
        CFG_BOOL(opt_tls_require_client_cert, cfg_true, CFGF_NONE),
        CFG_STR_LIST(opt_tls_ciphers, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(opt_tls_macs, 0, CFGF_NODEFAULT),
        CFG_STR(opt_tls_dhparam, "", CFGF_NONE),
        CFG_STR_LIST(opt_tls_ca_list, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t tls_sec[] = {
        CFG_SEC(sec_server_tls, tls_server, CFGF_NONE),
        CFG_SEC(sec_client_tls, tls_client, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opt[] = {
        CFG_SEC(sec_listen,listen_sec, CFGF_NONE),
        CFG_SEC(sec_acl,acl_sec, CFGF_NODEFAULT),
        CFG_SEC(sec_tls,tls_sec, CFGF_NODEFAULT),
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

    if(cfg_size(cfg, sec_tls)) {
        use_tls = true;
        cfg_t* tls = cfg_getsec(cfg, sec_tls);
        cfg_t* server = cfg_getsec(tls, sec_server_tls);
        for(unsigned int i = 0; i < cfg_size(server, opt_tls_protocols); i++) {
            std::string protocol = cfg_getnstr(server, opt_tls_protocols, i);
            server_settings.protocols.push_back(tls_settings::protocolFromStr(protocol));
        }
        server_settings.certificate_path = cfg_getstr(server, opt_tls_certificate);
        server_settings.certificate_key_path = cfg_getstr(server, opt_tls_certificate_key);
        for(unsigned int i = 0; i < cfg_size(server, opt_tls_ciphers); i++) {
            std::string cipher = cfg_getnstr(server, opt_tls_ciphers, i);
            server_settings.cipher_list.push_back(cipher);
        }
        for(unsigned int i = 0; i < cfg_size(server, opt_tls_macs); i++) {
            std::string mac = cfg_getnstr(server, opt_tls_macs, i);
            server_settings.macs_list.push_back(mac);
        }
        server_settings.verify_client_certificate = cfg_getbool(server, opt_tls_verify_client_cert);
        server_settings.require_client_certificate = cfg_getbool(server, opt_tls_require_client_cert);
        server_settings.dhparam = cfg_getstr(server, opt_tls_dhparam);
        for(unsigned int i = 0; i < cfg_size(server, opt_tls_ca_list); i++) {
            std::string ca = cfg_getnstr(server, opt_tls_ca_list, i);
            server_settings.ca_path_list.push_back(ca);
        }
        if(server_settings.verify_client_certificate && !server_settings.require_client_certificate) {
            ERROR("incorrect server tls configuration: verify client certificate cannot be set, if clients certificate is not required");
            return -1;
        }
        if(server_settings.certificate_path.empty() || server_settings.certificate_key_path.empty()) {
            ERROR("incorrect server tls configuration: client certificate and key must be set");
            return -1;
        }

        cfg_t* client = cfg_getsec(tls, sec_client_tls);
        for(unsigned int i = 0; i < cfg_size(client, opt_tls_protocols); i++) {
            std::string protocol = cfg_getnstr(client, opt_tls_protocols, i);
            client_settings.protocols.push_back(tls_settings::protocolFromStr(protocol));
        }
        client_settings.certificate_path = cfg_getstr(client, opt_tls_certificate);
        client_settings.certificate_key_path = cfg_getstr(client, opt_tls_certificate_key);
        client_settings.verify_certificate_chain = cfg_getbool(client, opt_tls_verify_certchain);
        client_settings.verify_certificate_cn = cfg_getbool(client, opt_tls_verify_certcn);
        for(unsigned int i = 0; i < cfg_size(client, opt_tls_ca_list); i++) {
            std::string ca = cfg_getnstr(client, opt_tls_ca_list, i);
            client_settings.ca_path_list.push_back(ca);
        }

        if(!client_settings.checkCertificateAndKey("jsonrpc","","client") ||
        !server_settings.checkCertificateAndKey("jsonrpc","","server")) {
                return -1;
        }
        client_settings.load_certificates();
        server_settings.load_certificates();
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
    args.assertArrayFmt("sssiisis");   // evq_link, notificationReceiver, requestReceiver, 
                                      // conn_type(i), flags(i), host, port (i), method, [params]
    if (args.size() > 8)  {
      if (!isArgArray(args.get(8)) && !isArgStruct(args.get(8))) {
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
  if (args.size()>8)
    params = args.get(8);

  AmArg u_none_params;
  AmArg& udata = u_none_params;
  if (args.size()>9)
    udata = args.get(9);

  JsonRPCServerLoop::execRpc(// evq_link, notification_link, request_link
			     args.get(0).asCStr(), args.get(1).asCStr(),
			     args.get(2).asCStr(),
			     // conn_type
			     args.get(3).asInt(), 
			     // flags
			     args.get(4).asInt(), 
			     // host, port, method
			     args.get(5).asCStr(), 
			     args.get(6).asInt(), args.get(7).asCStr(), 
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
