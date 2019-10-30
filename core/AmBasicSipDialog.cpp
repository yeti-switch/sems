#include "AmBasicSipDialog.h"

#include "AmSipHeaders.h"
#include "SipCtrlInterface.h"
#include "AmUtils.h"
#include "AmSession.h"

#include "sip/parse_common.h"
#include "sip/parse_route.h"
#include "sip/parse_uri.h"
#include "sip/parse_via.h"
#include "sip/parse_next_hop.h"
#include "sip/msg_logger.h"
#include "sip/sip_parser.h"

static const char *hdrs2remove[] = {
    SIP_HDR_USER_AGENT,
    SIP_HDR_SERVER,
    NULL,
};

static AddressType str2addrtype(const std::string &s)
{
    if(s.find(":") != std::string::npos) {
        return AT_V6;
    } else if(s.find(".") != std::string::npos) {
        return AT_V4;
    }
    return AT_NONE;
}

static SIP_info::SIP_type str2transport(cstring &s)
{
#define cmp_cond(trsp) 0==strncasecmp(s.s,trsp.s,trsp.len <= s.len ? trsp.len : s.len)
    static cstring udp("udp");
    static cstring tcp("tcp");
    static cstring tls("tls");
    DBG("str2transport(cstring &s [%.*s])",s.len,s.s);
    if(cmp_cond(udp)) return SIP_info::UDP;
    else if(cmp_cond(tcp)) return SIP_info::TCP;
    else if(cmp_cond(tls)) return SIP_info::TLS;
    return SIP_info::UNDEFINED;
#undef cmp_cond
}

const char* AmBasicSipDialog::status2str[AmBasicSipDialog::__max_Status] = {
  "Disconnected",
  "Trying",
  "Proceeding",
  "Cancelling",
  "Early",
  "Connected",
  "Disconnecting"
};

AmBasicSipDialog::AmBasicSipDialog(AmBasicSipEventHandler* h)
  : status(Disconnected),
    cseq(10),r_cseq_i(false),hdl(h),
	logger(NULL),sensor(NULL),
    outbound_proxy(AmConfig.outbound_proxy),
    force_outbound_proxy(AmConfig.force_outbound_proxy),
    next_hop(AmConfig.next_hop),
    next_hop_1st_req(AmConfig.next_hop_1st_req),
    patch_ruri_next_hop(false),
    next_hop_fixed(false),
    outbound_interface(-1),
    outbound_proto_id(-1),
    outbound_address_type(AT_NONE),
    resolve_priority(IPv4_only),
    nat_handling(AmConfig.sip_nat_handling),
    usages(0)
{
  //assert(h);
}

AmBasicSipDialog::~AmBasicSipDialog()
{
  termUasTrans();
  termUacTrans();
  if (logger) dec_ref(logger);
  if (sensor) dec_ref(sensor);
  dump();
}

AmSipRequest* AmBasicSipDialog::getUACTrans(unsigned int t_cseq)
{
  TransMap::iterator it = uac_trans.find(t_cseq);
  if(it == uac_trans.end())
    return NULL;

  return &(it->second);
}

AmSipRequest* AmBasicSipDialog::getUASTrans(unsigned int t_cseq)
{
  TransMap::iterator it = uas_trans.find(t_cseq);
  if(it == uas_trans.end())
    return NULL;

  return &(it->second);
}

string AmBasicSipDialog::getUACTransMethod(unsigned int t_cseq)
{
  AmSipRequest* req = getUACTrans(t_cseq);
  if(req != NULL)
    return req->method;

  return string();
}

bool AmBasicSipDialog::getUACTransPending()
{
  return !uac_trans.empty();
}

void AmBasicSipDialog::setStatus(Status new_status)
{
  DBG("setting SIP dialog status: %s->%s\n",
      getStatusStr(), getStatusStr(new_status));

  status = new_status;
}

const char* AmBasicSipDialog::getStatusStr(AmBasicSipDialog::Status st)
{
  if((st < 0) || (st >= __max_Status))
    return "Invalid";
  else
    return status2str[st];
}

const char* AmBasicSipDialog::getStatusStr()
{
  return getStatusStr(status);
}

string AmBasicSipDialog::getContactHdr()
{
  string contact_hdr = SIP_HDR_COLSP(SIP_HDR_CONTACT) "<";
  contact_hdr += getContactUri() + ">" CRLF;
  return contact_hdr;
}

string AmBasicSipDialog::getContactUri()
{
  string contact_uri = "sip:";
  if(!scheme.empty()) {
      contact_uri = scheme;
      contact_uri += ":";
  }
  if(!ext_local_tag.empty()) {
    contact_uri += local_tag + "@";
  }

  int oif = getOutboundIf();
  int oproto  = getOutboundProtoId();
  assert(oif >= 0);
  assert(oif < (int)AmConfig.sip_ifs.size());
  assert(oproto < (int)AmConfig.sip_ifs[oif].proto_info.size());

  const auto pi = AmConfig.sip_ifs[oif].proto_info[oproto];
  contact_uri += pi->getIP();
  contact_uri += ":" + int2str(pi->local_port);

  if(!contact_params.empty()) {
    contact_uri += ";" + contact_params;
  }
  return contact_uri;
}

string AmBasicSipDialog::getRoute()
{
  string res;

  if(!outbound_proxy.empty() && (force_outbound_proxy || remote_tag.empty())){
    res += "<" + outbound_proxy + ";lr>";

    if(!route.empty()) {
      res += ",";
    }
  }

  res += route;

  if(!res.empty()) {
    res = SIP_HDR_COLSP(SIP_HDR_ROUTE) + res + CRLF;
  }

  return res;
}

void AmBasicSipDialog::setOutboundInterface(int interface_id) {
  DBG("setting outbound interface to %i\n",  interface_id);
  outbound_interface = interface_id;
}

void AmBasicSipDialog::setOutboundAddrType(AddressType type_id)
{
  DBG("setting outbound address type to %i\n",  type_id);
  outbound_address_type = type_id;
}

void AmBasicSipDialog::setOutboundProtoId(int proto_id) {
  DBG("setting outbound proto id to %i\n",  proto_id);
  outbound_proto_id = proto_id;
}

/**
 * Computes, set and return the outbound interface
 * based on remote_uri, next_hop_ip, outbound_proxy, route.
 */
int AmBasicSipDialog::getOutboundIf()
{
    if (outbound_interface >= 0)
        return outbound_interface;

    // Destination priority:
    // 1. next_hop
    // 2. outbound_proxy (if 1st req or force_outbound_proxy)
    // 3. first route
    // 4. remote URI

    string dest_uri;
    string local_ip;
    sip_uri d_uri;
    sip_header fr;
    std::multimap<string,unsigned short>::iterator if_it;
    SIP_info::SIP_type transport_type = SIP_info::UDP;
    AddressType address_type;
    int proto_id;
    list<sip_destination> ip_list;

    if(!next_hop.empty() &&
       !parse_next_hop(stl2cstr(next_hop),ip_list) &&
       !ip_list.empty())
    {
        d_uri.host = ip_list.front().host;
        transport_type = str2transport(ip_list.front().trsp);
    } else if(!outbound_proxy.empty() &&
              (remote_tag.empty() || force_outbound_proxy))
    {
        dest_uri = outbound_proxy;
    } else if(!route.empty()) {
        // parse first route
        fr.value = stl2cstr(route);
        sip_uri* route_uri = get_first_route_uri(&fr);
        if(!route_uri) {
            DBG("Could not parse route (local_tag='%s';route='%s')",
                  local_tag.c_str(),route.c_str());
            goto error;
        }
        d_uri.host = route_uri->host;
        if(route_uri->trsp)
            transport_type = str2transport(route_uri->trsp->value);
    } else {
        dest_uri = remote_uri;
    }

    if(dest_uri.empty() && !d_uri.host.s) {
        ERROR("No destination found (local_tag='%s')",local_tag.c_str());
        goto error;
    }

    if(!dest_uri.empty()) {
        if(parse_uri(&d_uri,dest_uri.c_str(),static_cast<int>(dest_uri.length()),true) < 0) {
            DBG("Could not parse destination URI (local_tag='%s';dest_uri='%s')",
                  local_tag.c_str(),dest_uri.c_str());
            goto error;
        }
        //dest_ip = c2stlstr(d_uri.host);
        if(d_uri.trsp)
            transport_type = str2transport(d_uri.trsp->value);
    }

    if(get_local_addr_for_dest(d_uri,local_ip, static_cast<dns_priority>(resolve_priority)) < 0) {
        DBG("No local address for dest '%.*s' (local_tag='%s')",
              d_uri.host.len, d_uri.host.s,
              local_tag.c_str());
        goto error;
    }

    if_it = AmConfig.local_sip_ip2if.find(local_ip);
    if(if_it == AmConfig.local_sip_ip2if.end()) {
        ERROR("Could not find a local interface for resolved local IP (local_tag='%s';local_ip='%s')",
              local_tag.c_str(), local_ip.c_str());
        goto error;
    }

    address_type = str2addrtype(local_ip);
    if(!address_type) {
        address_type = AT_V4;
        ERROR("Could not resolve address type in interface for resolved local IP (local_tag='%s'; local_ip='%s'). Use default: IPv4",
              local_tag.c_str(), local_ip.c_str());
    }

    proto_id = AmConfig.sip_ifs[if_it->second].findProto(address_type, transport_type);
    if(proto_id < 0) {
        ERROR("Could not find a transport in interface for resolved local IP (local_tag='%s'; local_ip='%s').",
              local_tag.c_str(), local_ip.c_str());
        goto error;
    }

    setOutboundInterface(if_it->second);
    setOutboundAddrType(address_type);
    setOutboundProtoId(proto_id);

    return if_it->second;

  error:
    DBG("Error while computing outbound interface: default interface will be used instead.");
    setOutboundInterface(0);
    setOutboundAddrType(AT_V4);
    setOutboundProtoId(0);
    return 0;
}

AddressType AmBasicSipDialog::getOutboundAddrType()
{
  int out_if = getOutboundIf();
  int out_proto_id = getOutboundProtoId();

  if (outbound_address_type > 0)
    return outbound_address_type;

  if(out_if < 0 || out_proto_id < 0) {
      return AT_NONE;
  }

  std::string local_ip = AmConfig.sip_ifs[out_if].proto_info[out_proto_id]->getIP();
  AddressType addrType = str2addrtype(local_ip);
  if(addrType) {
      setOutboundAddrType(addrType);
  } else {
      ERROR("Could not parse local URI (local_tag='%s';local_ip='%s')",
	    local_tag.c_str(),local_ip.c_str());
  }

  return outbound_address_type;
}

int AmBasicSipDialog::getOutboundProtoId()
{
    if(outbound_proto_id < 0) {
        getOutboundIf();
    }
    return outbound_proto_id;
}

void AmBasicSipDialog::resetOutboundIf()
{
  setOutboundInterface(-1);
  setOutboundProtoId(-1);
  setOutboundAddrType(AT_NONE);
}

void AmBasicSipDialog::setResolvePriority(int priority)
{
    resolve_priority = priority;
}

int AmBasicSipDialog::getResolvePriority()
{
    return resolve_priority;
}

/**
 * Update dialog status from UAC Request that we send.
 */
void AmBasicSipDialog::initFromLocalRequest(const AmSipRequest& req)
{
  setRemoteUri(req.r_uri);

  scheme       = req.scheme;
  user         = req.user;
  domain       = req.domain;

  setCallid(      req.callid   );
  setLocalTag(    req.from_tag );
  setLocalUri(    req.from_uri );
  setRemoteParty( req.to       );
  setLocalParty(  req.from     );
}

bool AmBasicSipDialog::onRxReqSanity(const AmSipRequest& req)
{
  // Sanity checks
  if(!remote_tag.empty() && !req.from_tag.empty() &&
     (req.from_tag != remote_tag)){
    DBG("remote_tag = '%s'; req.from_tag = '%s'\n",
	remote_tag.c_str(), req.from_tag.c_str());
	reply_error(req, 481, SIP_REPLY_NOT_EXIST,string(),logger);
    return false;
  }

  if (r_cseq_i && req.cseq <= r_cseq){

    if (req.method == SIP_METH_NOTIFY) {
      if (!AmConfig.ignore_notify_lower_cseq) {
	// clever trick to not break subscription dialog usage
	// for implementations which follow 3265 instead of 5057
	string hdrs = SIP_HDR_COLSP(SIP_HDR_RETRY_AFTER)  "0"  CRLF;

	INFO("remote cseq lower than previous ones - refusing request. "
		 "method = %s, call-id = '%s'\n",
		 req.method.c_str(),callid.c_str());
	// see 12.2.2
	reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR, hdrs, logger);
	return false;
      }
    }
    else {
	  INFO("remote cseq lower than previous ones - refusing request. "
		   "method = %s, call-id = '%s'\n",
		   req.method.c_str(),callid.c_str());
      // see 12.2.2
      reply_error(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR, string(),logger);
      return false;
    }
  }

  r_cseq = req.cseq;
  r_cseq_i = true;

  return true;
}

void AmBasicSipDialog::onRxRequest(const AmSipRequest& req)
{
  DBG("AmBasicSipDialog::onRxRequest(req = %s)\n", req.method.c_str());

  if(req.method != SIP_METH_ACK) {
    // log only non-initial received requests, the initial one is already logged
    // or will be logged at application level (problem with SBCSimpleRelay)
	if (!callid.empty()) {
		req.log(logger,sensor);
	}
  }

  if(!onRxReqSanity(req))
    return;

  uas_trans[req.cseq] = req;

  // target refresh requests
  if (req.from_uri.length() &&
      (remote_uri.empty() ||
       (req.method == SIP_METH_INVITE ||
	req.method == SIP_METH_UPDATE ||
	req.method == SIP_METH_SUBSCRIBE ||
	req.method == SIP_METH_NOTIFY))) {

    // refresh the target
    if (remote_uri != req.from_uri) {
      setRemoteUri(req.from_uri);
      if(nat_handling && req.first_hop) {
	string nh = req.remote_ip + ":"
	  + int2str(req.remote_port)
	  + "/" + req.trsp;
	setNextHop(nh);
	setNextHop1stReq(false);
      }
    }

    string ua = getHeader(req.hdrs,"User-Agent");
    setRemoteUA(ua);
  }

  // Dlg not yet initialized?
  if(callid.empty()){

    scheme       = req.scheme;
    user         = req.user;
    domain       = req.domain;

    setCallid(      req.callid   );
    setRemoteTag(   req.from_tag );
    setLocalUri(    req.r_uri    );
    setRemoteParty( req.from     );
    setLocalParty(  req.to       );
    setRouteSet(    req.route    );
    set1stBranch(   req.via_branch );
    setOutboundInterface( req.local_if );
    setOutboundAddrType( str2addrtype(req.local_ip) );
    setOutboundProtoId(req.proto_idx);
  }

  if(onRxReqStatus(req)) {
    if(hdl) hdl->onSipRequest(req);
  } else {
    if(hdl) hdl->onFailure();
  }
}

bool AmBasicSipDialog::onRxReplyStatus(const AmSipReply& reply)
{
  /**
   * Error code list from RFC 5057:
   * those error codes terminate the dialog
   *
   * Note: 408, 480 should only terminate
   *       the usage according to RFC 5057.
   */
  switch(reply.code){
  case 404:
  case 408:
  case 410:
  case 416:
  case 480:
  case 482:
  case 483:
  case 484:
  case 485:
  case 502:
  case 604:
    if(hdl) hdl->onRemoteDisappeared(reply);
    break;
  }

  return true;
}

void AmBasicSipDialog::termUasTrans()
{
  while(!uas_trans.empty()) {

    TransMap::iterator it = uas_trans.begin();
    int req_cseq = it->first;
    const AmSipRequest& req = it->second;
    DBG("terminating UAS transaction (%u %s)",req.cseq,req.cseq_method.c_str());

    reply(req,481,SIP_REPLY_NOT_EXIST);

    it = uas_trans.find(req_cseq);
    if(it != uas_trans.end())
      uas_trans.erase(it);
  }
}

void AmBasicSipDialog::termUacTrans()
{
  while(!uac_trans.empty()) {
    TransMap::iterator it = uac_trans.begin();
    trans_ticket& tt = it->second.tt;

    tt.lock_bucket();
    tt.remove_trans();
    tt.unlock_bucket();

    uac_trans.erase(it);
  }
}

void AmBasicSipDialog::dropTransactions() {
  termUacTrans();
  uas_trans.clear();
}

bool AmBasicSipDialog::onRxReplySanity(const AmSipReply& reply)
{
  if(ext_local_tag.empty()) {
    if(reply.from_tag != local_tag) {
      ERROR("received reply with wrong From-tag ('%s' vs. '%s')",
	    reply.from_tag.c_str(), local_tag.c_str());
      throw string("reply has wrong from-tag");
      //return;
    }
  }
  else if(reply.from_tag != ext_local_tag) {
    ERROR("received reply with wrong From-tag ('%s' vs. '%s')",
	  reply.from_tag.c_str(), ext_local_tag.c_str());
    throw string("reply has wrong from-tag");
    //return;
  }

  return true;
}

void AmBasicSipDialog::onRxReply(const AmSipReply& reply)
{
  if(!onRxReplySanity(reply)) {
    DBG("reply %d:%s for %s is dropped by onRxReplySanity",
        reply.code,reply.reason.c_str(),reply.cseq_method.c_str());
    return;
  }

  TransMap::iterator t_it = uac_trans.find(reply.cseq);
  if(t_it == uac_trans.end()){
    _LOG(reply.code < 200 ? L_DBG : L_ERR,
         "could not find any transaction matching reply: %s\n",
         ((AmSipReply)reply).print().c_str());
    return;
  }

  DBG("onRxReply(rep = %u %s): transaction found!\n",
      reply.code, reply.reason.c_str());

  //!HACK: replace transaction ticket in uac_trans map if matched wrong
  t_it->second.tt.assign_if_differs(reply.tt);

  updateDialogTarget(reply);

  Status saved_status = status;
  AmSipRequest orig_req(t_it->second);

  if(onRxReplyStatus(reply) && hdl) {
    hdl->onSipReply(orig_req,reply,saved_status);
  }

  if((reply.code >= 200) && // final reply
     // but not for 2xx INV reply (wait for 200 ACK)
     ((reply.cseq_method != SIP_METH_INVITE) ||
      (reply.code >= 300))) {

    uac_trans.erase(reply.cseq);
    if (hdl) hdl->onTransFinished();
  }
}

void AmBasicSipDialog::updateDialogTarget(const AmSipReply& reply)
{
  if( (reply.code > 100) && (reply.code < 300) &&
      !reply.to_uri.empty() &&
      !reply.to_tag.empty() &&
      (remote_uri.empty() ||
       (reply.cseq_method.length()==6 &&
	((reply.cseq_method == SIP_METH_INVITE) ||
	 (reply.cseq_method == SIP_METH_UPDATE) ||
	 (reply.cseq_method == SIP_METH_NOTIFY))) ||
       (reply.cseq_method == SIP_METH_SUBSCRIBE)) ) {

    setRemoteUri(reply.to_uri);
    if(!getNextHop().empty()) {
      string nh = reply.remote_ip
	+ ":" + int2str(reply.remote_port)
	+ "/" + reply.trsp;
      setNextHop(nh);
    }

    string ua = getHeader(reply.hdrs,"Server");
    setRemoteUA(ua);
  }
}

void AmBasicSipDialog::setRemoteTag(const string& new_rt)
{
  if(new_rt != remote_tag){
    remote_tag = new_rt;
  }
}

int AmBasicSipDialog::onTxRequest(AmSipRequest& req, int& flags)
{
  if(hdl) hdl->onSendRequest(req,flags);

  return 0;
}

int AmBasicSipDialog::onTxReply(const AmSipRequest& req,
				AmSipReply& reply, int& flags)
{
  if(hdl) hdl->onSendReply(req,reply,flags);

  return 0;
}

void AmBasicSipDialog::onReplyTxed(const AmSipRequest& req,
				   const AmSipReply& reply)
{
  if(hdl) hdl->onReplySent(req, reply);

  /**
   * Error code list from RFC 5057:
   * those error codes terminate the dialog
   *
   * Note: 408, 480 should only terminate
   *       the usage according to RFC 5057.
   */
  switch(reply.code){
  case 404:
  case 408:
  case 410:
  case 416:
  case 480:
  case 482:
  case 483:
  case 484:
  case 485:
  case 502:
  case 604:
    if(hdl) hdl->onLocalTerminate(reply);
    break;
  }

  if ((reply.code >= 200) &&
      (reply.cseq_method != SIP_METH_CANCEL)) {

    uas_trans.erase(reply.cseq);
    if (hdl) hdl->onTransFinished();
  }
}

void AmBasicSipDialog::onRequestTxed(const AmSipRequest& req)
{
  if(hdl) hdl->onRequestSent(req);

  if(req.method != SIP_METH_ACK) {
    uac_trans[req.cseq] = req;
    cseq++;
  }
  else {
    uac_trans.erase(req.cseq);
    if (hdl) hdl->onTransFinished();
  }
}

int AmBasicSipDialog::reply(const AmSipRequest& req,
			    unsigned int  code,
			    const string& reason,
			    const AmMimeBody* body,
			    const string& hdrs,
			    int flags)
{
  TransMap::const_iterator t_it = uas_trans.find(req.cseq);
  if(t_it == uas_trans.end()){
    DBG("could not find any transaction matching request "
        "cseq=%i; reply code=%i; callid=%s; local_tag=%s; "
        "remote_tag=%s",
        req.cseq,code,callid.c_str(),
        local_tag.c_str(),remote_tag.c_str());
    return -1;
  }
  //DBG("reply: transaction found!\n");

  AmSipReply reply;

  reply.code = code;
  reply.reason = reason;
  reply.tt = req.tt;
  if((code > 100) && !(flags & SIP_FLAGS_NOTAG))
    reply.to_tag = ext_local_tag.empty() ? local_tag : ext_local_tag;
  reply.hdrs = hdrs;
  reply.cseq = req.cseq;
  reply.cseq_method = req.method;

  if(body != NULL)
    reply.body = *body;

  if(onTxReply(req,reply,flags)){
    DBG("onTxReply failed\n");
    return -1;
  }

  inplaceHeadersErase(reply.hdrs,hdrs2remove);
  if (AmConfig.signature.length()){
    reply.hdrs += SIP_HDR_COLSP(SIP_HDR_SERVER) + AmConfig.signature + CRLF;
  }

  if ((code > 100 && code < 300) && !(flags & SIP_FLAGS_NOCONTACT)) {
    /* if 300<=code<400, explicit contact setting should be done */
    reply.contact = getContactHdr();
  }

  int ret = SipCtrlInterface::send(reply,local_tag,logger,sensor);
  if(ret){
    ERROR("Could not send reply: code=%i; reason='%s'; method=%s;"
	  " call-id=%s; cseq=%i\n",
	  reply.code,reply.reason.c_str(),reply.cseq_method.c_str(),
	  callid.c_str(),reply.cseq);

    return ret;
  }
  else {
    onReplyTxed(req,reply);
  }

  return ret;
}


/* static */
int AmBasicSipDialog::reply_error(const AmSipRequest& req, unsigned int code,
				  const string& reason, const string& hdrs,
				  msg_logger* logger, msg_sensor *sensor)
{
  AmSipReply reply;

  reply.code = code;
  reply.reason = reason;
  reply.tt = req.tt;
  reply.hdrs = hdrs;
  reply.to_tag = AmSession::getNewId();

  inplaceHeadersErase(reply.hdrs,hdrs2remove);
  if (AmConfig.signature.length())
    reply.hdrs += SIP_HDR_COLSP(SIP_HDR_SERVER) + AmConfig.signature + CRLF;

  // add transcoder statistics into reply headers
  //addTranscoderStats(reply.hdrs);

  int ret = SipCtrlInterface::send(reply,string(""),logger,sensor);
  if(ret){
    ERROR("Could not send reply: code=%i; reason='%s';"
	  " method=%s; call-id=%s; cseq=%i\n",
	  reply.code,reply.reason.c_str(),
	  req.method.c_str(),req.callid.c_str(),req.cseq);
  }

  return ret;
}

int AmBasicSipDialog::sendRequest(const string& method,
				  const AmMimeBody* body,
				  const string& hdrs,
				  int flags,
				  sip_timers_override *timers_override,
				  sip_target_set* target_set_override,
				  unsigned int redirects_allowed)
{
    auto_ptr<sip_target_set> targets(
        target_set_override ? target_set_override: new sip_target_set((dns_priority)getResolvePriority()));

  AmSipRequest req;

  req.method = method;
  req.scheme = scheme;
  req.r_uri = remote_uri;

  req.from = SIP_HDR_COLSP(SIP_HDR_FROM) + local_party;
  if(!ext_local_tag.empty())
    req.from += ";tag=" + ext_local_tag;
  else if(!local_tag.empty())
    req.from += ";tag=" + local_tag;

  req.to = SIP_HDR_COLSP(SIP_HDR_TO) + remote_party;
  if(!remote_tag.empty())
    req.to += ";tag=" + remote_tag;

  req.cseq = cseq;
  req.callid = callid;

  req.hdrs = hdrs;

  req.route = getRoute();

  if(body != NULL) {
    req.body = *body;
  }

  if(onTxRequest(req,flags) < 0)
    return -1;

  if (!(flags & SIP_FLAGS_NOCONTACT)) {
    req.contact = getContactHdr();
  }

  inplaceHeadersErase(req.hdrs,hdrs2remove);
  if (AmConfig.signature.length()){
    req.hdrs += SIP_HDR_COLSP(SIP_HDR_USER_AGENT) + AmConfig.signature + CRLF;
  }

  int send_flags = 0;
  if(patch_ruri_next_hop && remote_tag.empty()) {
    send_flags |= TR_FLAG_NEXT_HOP_RURI;
  }

  if((flags & SIP_FLAGS_NOBL) ||
     !remote_tag.empty()) {
    send_flags |= TR_FLAG_DISABLE_BL;
  }

  int res = SipCtrlInterface::send(req, local_tag,
				   remote_tag.empty() || !next_hop_1st_req ?
				   next_hop : "",
				   outbound_interface,
				   send_flags, targets.release(),
                   logger,sensor,timers_override,
				   redirects_allowed);
  if(res) {
    DBG("Could not send request: method=%s; ruri=%s; call-id=%s; cseq=%i\n",
      req.method.c_str(),
      req.r_uri.c_str(),
      req.callid.c_str(),
      req.cseq);
    return res;
  }

  onRequestTxed(req);
  return 0;
}

void AmBasicSipDialog::dump()
{
  DBG("callid = %s\n",callid.c_str());
  DBG("local_tag = %s\n",local_tag.c_str());
  DBG("uac_trans.size() = %zu\n",uac_trans.size());
  if(uac_trans.size()){
    for(TransMap::iterator it = uac_trans.begin();
	it != uac_trans.end(); it++){

      DBG("    cseq = %i; method = %s\n",it->first,it->second.method.c_str());
    }
  }
  DBG("uas_trans.size() = %zu\n",uas_trans.size());
  if(uas_trans.size()){
    for(TransMap::iterator it = uas_trans.begin();
	it != uas_trans.end(); it++){

      DBG("    cseq = %i; method = %s\n",it->first,it->second.method.c_str());
    }
  }
}

void AmBasicSipDialog::info(AmArg &s)
{

}

void AmBasicSipDialog::setMsgLogger(msg_logger* logger)
{
  if(this->logger) {
    dec_ref(this->logger);
  }

  if(logger){
    inc_ref(logger);
  }

  this->logger = logger;
}

void AmBasicSipDialog::setMsgSensor(msg_sensor* _sensor)
{
	DBG("AmBasicSipDialog[%p]: change sensor to %p",this,_sensor);
	if(sensor) dec_ref(sensor);
	sensor = _sensor;
	if(sensor) inc_ref(sensor);
}
