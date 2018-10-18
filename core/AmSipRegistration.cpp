/*
 * Copyright (C) 2006 iptego GmbH
 * Copyright (C) 2011 Stefan Sayer
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

#include "AmSipRegistration.h"
#include "AmSession.h"
#include "AmUtils.h"
#include "AmSessionContainer.h"
#include "sip/parse_via.h"

AmSIPRegistration::AmSIPRegistration(const string& handle,
				     const SIPRegistrationInfo& info,
					 const string& sess_link,
					 RegShaper &shaper)
  : info(info),
    dlg(this),
    cred(info.domain, info.auth_user, info.pwd),
    active(false),
    reg_begin(0),
    reg_expires(0),
    remove(false),
    sess_link(sess_link),
    handle(handle),
    reg_send_begin(0),
    waiting_result(false),
    unregistering(false),
    postponed(false),
    seh(NULL),
    error_code(0),
    expires_interval(3600),
    force_expires_interval(false),
    shaper(shaper)
{
  req.user     = info.user;
  req.method   = "REGISTER";
  req.r_uri    = "sip:"+info.domain;
  req.from     = info.name+" <sip:"+info.user+"@"+info.domain+">";
  req.from_uri = "sip:"+info.user+"@"+info.domain;
  req.from_tag = handle;
  req.to       = req.from;
  req.to_tag   = "";
  req.callid   = AmSession::getNewId(); 

  reg_timers_override.stimer_f = info.transaction_timeout;
  reg_timers_override.stimer_m = info.srv_failover_timeout;

  patch_transport(req.r_uri,info.transport_protocol_id);

  // clear dlg.callid? ->reregister?
  dlg.initFromLocalRequest(req);
  dlg.cseq = 50;
}

void AmSIPRegistration::patch_transport(string &uri, int transport_protocol_id)
{
    switch(transport_protocol_id) {
    case sip_transport::UDP: break;
    case sip_transport::TCP: {
        DBG("%s patch uri to use TCP transport. current value is: '%s'",
            handle.c_str(),uri.c_str());
        AmUriParser parser;
        parser.uri = uri;
        if(!parser.parse_uri()) {
            ERROR("%s Error parsing '%s' for protocol patching to TCP. leave it as is",
                 handle.c_str(),parser.uri.c_str());
            break;
        }
        //check for existent transport param
        if(!parser.uri_param.empty()) {
            bool can_patch = true;
            auto uri_params_list = explode(URL_decode(parser.uri_param),";");
            for(const auto &p: uri_params_list) {
                auto v = explode(p,"=");
                if(v[0]=="transport") {
                    ERROR("%s attempt to patch with existent transport parameter: '%s'."
                          " leave it as is",
                          handle.c_str(),v.size()>1?v[1].c_str():"");
                    can_patch = false;
                    break;
                }
            }
            if(can_patch) {
                parser.uri_param+=";transport=TCP";
                uri = parser.uri_str();
                DBG("%s uri patched to: '%s'",
                    handle.c_str(),uri.c_str());
            }
        } else {
            parser.uri_param = "transport=TCP";
            uri = parser.uri_str();
            DBG("%s uri patched to: '%s'",
                handle.c_str(),uri.c_str());
        }
    } break;
    default:
        ERROR("%s transport_protocol_id %d is not supported yet. ignore it",
              handle.c_str(),transport_protocol_id);
    }
}

AmSIPRegistration::~AmSIPRegistration() {
  setSessionEventHandler(NULL);
}

void AmSIPRegistration::setRegistrationInfo(const SIPRegistrationInfo& _info) {
  DBG("updating registration info for '%s@%s'\n",
      _info.user.c_str(), _info.domain.c_str());
  info = _info;

  cred.realm = info.domain;
  cred.user = info.user;
  cred.pwd = info.pwd;

  req.user     = info.user;
  req.r_uri    = "sip:"+info.domain;
  req.from     = info.name+" <sip:"+info.user+"@"+info.domain+">";
  req.from_uri = "sip:"+info.user+"@"+info.domain;
  req.to       = req.from;
  req.to_tag   = "";

  patch_transport(req.r_uri,info.transport_protocol_id);

  // to trigger setting dlg identifiers
  dlg.setCallid(string());

  dlg.initFromLocalRequest(req);
}

void AmSIPRegistration::setSessionEventHandler(AmSessionEventHandler* new_seh) {
  if (seh)
    delete seh;
  seh = new_seh;
}
 
void AmSIPRegistration::setExpiresInterval(unsigned int desired_expires) {
  expires_interval = desired_expires;
}

void AmSIPRegistration::setForceExpiresInterval(bool force) {
  force_expires_interval = force;
}

bool AmSIPRegistration::doRegistration(bool skip_shaper)
{
  if(postponed) {
      ERROR("programming error: attempt to call doRegistration() for postponed registration. "
            "handle: %s",handle.c_str());
      log_stacktrace(L_ERR);
      return false;
  }

  if(!skip_shaper &&
     shaper.check_rate_limit(info.domain,postponed_next_attempt))
  {
    DBG("registration %s(%s): rate limit reached for %s. postpone sending request",
        handle.c_str(),info.id.c_str(),info.domain.c_str());
    unregistering = false;
    postponed = true;
    return false;
  }

  bool res = true;
  waiting_result = true;
  unregistering = false;
  postponed = false;

  req.to_tag     = "";
  req.r_uri    = "sip:"+info.domain;

  patch_transport(req.r_uri,info.transport_protocol_id);

  dlg.setRemoteTag(string());
  dlg.setRemoteUri(req.r_uri);
    
  // set outbound proxy as next hop 
  if (!info.proxy.empty()) {
    dlg.outbound_proxy = info.proxy;
    patch_transport(dlg.outbound_proxy,info.proxy_transport_protocol_id);
  } else if (!AmConfig.outbound_proxy.empty()) {
    dlg.outbound_proxy = AmConfig.outbound_proxy;
  }

  string hdrs = SIP_HDR_COLSP(SIP_HDR_EXPIRES) +
    int2str(expires_interval) + CRLF;

  int flags=0;

  if(info.contact.empty()) {
    //force contact username
    int oif = dlg.getOutboundIf();
    int oat = dlg.getOutboundAddrType();
    info_contact.uri_user = info.user;
    SIP_interface& if_ = AmConfig.sip_ifs[oif];
    for(auto& info : if_.proto_info) {
        if ((oat == sip_address_type::IPv4 && info->type_ip == IP_info::IPv4 &&
           info->type == SIP_info::UDP && dlg.getOutboundTransport() == sip_transport::UDP) ||

            (oat == sip_address_type::IPv4 && info->type_ip == IP_info::IPv4 &&
            info->type == SIP_info::TCP && dlg.getOutboundTransport() == sip_transport::TCP) ||

            (oat == sip_address_type::IPv4 && info->type_ip == IP_info::IPv4 &&
            info->type == SIP_info::TLS && dlg.getOutboundTransport() == sip_transport::TLS) ||

            (oat == sip_address_type::IPv6 && info->type_ip == IP_info::IPv6 &&
            info->type == SIP_info::UDP &&dlg.getOutboundTransport() == sip_transport::UDP) ||

            (oat == sip_address_type::IPv6 && info->type_ip == IP_info::IPv6 &&
            info->type == SIP_info::TCP && dlg.getOutboundTransport() == sip_transport::TCP) ||

            (oat == sip_address_type::IPv6 && info->type_ip == IP_info::IPv6 &&
            info->type == SIP_info::TLS && dlg.getOutboundTransport() == sip_transport::TLS))
        {
            info_contact.uri_host = info->getIP();
            info_contact.uri_port = int2str(info->local_port);
        }
    }
    info_contact.uri_param = info.contact_uri_params;

    info.contact = info_contact.uri_str();
  }

  size_t end = 0;
  if(!info_contact.parse_contact(info.contact,(size_t)0,end)){
    ERROR("failed to parse contact field: %s",info.contact.c_str());
    waiting_result = false;
    reg_send_begin  = time(NULL);
    return false;
  }
  request_contact = info.contact;
  hdrs += SIP_HDR_COLSP(SIP_HDR_CONTACT) "<"
          + info.contact + ">" + CRLF;
          flags = SIP_FLAGS_NOCONTACT;

  info.attempt++;

  if (dlg.sendRequest(req.method, NULL, hdrs, flags, &reg_timers_override) < 0) {
    WARN("failed to send registration. ruri: %s\n",
         req.r_uri.c_str());
    res = false;
    waiting_result = false;
    error_code = 500;
    error_reason = "failed to send request";
    error_initiatior = REG_ERROR_LOCAL;
  }
    
  // save TS
  reg_send_begin  = time(NULL);
  return res;
}

bool AmSIPRegistration::doUnregister()
{
  bool res = true;

  if(!unregistering && waiting_result) {
      dlg.finalize();
  }
  waiting_result = true;
  unregistering = true;
  postponed = false;

  req.to_tag     = "";
  req.r_uri      = "sip:"+info.domain;
  patch_transport(req.r_uri,info.transport_protocol_id);

  dlg.setRemoteTag(string());
  dlg.setRemoteUri(req.r_uri);
    
  // set outbound proxy as next hop 
  if (!info.proxy.empty()) {
    dlg.outbound_proxy = info.proxy;
    patch_transport(dlg.outbound_proxy,info.proxy_transport_protocol_id);
  } else if (!AmConfig.outbound_proxy.empty()) {
    dlg.outbound_proxy = AmConfig.outbound_proxy;
    patch_transport(dlg.outbound_proxy,info.proxy_transport_protocol_id);
  }

  int flags=0;
  string hdrs = SIP_HDR_COLSP(SIP_HDR_EXPIRES) "0" CRLF;
  if(!info.contact.empty()) {
    hdrs += SIP_HDR_COLSP(SIP_HDR_CONTACT) "<";
    hdrs += info.contact + ">" + CRLF;
    flags = SIP_FLAGS_NOCONTACT;
  }

  if (dlg.sendRequest(req.method, NULL, hdrs, flags) < 0) {
    ERROR("failed to send deregistration. mark to remove anyway. ruri: %s",
          req.r_uri.c_str());
    res = false;
    waiting_result = false;
    remove = true;
  }

  // save TS
  reg_send_begin  = time(NULL);
  return res;
}

void AmSIPRegistration::onSendRequest(AmSipRequest& req, int& flags)
{
  if (seh)
    seh->onSendRequest(req,flags);
}
	
void AmSIPRegistration::onSendReply(const AmSipRequest& req, AmSipReply& reply,
				    int& flags) {
  if (seh)
    seh->onSendReply(req,reply,flags);
}

AmSIPRegistration::RegistrationState AmSIPRegistration::getState() {
  if (active)
    return RegisterActive;
  if (waiting_result)
    return RegisterPending;
  if(postponed)
    return RegisterPostponed;
  if(error_code!=0)
    return RegisterError;
  return RegisterExpired;
}

bool AmSIPRegistration::getUnregistering() {
  return unregistering;
}

unsigned int AmSIPRegistration::getExpiresLeft() {
  long diff = reg_begin + reg_expires  - time(NULL);
  if (diff < 0) 
    return 0;
  else 
    return diff;
}

time_t AmSIPRegistration::getExpiresTS() {
  return reg_begin + reg_expires;
}
	
void AmSIPRegistration::onRegisterExpired() {
  if (sess_link.length()) {
    AmSessionContainer::instance()->postEvent(sess_link,
					      new SIPRegistrationEvent(SIPRegistrationEvent::RegisterTimeout,
									   handle,info.id));
  }
  DBG("Registration '%s' expired.\n", (info.user+"@"+info.domain).c_str());
  active = false;
  error_code = 500;
  error_reason = "register expired";
  error_initiatior = REG_ERROR_LOCAL;
  doRegistration();
}

void AmSIPRegistration::onRegisterSendTimeout() {
  if(info.max_attempts && info.attempt >= info.max_attempts) {
    return;
  }

  if (sess_link.length()) {
    AmSessionContainer::instance()->
      postEvent(sess_link,
		new SIPRegistrationEvent(SIPRegistrationEvent::RegisterSendTimeout,
					 handle,info.id));
  }
  DBG("Registration '%s' REGISTER request timeout.\n", 
      (info.user+"@"+info.domain).c_str());
  active = false;
  doRegistration();
}

void AmSIPRegistration::onPostponeExpired()
{
    DBG("Registration %s(%s) postponing timeout. REGISTER immediately ignoring shaper",
        handle.c_str(),info.id.c_str());
    postponed = false;
    doRegistration(true);
}

bool AmSIPRegistration::registerSendTimeout(time_t now_sec) {
  return now_sec > reg_send_begin + info.retry_delay;
}

bool AmSIPRegistration::timeToReregister(time_t now_sec) {
  //   	if (active) 
  //   		DBG("compare %lu with %lu\n",(reg_begin+reg_expires), (unsigned long)now_sec);
  return (((unsigned long)reg_begin+ reg_expires/2) < (unsigned long)now_sec);	
}

bool AmSIPRegistration::registerExpired(time_t now_sec) {
  return ((reg_begin+reg_expires) < (unsigned int)now_sec);	
}

bool AmSIPRegistration::postponingExpired(RegShaper::timep now)
{
	return now >= postponed_next_attempt;
}

void AmSIPRegistration::onSipReply(const AmSipRequest& req,
				   const AmSipReply& reply, 
				   AmBasicSipDialog::Status old_dlg_status)
{
  if ((seh!=NULL) && seh->onSipReply(req,reply, old_dlg_status))
    return;

  if (reply.code>=200)
    waiting_result = false;

  if ((reply.code>=200)&&(reply.code<300)) {

    string contacts = reply.contact;
    if (contacts.empty()) 
      contacts = getHeader(reply.hdrs, "Contact", "m", true);

    if (unregistering) {
      DBG("received positive reply to De-REGISTER\n");

      active = false;
      error_code = 0;
      remove = true;
      if (!contacts.length()) {
        DBG("no contacts registered any more\n");
      }
      if (sess_link.length()) {
        AmSessionContainer::instance()->postEvent(
          sess_link,
          new SIPRegistrationEvent(SIPRegistrationEvent::RegisterNoContact,
          handle,info.id,
          reply.code, reply.reason));
      }
    } else {
      DBG("%s(%s) positive reply to REGISTER!",
          req.from_tag.c_str(),info.id.c_str());

      size_t end  = 0;
      string local_contact_hdr = dlg.getContactUri();
      local_contact.parse_contact(local_contact_hdr, (size_t)0, end);
      local_contact.dump();
      reply_contacts.clear();

      bool found = false;

      if (!contacts.length()) {
        // should not happen - positive reply without contact
        DBG("%s(%s) no contacts registered any more",
            handle.c_str(),info.id.c_str());
        active = false;
        error_code = 500;
        error_reason = "no Contacts in positive reply";
        error_initiatior = REG_ERROR_LOCAL;;
      } else {
        end = 0;
        while (contacts.length() != end) {

          if (!server_contact.parse_contact(contacts, end, end)) {
            DBG("while parsing contact\n");
            break;
          }
          server_contact.dump();

          if(!reply_contacts.empty()) reply_contacts+=", ";
          reply_contacts += server_contact.uri_str();

          if(found) continue;

          if (server_contact.isEqual(local_contact) ||
              (!info.contact.empty()&&server_contact.isEqual(info_contact)))
          {
            DBG("contact found\n");
            found = active = true;
            info.attempt = 0;
            error_code = 0;
            if (str2i(server_contact.params["expires"], reg_expires)) {
              ERROR("could not extract expires value, default to 300.\n");
              reg_expires = 300;
            }

            DBG("got an expires of %d\n", reg_expires);
            if(force_expires_interval) {
              reg_expires = expires_interval;
              DBG("force expires to %d", reg_expires);
            }
            // save TS
            reg_begin = time(0);

            if (sess_link.length()) {
              DBG("%s(%s) posting SIPRegistrationEvent to '%s'\n",
                  handle.c_str(),info.id.c_str(),
                  sess_link.c_str());
              AmSessionContainer::instance()->
                postEvent(sess_link,
                  new SIPRegistrationEvent(SIPRegistrationEvent::RegisterSuccess,
                  handle,info.id,
                  reply.code, reply.reason));
            }
            break;
          }
        }
      } //if (!contacts.length()) else
      if (!found) {
        if (sess_link.length()) {
          AmSessionContainer::instance()->
            postEvent(sess_link,
              new SIPRegistrationEvent(SIPRegistrationEvent::RegisterNoContact,
              handle,info.id,
              reply.code, reply.reason));
        }
        DBG("Registration %s(%s) no matching Contact - deregistered",
            handle.c_str(),info.id.c_str());
        active = false;
        error_code = 500;
        error_reason = "no matching Contact in positive reply";
        error_initiatior = REG_ERROR_LOCAL;
      }
    } // if (unregistering) else
  } else if (reply.code >= 300) {
    if(unregistering) {
        DBG("De-Registration %s(%s) failed with code %d. remove it anyway",
            handle.c_str(),info.id.c_str(),reply.code);

        if (sess_link.length()) {
            AmSessionContainer::instance()->
                postEvent(sess_link,
                    new SIPRegistrationEvent(
                        SIPRegistrationEvent::RegisterNoContact,
                        handle,info.id,
                        reply.code,
                        reply.reason));
        }
        active = false;
        remove = true;
        return;
    }

    DBG("Registration %s(%s) failed with code %d",
        handle.c_str(),info.id.c_str(),reply.code);
    error_code = reply.code;
    error_reason = reply.reason;
    error_initiatior = REG_ERROR_REMOTE;

    if (sess_link.length()) {
        AmSessionContainer::instance()->
        postEvent(sess_link,
            new SIPRegistrationEvent(
                SIPRegistrationEvent::RegisterFailed,
                handle,info.id,
                reply.code,
                reply.reason));
    }
    active = false;
    //doRegistration();
  }
}

