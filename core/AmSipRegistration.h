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

#ifndef _AmSipRegistration_h_
#define _AmSipRegistration_h_
#include <string>
using std::string;

#include "ampi/SIPRegistrarClientAPI.h"
#include "ampi/UACAuthAPI.h"
#include "AmUriParser.h"
#include "AmSessionEventHandler.h"
#include "RegShaper.h"

#define DEFAULT_REGISTER_RETRY_DELAY 5
#define REGISTER_ATTEMPTS_UNLIMITED 0

struct SIPRegistrationInfo {
  string id;
  string domain;
  string user;
  string name;
  string auth_user;
  string pwd;
  string proxy;
  string contact;
  int expires_interval;
  int retry_delay;
  int max_attempts;
  int attempt;
  int transport_protocol_id;
  int proxy_transport_protocol_id;
  bool force_expires_interval;

  SIPRegistrationInfo(
    const string& id,
    const string& domain,
    const string& user,
    const string& name,
    const string& auth_user,
    const string& pwd,
    const string& proxy,
    const string& contact,
    const int& expires_interval,
    const bool &force_expires_interval,
    const int& retry_delay,
    const int& max_attempts,
    const int& transport_protocol_id,
    const int& proxy_transport_protocol_id)
  : id(id),domain(domain),user(user),name(name),
    auth_user(auth_user),pwd(pwd),proxy(proxy),contact(contact),
    expires_interval(expires_interval),
    force_expires_interval(force_expires_interval),
    retry_delay(retry_delay),
    max_attempts(max_attempts),
    transport_protocol_id(transport_protocol_id),
    proxy_transport_protocol_id(proxy_transport_protocol_id),
    attempt(0)
  { }
};

class AmSIPRegistration 
: public AmBasicSipEventHandler,
  public DialogControl,
  public CredentialHolder
	
{
	
  AmBasicSipDialog dlg;
  UACAuthCred cred;

  SIPRegistrationInfo info;
  string handle;

  // session to post events to 
  string sess_link;      

  AmSessionEventHandler* seh;

  AmSipRequest req;

  AmUriParser server_contact;
  AmUriParser local_contact;
  AmUriParser info_contact;

  unsigned int expires_interval;
  bool force_expires_interval;

  RegShaper &shaper;

  void patch_transport(string &uri, int transport_protocol_id);

 public:
  AmSIPRegistration(const string& handle,
		    const SIPRegistrationInfo& info,
			const string& sess_link,
			RegShaper &shaper);
  ~AmSIPRegistration();

  void setRegistrationInfo(const SIPRegistrationInfo& _info);

  void setSessionEventHandler(AmSessionEventHandler* new_seh);

  void setExpiresInterval(unsigned int desired_expires);
  void setForceExpiresInterval(bool force);

  bool doRegistration(bool skip_shaper = false);
  bool doUnregister();
	
  bool timeToReregister(time_t now_sec);
  bool registerExpired(time_t now_sec);
  bool postponingExpired(RegShaper::timep now);
  void onRegisterExpired();
  void onRegisterSendTimeout();
  void onPostponeExpired();

  bool registerSendTimeout(time_t now_sec);

  void onSendRequest(AmSipRequest& req, int& flags);
  void onSendReply(const AmSipRequest& req, AmSipReply& reply, int& flags);

  // DialogControl if
  AmBasicSipDialog* getDlg() { return &dlg; }
  // CredentialHolder	
  UACAuthCred* getCredentials() { return &cred; }

  void onSipReply(const AmSipRequest& req,
		  const AmSipReply& reply, 
		  AmBasicSipDialog::Status old_dlg_status);

  /** is this registration registered? */
  bool active; 
  /** should this registration be removed from container? */
  bool remove;
  /** are we waiting for the response to a register? */
  bool waiting_result;
  /** are we unregistering? */
  bool unregistering;
  /** are we postponed */
  bool postponed;

  time_t reg_begin;
  unsigned int reg_expires;
  time_t reg_send_begin;
  RegShaper::timep postponed_next_attempt;

  string request_contact;
  string reply_contacts;

  enum error_initiator {
    REG_ERROR_LOCAL = 0,
    REG_ERROR_REMOTE
  } error_initiatior;
  int error_code;
  string error_reason;

  enum RegistrationState {
    RegisterPending = 0,
    RegisterActive,
    RegisterError,
    RegisterExpired,
    RegisterPostponed
  };
  /** return the state of the registration */
  RegistrationState getState(); 
  /** return the expires left for the registration */
  unsigned int getExpiresLeft();
  /** return the expires TS for the registration */
  time_t getExpiresTS();

  bool getUnregistering();

  SIPRegistrationInfo& getInfo() { return info; }
  const string& getEventSink() { return sess_link; }
  const string& getHandle() { return req.from_tag; }
};



#endif
