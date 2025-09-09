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
#include "sip/parse_route.h"

bool SIPRegistrationInfo::init_from_amarg(const AmArg &info)
{
#define DEF_AND_VALIDATE_OPTIONAL_STR(key)                                                                             \
    if (info.hasMember(#key)) {                                                                                        \
        AmArg &key##_arg = info[#key];                                                                                 \
        if (!isArgCStr(key##_arg)) {                                                                                   \
            ERROR("unexpected '" #key "' type. expected string");                                                      \
            return false;                                                                                              \
        }                                                                                                              \
        key = key##_arg.asCStr();                                                                                      \
    }

#define DEF_AND_VALIDATE_OPTIONAL_STR_ALT(key, altname)                                                                \
    if (info.hasMember(#key)) {                                                                                        \
        AmArg &a = info[#key];                                                                                         \
        if (!isArgCStr(a)) {                                                                                           \
            ERROR("unexpected '" #key "' type. expected string");                                                      \
            return false;                                                                                              \
        }                                                                                                              \
        key = a.asCStr();                                                                                              \
    } else if (info.hasMember(#altname)) {                                                                             \
        AmArg &a = info[#altname];                                                                                     \
        if (!isArgCStr(a)) {                                                                                           \
            ERROR("unexpected '" #altname "' type. expected string");                                                  \
            return false;                                                                                              \
        }                                                                                                              \
        key = a.asCStr();                                                                                              \
    }

#define DEF_AND_VALIDATE_OPTIONAL_INT(key, default_value)                                                              \
    key = default_value;                                                                                               \
    if (info.hasMember(#key)) {                                                                                        \
        AmArg &key##_arg = info[#key];                                                                                 \
        if (!isArgInt(key##_arg)) {                                                                                    \
            ERROR("unexpected '" #key "' type. expected integer");                                                     \
            return false;                                                                                              \
        }                                                                                                              \
        key = key##_arg.asInt();                                                                                       \
    }

#define DEF_AND_VALIDATE_OPTIONAL_INT_ALT(key, altname, default_value)                                                 \
    key = default_value;                                                                                               \
    if (info.hasMember(#key)) {                                                                                        \
        AmArg &a = info[#key];                                                                                         \
        if (!isArgInt(a)) {                                                                                            \
            ERROR("unexpected '" #key "' type. expected integer");                                                     \
            return false;                                                                                              \
        }                                                                                                              \
        key = a.asInt();                                                                                               \
    } else if (info.hasMember(#altname)) {                                                                             \
        AmArg &a = info[#altname];                                                                                     \
        if (!isArgInt(a)) {                                                                                            \
            ERROR("unexpected '" #altname "' type. expected integer");                                                 \
            return false;                                                                                              \
        }                                                                                                              \
        key = a.asInt();                                                                                               \
    }

#define DEF_AND_VALIDATE_MANDATORY_STR(key)                                                                            \
    if (!info.hasMember(#key)) {                                                                                       \
        ERROR("missed '" #key "' in BusReplyEvent payload");                                                           \
        return false;                                                                                                  \
    }                                                                                                                  \
    AmArg &key##_arg = info[#key];                                                                                     \
    if (!isArgCStr(key##_arg)) {                                                                                       \
        ERROR("unexpected '" #key "' type. expected string");                                                          \
        return false;                                                                                                  \
    }                                                                                                                  \
    key = key##_arg.asCStr();

    if (!isArgStruct(info)) {
        ERROR("unexpected payload type in BusReplyEvent");
        return false;
    }
    if (!info.hasMember("id")) {
        ERROR("missed 'id' in BusReplyEvent payload");
        return false;
    }
    AmArg &id_arg = info["id"];
    if (isArgCStr(id_arg)) {
        id = id_arg.asCStr();
    } else if (isArgInt(id_arg)) {
        id = int2str(id_arg.asInt());
    } else {
        ERROR("unexpected 'id' type. expected string or integer");
        return false;
    }
    DEF_AND_VALIDATE_MANDATORY_STR(domain);

    if (info.hasMember("port")) {
        AmArg &a = info["port"];
        if (isArgInt(a))
            port = a.asInt();
    }

    DEF_AND_VALIDATE_OPTIONAL_STR(user);
    DEF_AND_VALIDATE_OPTIONAL_STR(name);
    DEF_AND_VALIDATE_OPTIONAL_STR_ALT(auth_user, auth_username);
    DEF_AND_VALIDATE_OPTIONAL_STR_ALT(pwd, auth_password);
    DEF_AND_VALIDATE_OPTIONAL_STR(proxy);
    DEF_AND_VALIDATE_OPTIONAL_STR(contact);
    DEF_AND_VALIDATE_OPTIONAL_STR(contact_uri_params);
    DEF_AND_VALIDATE_OPTIONAL_STR(sip_interface_name);
    DEF_AND_VALIDATE_OPTIONAL_STR(route_set);

    DEF_AND_VALIDATE_OPTIONAL_INT_ALT(expires_interval, expires, 0);
    DEF_AND_VALIDATE_OPTIONAL_INT(force_expires_interval, 0);
    DEF_AND_VALIDATE_OPTIONAL_INT(retry_delay, DEFAULT_REGISTER_RETRY_DELAY);
    DEF_AND_VALIDATE_OPTIONAL_INT(max_attempts, REGISTER_ATTEMPTS_UNLIMITED);
    DEF_AND_VALIDATE_OPTIONAL_INT(transport_protocol_id, sip_transport::UDP);
    DEF_AND_VALIDATE_OPTIONAL_INT(proxy_transport_protocol_id, sip_transport::UDP);

    DEF_AND_VALIDATE_OPTIONAL_INT(transaction_timeout, 0);
    DEF_AND_VALIDATE_OPTIONAL_INT(srv_failover_timeout, 0);

    string priority;
    DEF_AND_VALIDATE_OPTIONAL_STR(priority);
    resolve_priority = string_to_priority(priority);

    if (info.hasMember("scheme_id")) {
        AmArg &a = info["scheme_id"];
        if (!isArgInt(a)) {
            ERROR("unexpected scheme_id type. expected integer");
            return false;
        }
        scheme_id = static_cast<sip_uri::uri_scheme>(a.asInt());
        if (scheme_id < sip_uri::SIP || scheme_id > sip_uri::SIPS) {
            ERROR("unexpected scheme_id value: %d", scheme_id);
            return false;
        }
    }

    if (info.hasMember("contact_params")) {
        AmArg &a = info["contact_params"];
        if (!isArgStruct(a)) {
            ERROR("unexpected contact_params type. expected struct");
            return false;
        }

        for (auto &p : a) {
            if (!isArgCStr(p.second)) {
                ERROR("unexpected value of contact_params member %s. expected string", p.first.c_str());
                return false;
            }
            contact_params[p.first] = p.second.asCStr();
        }
    }

#undef DEF_AND_VALIDATE_OPTIONAL_STR
#undef DEF_AND_VALIDATE_OPTIONAL_INT
#undef DEF_AND_VALIDATE_MANDATORY_STR
    return true;
}


AmSIPRegistration::AmSIPRegistration(const string &handle, const SIPRegistrationInfo &info, const string &sess_link)
    : dlg(this)
    , cred(info.domain, info.auth_user, info.pwd)
    , info(info)
    , handle(handle)
    , sess_link(sess_link)
    , seh(nullptr)
    , expires_interval(3600)
    , force_expires_interval(false)
    , active(false)
    , remove(false)
    , waiting_result(false)
    , unregistering(false)
    , postponed(false)
    , reg_begin(0)
    , reg_expires(0)
    , reg_send_begin(0)
    , error_code(0)
{
    applyInfo();
}

void AmSIPRegistration::patch_transport(string &uri, int transport_protocol_id)
{
    switch (transport_protocol_id) {
    case sip_transport::UDP: break;
    case sip_transport::TCP:
    case sip_transport::TLS:
    {
        auto transport_name = transport_str(transport_protocol_id);
        DBG("%s patch uri to use %.*s transport. current value is: '%s'", handle.c_str(), transport_name.len,
            transport_name.s, uri.c_str());
        AmUriParser parser;
        parser.uri = uri;
        if (!parser.parse_uri()) {
            ERROR("%s Error parsing '%s' for protocol patching to %.*s. leave it as is", handle.c_str(),
                  parser.uri.c_str(), transport_name.len, transport_name.s);
            break;
        }
        // check for existent transport param
        if (!parser.uri_param.empty()) {
            bool can_patch       = true;
            auto uri_params_list = explode(URL_decode(parser.uri_param), ";");
            for (const auto &p : uri_params_list) {
                auto v = explode(p, "=");
                if (v[0] == "transport") {
                    ERROR("%s attempt to patch with existent transport parameter: '%s'."
                          " leave it as is",
                          handle.c_str(), v.size() > 1 ? v[1].c_str() : "");
                    can_patch = false;
                    break;
                }
            }
            if (can_patch) {
                parser.uri_param += ";transport=";
                parser.uri_param += c2stlstr(transport_name);
                uri = parser.uri_str();
                DBG("%s uri patched to: '%s'", handle.c_str(), uri.c_str());
            }
        } else {
            parser.uri_param = "transport=";
            parser.uri_param += c2stlstr(transport_name);
            uri = parser.uri_str();
            DBG("%s uri patched to: '%s'", handle.c_str(), uri.c_str());
        }
    } break;
    default:
        ERROR("%s transport_protocol_id %d is not supported yet. ignore it", handle.c_str(), transport_protocol_id);
    }
}

AmSIPRegistration::~AmSIPRegistration()
{
    setSessionEventHandler(nullptr);
}

void AmSIPRegistration::setRegistrationInfo(const SIPRegistrationInfo &_info)
{
    DBG("updating registration info for '%s@%s'", _info.user.c_str(), _info.domain.c_str());
    info = _info;

    cred.realm = info.domain;
    cred.user  = info.user;
    cred.pwd   = info.pwd;

    applyInfo();
}

void AmSIPRegistration::applyInfo()
{
    AmUriParser uri_parser;

    req.method = "REGISTER";
    req.user   = info.user;

    uri_parser.uri_host = info.domain;
    ensure_ipv6_reference(uri_parser.uri_host);

    if (info.port) {
        uri_parser.uri_port = int2str(info.port);
    }

    // set scheme
    if (sip_uri::SIPS == info.scheme_id) {
        uri_parser.uri_scheme = "sips";
    }

    // add transport
    if (sip_transport::UDP != info.transport_protocol_id && sip_uri::SIPS != info.scheme_id) {
        uri_parser.uri_param += "transport=";
        uri_parser.uri_param += c2stlstr(transport_str(info.transport_protocol_id));
    }

    req.r_uri = uri_parser.uri_str();
    uri_parser.uri_param.clear(); // remove transport for To/From/Contact headers

    uri_parser.display_name = info.name;
    uri_parser.uri_user     = info.user;

    req.from     = uri_parser.nameaddr_str();
    req.from_tag = handle;

    req.to     = req.from;
    req.to_tag = "";

    req.from_uri = uri_parser.uri_str(); // Contact header

    req.callid = AmSession::getNewId();

    reg_timers_override.stimer_f = static_cast<unsigned int>(info.transaction_timeout);
    reg_timers_override.stimer_m = static_cast<unsigned int>(info.srv_failover_timeout);

    dlg.initFromLocalRequest(req);
    dlg.cseq = 50;

    if (!info.route_set.empty()) {
        if (parse_and_validate_route(info.route_set) == 0)
            dlg.setRouteSet(info.route_set);
    } else
        // set outbound proxy as next hop
        if (!info.proxy.empty()) {
            dlg.outbound_proxy = info.proxy;
            patch_transport(dlg.outbound_proxy, info.proxy_transport_protocol_id);
        } else if (!AmConfig.outbound_proxy.empty()) {
            dlg.outbound_proxy = AmConfig.outbound_proxy;
        }
}

void AmSIPRegistration::setSessionEventHandler(AmSessionEventHandler *new_seh)
{
    if (seh)
        delete seh;
    seh = new_seh;
}

void AmSIPRegistration::setExpiresInterval(unsigned int desired_expires)
{
    expires_interval = desired_expires;
}

void AmSIPRegistration::setForceExpiresInterval(bool force)
{
    force_expires_interval = force;
}

bool AmSIPRegistration::doRegistration()
{
    if (postponed) {
        ERROR("programming error: attempt to call doRegistration() for postponed registration. "
              "handle: %s",
              handle.c_str());
        log_stacktrace(L_ERR);
        return false;
    }

    /*auto now = std::chrono::system_clock::now();
    long value = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
    DBG("send register id %s key %s now %ld", info.id.c_str(), info.domain.c_str(), value%100000);*/

    bool res       = true;
    waiting_result = true;
    unregistering  = false;

    while (!info.sip_interface_name.empty() && info.sip_interface_name != "default") {
        auto name_it = AmConfig.sip_if_names.find(info.sip_interface_name);
        if (name_it == AmConfig.sip_if_names.end()) {
            ERROR("regisration %s(%s): specified sip_interface_name '%s' does not exist as a signaling interface",
                  handle.data(), info.id.data(), info.sip_interface_name.data());
            break;
        }
        dlg.setOutboundInterface(name_it->second);
        dlg.setOutboundAddrType(AT_V4);
        dlg.setOutboundProtoId(0);
        break;
    }

    dlg.setRemoteTag(req.to_tag);
    dlg.setRemoteUri(req.r_uri);
    dlg.setResolvePriority(info.resolve_priority);

    string hdrs = SIP_HDR_COLSP(SIP_HDR_EXPIRES) + int2str(expires_interval) + CRLF;

    if (request_contact.empty()) {
        if (info.contact.empty()) {
            // force contact username
            int oif                = dlg.getOutboundIf();
            int oproto             = dlg.getOutboundProtoId();
            local_contact.uri_user = info.user;
            const auto &pi         = AmConfig.sip_ifs[static_cast<size_t>(oif)].proto_info[static_cast<size_t>(oproto)];
            local_contact.uri_host = pi->getIP();
            local_contact.uri_port = int2str(pi->local_port);
            local_contact.uri_param = info.contact_uri_params;
            local_contact.params    = info.contact_params;
        } else {
            size_t end = 0;
            if (!local_contact.parse_contact(info.contact, 0, end)) {
                ERROR("failed to parse contact field: %s", info.contact.c_str());
                waiting_result = false;
                reg_send_begin = time(nullptr);
                return false;
            }
        }

        request_contact = local_contact.nameaddr_str();
    }

    hdrs += SIP_HDR_COLSP(SIP_HDR_CONTACT) + request_contact + CRLF;

    info.attempt++;

    if (dlg.sendRequest(req.method, nullptr, hdrs, SIP_FLAGS_NOCONTACT, &reg_timers_override) < 0) {
        DBG("failed to send registration. ruri: %s", req.r_uri.c_str());
        res              = false;
        waiting_result   = false;
        error_code       = 500;
        error_reason     = "failed to send request";
        error_initiatior = REG_ERROR_LOCAL;
    }

    // save TS
    reg_send_begin = time(nullptr);
    return res;
}

bool AmSIPRegistration::doUnregister()
{
    bool res = true;

    if (!unregistering && waiting_result) {
        dlg.finalize();
    }
    waiting_result = true;
    unregistering  = true;
    postponed      = false;

    dlg.setRemoteTag(req.to_tag);
    dlg.setRemoteUri(req.r_uri);

    int    flags = 0;
    string hdrs  = SIP_HDR_COLSP(SIP_HDR_EXPIRES) "0" CRLF;
    if (!request_contact.empty()) {
        hdrs += SIP_HDR_COLSP(SIP_HDR_CONTACT) + request_contact + CRLF;
        flags = SIP_FLAGS_NOCONTACT;
    }

    if (dlg.sendRequest(req.method, nullptr, hdrs, flags) < 0) {
        ERROR("failed to send deregistration. mark to remove anyway. ruri: %s", req.r_uri.c_str());
        res            = false;
        waiting_result = false;
        remove         = true;
    }

    // save TS
    reg_send_begin = time(nullptr);
    return res;
}

void AmSIPRegistration::onSendRequest(AmSipRequest &req, int &flags)
{
    if (seh)
        seh->onSendRequest(req, flags);
}

void AmSIPRegistration::onSendReply(const AmSipRequest &req, AmSipReply &reply, int &flags)
{
    if (seh)
        seh->onSendReply(req, reply, flags);
}

AmSIPRegistration::RegistrationState AmSIPRegistration::getState()
{
    if (active)
        return RegisterActive;
    if (waiting_result)
        return RegisterPending;
    if (postponed)
        return RegisterPostponed;
    if (error_code != 0)
        return RegisterError;
    return RegisterExpired;
}

bool AmSIPRegistration::getUnregistering()
{
    return unregistering;
}

unsigned int AmSIPRegistration::getExpiresLeft()
{
    long diff = reg_begin + reg_expires - time(nullptr);
    if (diff < 0)
        return 0;
    else
        return static_cast<unsigned int>(diff);
}

time_t AmSIPRegistration::getExpiresTS()
{
    return reg_begin + reg_expires;
}

void AmSIPRegistration::onRegisterExpired()
{
    if (sess_link.length()) {
        AmSessionContainer::instance()->postEvent(
            sess_link, new SIPRegistrationEvent(SIPRegistrationEvent::RegisterTimeout, handle, info.id));
    }
    DBG("Registration '%s' expired.", (info.user + "@" + info.domain).c_str());
    active           = false;
    error_code       = 500;
    error_reason     = "register expired";
    error_initiatior = REG_ERROR_LOCAL;
}

void AmSIPRegistration::onRegisterSendTimeout()
{
    if (info.max_attempts && info.attempt >= info.max_attempts) {
        return;
    }

    if (sess_link.length()) {
        AmSessionContainer::instance()->postEvent(
            sess_link, new SIPRegistrationEvent(SIPRegistrationEvent::RegisterSendTimeout, handle, info.id));
    }
    DBG("Registration '%s' REGISTER request timeout.", (info.user + "@" + info.domain).c_str());
    active = false;
}

bool AmSIPRegistration::registerSendTimeout(time_t now_sec)
{
    return now_sec > reg_send_begin + info.retry_delay;
}

bool AmSIPRegistration::timeToReregister(time_t now_sec)
{
    return ((static_cast<unsigned long>(reg_begin) + reg_expires / 2) < static_cast<unsigned long>(now_sec));
}

bool AmSIPRegistration::registerExpired(time_t now_sec)
{
    return ((reg_begin + reg_expires) < static_cast<unsigned int>(now_sec));
}

void AmSIPRegistration::onSipReply(const AmSipRequest &req, const AmSipReply &reply,
                                   AmBasicSipDialog::Status old_dlg_status)
{
    if ((seh != nullptr) && seh->onSipReply(req, reply, old_dlg_status))
        return;

    if (reply.code >= 200)
        waiting_result = false;

    if ((reply.code >= 200) && (reply.code < 300)) {

        string contacts = reply.contact;
        if (contacts.empty())
            contacts = getHeader(reply.hdrs, "Contact", "m", true);

        if (unregistering) {
            active     = false;
            error_code = 0;
            remove     = true;

            if (sess_link.length()) {
                AmSessionContainer::instance()->postEvent(
                    sess_link, new SIPRegistrationEvent(SIPRegistrationEvent::RegisterNoContact, handle, info.id,
                                                        reply.code, reply.reason));
            }
        } else {
            size_t      end = 0;
            AmUriParser server_contact;

            // local_contact.dump();
            reply_contacts.clear();

            bool found = false;

            if (!contacts.length()) {
                DBG("%s(%s) no contacts in register positive reply", handle.c_str(), info.id.c_str());
                active           = false;
                error_code       = 500;
                error_reason     = "no Contacts in positive reply";
                error_initiatior = REG_ERROR_LOCAL;
            } else {
                end = 0;
                while (contacts.length() != end) {
                    if (!server_contact.parse_contact(contacts, end, end)) {
                        DBG("[%s](%s) failed to parse contact", handle.c_str(), info.id.c_str());
                        break;
                    }

                    if (end < contacts.length())
                        end++; // skip ','. see: _SipCtrlInterface::sip_msg2am_reply

                    reply_contacts.push(server_contact.nameaddr_str());

                    if (found)
                        continue;

                    if (server_contact.isEqual(local_contact)) {
                        const auto contact_expires = server_contact.params.find("expires");
                        if (contact_expires == server_contact.params.end()) {
                            auto expires_header = getHeader(reply.hdrs, SIP_HDR_EXPIRES, true);
                            if (expires_header.empty()) {
                                ERROR("[%s](%s) missed both 'expires' param on matched contact and Expires header",
                                      handle.c_str(), info.id.c_str());
                                active           = false;
                                error_code       = 500;
                                error_reason     = "Failed to extract expires value from matched contact";
                                error_initiatior = REG_ERROR_LOCAL;
                                return;
                            }
                            if (str2i(expires_header, reg_expires)) {
                                ERROR("[%s](%s) could not extract Expires header value", handle.c_str(),
                                      info.id.c_str());
                                active           = false;
                                error_code       = 500;
                                error_reason     = "Failed to extract Expires header value on missed 'expires' param";
                                error_initiatior = REG_ERROR_LOCAL;
                                return;
                            }
                        } else {
                            if (str2i(contact_expires->second, reg_expires)) {
                                ERROR("[%s](%s) could not extract expires value", handle.c_str(), info.id.c_str());
                                active           = false;
                                error_code       = 500;
                                error_reason     = "Failed to extract expires value from matched contact";
                                error_initiatior = REG_ERROR_LOCAL;
                                return;
                            }
                        }

                        if (force_expires_interval) {
                            reg_expires = expires_interval;
                        }

                        found = active = true;
                        info.attempt   = 0;
                        error_code     = 0;

                        // save TS
                        reg_begin = time(nullptr);

                        if (sess_link.length()) {
                            DBG("[%s](%s) posting SIPRegistrationEvent to '%s'", handle.c_str(), info.id.c_str(),
                                sess_link.c_str());
                            AmSessionContainer::instance()->postEvent(
                                sess_link, new SIPRegistrationEvent(SIPRegistrationEvent::RegisterSuccess, handle,
                                                                    info.id, reply.code, reply.reason));
                        }
                    }
                } // while(contacts.length() != end)
            } // if (!contacts.length()) else

            if (!found) {
                if (sess_link.length()) {
                    AmSessionContainer::instance()->postEvent(
                        sess_link, new SIPRegistrationEvent(SIPRegistrationEvent::RegisterNoContact, handle, info.id,
                                                            reply.code, reply.reason));
                }

                DBG("[%s](%s) no matching Contact - deregistered", handle.c_str(), info.id.c_str());

                active           = false;
                error_code       = 500;
                error_reason     = "no matching Contact in positive reply";
                error_initiatior = REG_ERROR_LOCAL;
            }
        } // if (unregistering) else
    } else if (reply.code >= 300) {
        if (unregistering) {
            DBG("[%s](%s) De-Registration failed with code %d. remove it anyway", handle.c_str(), info.id.c_str(),
                reply.code);

            if (sess_link.length()) {
                AmSessionContainer::instance()->postEvent(
                    sess_link, new SIPRegistrationEvent(SIPRegistrationEvent::RegisterNoContact, handle, info.id,
                                                        reply.code, reply.reason));
            }

            active = false;
            remove = true;
            return;
        }

        DBG("[%s](%s) Registration failed with code %d", handle.c_str(), info.id.c_str(), reply.code);

        error_code       = static_cast<int>(reply.code);
        error_reason     = reply.reason;
        error_initiatior = REG_ERROR_REMOTE;

        if (sess_link.length()) {
            AmSessionContainer::instance()->postEvent(
                sess_link, new SIPRegistrationEvent(SIPRegistrationEvent::RegisterFailed, handle, info.id, reply.code,
                                                    reply.reason));
        }
        active = false;
    } // else if (reply.code >= 300)
}
