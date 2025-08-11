/*
 * Copyright (C) 2002-2003 Fhg Fokus
 * Copyright (C) 2006 iptego GmbH
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

#include "UACAuth.h"
#include "AmSipMsg.h"
#include "AmUtils.h"
#include "AmSipHeaders.h"
#include "AmLcConfig.h"
#include "AmUriParser.h"

#include <map>

#include <cctype>
#include <algorithm>

#include "md5.h"
#include "sip/sip_trans.h"
#include "sip/resolver.h"
#include <confuse.h>

using std::string;


#define MOD_NAME "uac_auth"

#define OPT_ALLOWED_QOPS "allowed_qops"
#define OPT_SERVER_SECRET "server_secret"
#define OPT_NONCE_EXPIRE "nonce_expire"

#define DEFAULT_NONCE_EXPIRE 300

EXPORT_SESSION_EVENT_HANDLER_FACTORY(UACAuthFactory);
EXPORT_PLUGIN_CLASS_FACTORY(UACAuthFactory);
EXPORT_PLUGIN_CONF_FACTORY(UACAuthFactory);

UACAuthFactory* UACAuthFactory::_instance=0;
string UACAuth::server_nonce_secret = "CKASLD§$>NLKJSLDKFJ"; // replaced on load
int UACAuth::allowed_qop_types;
int UACAuth::nonce_expire;
static string qop_str_value;

static string default_nonce_count("00000001");

UACAuthFactory* UACAuthFactory::instance()
{
    if(!_instance)
        _instance = new UACAuthFactory(MOD_NAME);
    return _instance;
}

void UACAuthFactory::invoke(const string& method, const AmArg& args, AmArg& ret)
{
    if(method == "getHandler") {
        CredentialHolder* c = dynamic_cast<CredentialHolder*>(args.get(0).asObject());
        DialogControl* cc = dynamic_cast<DialogControl*>(args.get(1).asObject());

        if ((c!=nullptr)&&(cc!=nullptr)) {
        AmArg handler;
        handler.setBorrowedPointer(getHandler(cc->getDlg(), c));
        ret.push(handler);
        } else {
            ERROR("wrong types in call to getHandler.  (c=%ld, cc= %ld)", 
                  (unsigned long)c, (unsigned long)cc);
        }
    } else if (method == "checkAuth") {
        // params: Request realm user pwd [default_realm]
        if(args.size() < 4) {
            ERROR("missing arguments to uac_auth checkAuth function, expected Request realm user pwd");
            throw AmArg::TypeMismatchException();
        }

        AmSipRequest* req = dynamic_cast<AmSipRequest*>(args.get(0).asObject());
        if (nullptr == req)
            throw AmArg::TypeMismatchException();

        const AmArg &realms_arg = args.get(1);
        vector<string> realms;
        switch(realms_arg.getType()) {
        case AmArg::CStr:
            realms.emplace_back(realms_arg.asCStr());
            break;
        case AmArg::Array:
            if(!realms_arg.size())
                throw AmArg::TypeMismatchException();
            realms = realms_arg.asStringVector();
            break;
        default: throw AmArg::TypeMismatchException();
        };

        string default_realm;
        if (args.size() >= 5) {
            const AmArg &default_realm_arg = args.get(4);
            if (isArgCStr(default_realm_arg))
                default_realm = default_realm_arg.asCStr();
        }
        if(default_realm.empty())
            default_realm = realms[0];

        UACAuth::checkAuthentication(req, realms,
                                     args.get(2).asCStr(),
                                     args.get(3).asCStr(),
                                     default_realm, ret);
    } else if(method == "getChallenge") {
        ret = UACAuth::getChallengeHeader(args.get(0).asCStr());
    } else if(method == "checkAuthHA1") {
        // params: Request realm user pwd
        if (args.size() < 4) {
            ERROR("missing arguments to uac_auth checkAuthHA1 function, expected Request realm user pwd");
            throw AmArg::TypeMismatchException();
        }

        AmSipRequest* req = dynamic_cast<AmSipRequest*>(args.get(0).asObject());
        if(nullptr == req)
            throw AmArg::TypeMismatchException();

        UACAuth::checkAuthenticationByHA1(
            req, args.get(1).asCStr(),
            args.get(2).asCStr(),
            args.get(3).asCStr(), ret);
    } else if (method == "fetchCred") {
        // params: Request
        if (args.size() < 1) {
            ERROR("missing arguments to uac_auth fetchCred function, expected Request");
            throw AmArg::TypeMismatchException();
        }

        AmSipRequest *req = dynamic_cast<AmSipRequest *>(args.get(0).asObject());
        if (nullptr == req)
            throw AmArg::TypeMismatchException();

        UACAuth::fetchAuthentication(req, ret);
    } else
        throw AmDynInvoke::NotImplemented(method);
}


int UACAuthFactory::onLoad()
{
    return 0;
}

int UACAuthFactory::configure(const std::string& config)
{
    cfg_opt_t opt[] = {
        CFG_STR_LIST(OPT_ALLOWED_QOPS, 0,CFGF_NONE),
        CFG_STR(OPT_SERVER_SECRET, "", CFGF_NONE),
        CFG_INT(OPT_NONCE_EXPIRE, DEFAULT_NONCE_EXPIRE, CFGF_NONE),
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

    //server_secret
    std::string secret = cfg_getstr(cfg, OPT_SERVER_SECRET);
    if(secret.empty()) {
        WARN("server_secret is not set. use the randomly generated one");
        secret = AmSession::getNewId();
    } else {
        //validate secret
        if(secret.size() < 5) {
            ERROR("uac_auth: server_secret is too short");
            return -1;
        }
    }
    UACAuth::setServerSecret(secret);

    //allowed_qops
    if(cfg_size(cfg, OPT_ALLOWED_QOPS)) {
        int allowed_qops = 0;
        for(unsigned int j = 0; j < cfg_size(cfg, OPT_ALLOWED_QOPS); j++) {
            std::string str_qop_name = cfg_getnstr(cfg, OPT_ALLOWED_QOPS, j);
            if("auth"==str_qop_name) {
                allowed_qops |= UACAuth::QOP_AUTH;
                DBG("enable 'auth' qop");
            } else if("auth-int"==str_qop_name) {
                allowed_qops |= UACAuth::QOP_AUTH_INT;
                DBG("enable 'auth-int' qop");
            } else {
                ERROR("unknown qop type: '%s'. (expected: auth, auth-int)",str_qop_name.data());
                return -1;
            }
        }
        UACAuth::setAllowedQops(allowed_qops);
    } else {
        DBG("empty " OPT_ALLOWED_QOPS ". allow both auth and auth-int by default");
        UACAuth::setAllowedQops(UACAuth::QOP_AUTH | UACAuth::QOP_AUTH_INT);
    }

    UACAuth::setNonceExpire(cfg_getint(cfg, OPT_NONCE_EXPIRE));

    cfg_free(cfg);

    return 0;
}

int UACAuthFactory::reconfigure(const std::string& config)
{
    return configure(config);
}

bool UACAuthFactory::onInvite(const AmSipRequest&, AmConfigReader&)
{
    return true;
}

string UACAuthDigestChallenge::find_attribute(const string &name)
{
    auto it = attributes.find(name);
    if(it != attributes.end()) {
        return it->second;
    }
    return string();
}

bool UACAuthDigestChallenge::parse(const std::string auth_hdr)
{
    attributes.clear();

    auto pos = auth_hdr.find_first_not_of(' ');

    string method = auth_hdr.substr(pos, 6);
    std::transform(
        method.begin(), method.end(), method.begin(),
        (int(*)(int)) toupper);
    if(method != "DIGEST") {
        ERROR("only Digest auth supported. hdr: %s", auth_hdr.data());
        return false;
    }
    pos+=6;

    char last_c = 0;
    string::size_type name_start_pos = 0, name_end_pos = 0,
                      value_start_pos = 0, value_end_pos = 0;
    enum { ST_START,
           ST_NAME_SKIP_WS_BEFORE, ST_NAME, ST_NAME_SKIP_WS_AFTER,
           ST_VALUE_SKIP_WS_BEFORE, ST_VALUE, ST_ESCAPED_VALUE, ST_VALUE_SKIP_WS_AFTER
    } st = ST_START;

    auto process_attribute_end = [&](bool end_by_comma = true) -> bool {
        switch(st) {
        case ST_NAME:
            st = ST_START;
            name_end_pos = pos;
            attributes.emplace(
                auth_hdr.substr(name_start_pos, name_end_pos - name_start_pos),
                string());
            break;
        case ST_NAME_SKIP_WS_AFTER:
            st = ST_START;
            attributes.emplace(
                auth_hdr.substr(name_start_pos, name_end_pos - name_start_pos),
                string());
            name_start_pos = pos;
            break;
        case ST_VALUE_SKIP_WS_BEFORE:
            st = ST_START;
            attributes.emplace(
                auth_hdr.substr(name_start_pos, name_end_pos - name_start_pos),
                string());
            name_start_pos = pos;
            break;
        case ST_VALUE:
            st = ST_START;
            value_end_pos = pos;
            attributes.emplace(
                auth_hdr.substr(name_start_pos, name_end_pos - name_start_pos),
                auth_hdr.substr(value_start_pos, value_end_pos - value_start_pos));
            name_start_pos = pos;
            break;
        case ST_VALUE_SKIP_WS_AFTER:
            st = ST_START;
            attributes.emplace(
                auth_hdr.substr(name_start_pos, name_end_pos - name_start_pos),
                auth_hdr.substr(value_start_pos, value_end_pos - value_start_pos));
            name_start_pos = pos;
            break;
        case ST_ESCAPED_VALUE:
        case ST_START:
            break;
        default:
            if (end_by_comma) {
                ERROR("unexpected comma at %lu. hdr: %s", pos, auth_hdr.data());
                return false;
            }
        }
        return true;
    };

    while(pos < auth_hdr.length()) {
        auto &c = auth_hdr[pos];
        switch(c) {
        case '\"':
            switch(st) {
            case ST_VALUE_SKIP_WS_BEFORE:
                st = ST_ESCAPED_VALUE;
                value_start_pos = pos+1;
                last_c = c;
                break;
            case ST_ESCAPED_VALUE:
                if(last_c != '\\') {
                    st = ST_VALUE_SKIP_WS_AFTER;
                    value_end_pos = pos;
                }
                break;
            default:
                ERROR("unexpected dquote at %lu. hdr: %s", pos, auth_hdr.data());
                return false;
            }
            break;
        case '=':
            switch(st) {
            case ST_NAME:
                st = ST_VALUE_SKIP_WS_BEFORE;
                name_end_pos = value_start_pos = pos;
                break;
            case ST_NAME_SKIP_WS_AFTER:
                st = ST_VALUE_SKIP_WS_BEFORE;
                value_start_pos = pos;
                break;
            case ST_ESCAPED_VALUE:
                break;
            default:
                ERROR("unexpected equal sign at %lu. hdr: %s", pos, auth_hdr.data());
                return false;
            }
            break;
        case ',':
            if(!process_attribute_end(true))
                return false;
            break;
        case ' ':
            switch(st) {
            case ST_START:
                st = ST_NAME_SKIP_WS_BEFORE;
                break;
            case ST_NAME:
                st = ST_NAME_SKIP_WS_AFTER;
                name_end_pos = pos;
                break;
            case ST_VALUE:
                st = ST_VALUE_SKIP_WS_AFTER;
                value_end_pos = pos;
                break;
            case ST_NAME_SKIP_WS_BEFORE:
            case ST_NAME_SKIP_WS_AFTER:
            case ST_VALUE_SKIP_WS_BEFORE:
            case ST_VALUE_SKIP_WS_AFTER:
            case ST_ESCAPED_VALUE:
                break;
            default:
                ERROR("unexpected space at %lu. hdr: %s", pos, auth_hdr.data());
                return false;
            }
            break;
        default:
            switch(st) {
            case ST_START:
                st = ST_NAME;
                name_start_pos = pos;
                break;
            case ST_NAME_SKIP_WS_BEFORE:
                st = ST_NAME;
                name_start_pos = pos;
                break;
            case ST_VALUE_SKIP_WS_BEFORE:
                st = ST_VALUE;
                value_start_pos = pos;
                break;
            case ST_ESCAPED_VALUE:
                last_c = c;
                break;
            case ST_VALUE:
            case ST_NAME:
                break;
            default:
                ERROR("unexpected '%c' at %lu. hdr: %s", c, pos, auth_hdr.data());
                return false;
            }
            break;
        } //switch(c)
        pos++;
    } //while(pos < auth_hdr.length())

    process_attribute_end(false);

    /*for(const auto &p : attributes) {
        DBG("attribute '%s': '%s'", p.first.data(),p.second.data());
    }*/

    realm = find_attribute("realm");
    nonce = find_attribute("nonce");
    opaque = find_attribute("opaque");
    algorithm = find_attribute("algorithm");
    qop = find_attribute("qop");

    return (realm.length() && nonce.length());
}

AmSessionEventHandler* UACAuthFactory::getHandler(AmSession* s)
{
    CredentialHolder* c = dynamic_cast<CredentialHolder*>(s);
    if(c != nullptr) {
        return getHandler(s->dlg, c);
    } else {
        DBG("no credentials for new session. not enabling auth session handler.");
    }
    return nullptr;
}

AmSessionEventHandler* UACAuthFactory::getHandler(AmBasicSipDialog* dlg, CredentialHolder* c)
{
    return new UACAuth(dlg, c->getCredentials());
}

UACAuth::UACAuth(AmBasicSipDialog* dlg, UACAuthCred* cred)
  : AmSessionEventHandler(),
    credential(cred),
    dlg(dlg),
    nonce_count(0),
    nonce_reuse(false)
{ }

bool UACAuth::process(AmEvent*)
{
    return false;
}

bool UACAuth::onSipEvent(AmSipEvent*)
{
    return false;
}

bool UACAuth::onSipRequest(const AmSipRequest&)
{
    return false;
}

bool UACAuth::onSipReply(
    const AmSipRequest&, const AmSipReply& reply,
    AmBasicSipDialog::Status old_dlg_status)
{
    CLASS_DBG("UACAuth::onSipReply() code:%d", reply.code);
    bool processed = false;
    bool proxy_auth;

    if(reply.code == 407) {
        proxy_auth = true;
    } else if(reply.code == 401) {
        proxy_auth = false;
    } else {
        if(reply.cseq >= 200)
            sent_requests.erase(reply.cseq);
        return false;
    }

    DBG("SIP reply with code:%d cseq:%d", reply.code, reply.cseq);
    auto ri = sent_requests.find(reply.cseq);
    if(ri == sent_requests.end()) {
        DBG("cseq:%d not found in sent_requests", reply.cseq);
        return false;
    }

    DBG("processing %s reply:%d. nonce_reuse:%d",
        reply.cseq_method.data(), reply.code, nonce_reuse);

    string auth_hdr = proxy_auth ?
        getHeader(reply.hdrs, SIP_HDR_PROXY_AUTHENTICATE, true) :
        getHeader(reply.hdrs, SIP_HDR_WWW_AUTHENTICATE, true);

    if(!nonce_reuse &&
        (proxy_auth ?
            getHeader(ri->second.hdrs, SIP_HDR_PROXY_AUTHORIZATION, true).length() :
            getHeader(ri->second.hdrs, SIP_HDR_AUTHORIZATION, true).length()))
    {
        DBG("Authorization failed. got 401/407 after the auth header sent");
    } else {
        string result;
        string auth_uri = dlg->getRemoteUri();

        nonce_reuse = false;

        if(!do_auth(reply.code, auth_hdr,
                    ri->second.method,
                    auth_uri, &(ri->second.body), result))
        {
            goto out;
        }

        DBG("result: %s", result.data());

        string hdrs = ri->second.hdrs;
        // strip other auth headers
        if(proxy_auth) {
            removeHeader(hdrs, SIP_HDR_PROXY_AUTHORIZATION);
        } else {
            removeHeader(hdrs, SIP_HDR_AUTHORIZATION);
        }

        if (hdrs == "\r\n" || hdrs == "\r" || hdrs == "\n")
           hdrs = result;
        else
           hdrs.insert(hdrs.begin(), result.begin(), result.end());

        if(dlg->getStatus() < AmSipDialog::Connected &&
            ri->second.method != SIP_METH_BYE)
        {
            // reset remote tag so remote party
            // thinks its new dlg
            dlg->setRemoteTag(string());

            if(AmConfig.proxy_sticky_auth) {
                // update remote URI to resolved IP
                auto hpos = auth_uri.find("@");
                if (hpos != string::npos && reply.remote_ip.length())
                {
                    string remote_uri =
                       auth_uri.substr(0, hpos+1) +
                        reply.remote_ip + ":"+int2str(reply.remote_port);
                    dlg->setRemoteUri(remote_uri);
                    DBG("updated remote URI to '%s'", remote_uri.c_str());
                }
            }
        }

        int flags = SIP_FLAGS_VERBATIM | SIP_FLAGS_NOAUTH;
        size_t skip = 0, pos1, pos2, hdr_start;
        if(findHeader(hdrs, SIP_HDR_CONTACT, skip, pos1, pos2, hdr_start) ||
            findHeader(hdrs, "m", skip, pos1, pos2, hdr_start))
        {
            flags |= SIP_FLAGS_NOCONTACT;
        }

        reply.tt.lock_bucket();
        const sip_trans *t = reply.tt.get_trans();
        sip_target_set *targets_copy = nullptr;
        if(t && t->targets) {
            targets_copy = new sip_target_set(*t->targets);
            targets_copy->prev();
        }
        reply.tt.unlock_bucket();

        // resend request
        if(dlg->sendRequest(
            ri->second.method,
            &(ri->second.body),
            hdrs, ri->second.flags | flags,
            nullptr, targets_copy) != 0)
        {
            ERROR("failed to send authenticated request");
            goto out;
        }

        DBG("authenticated request successfully sent");

        processed = true;

        // undo SIP dialog status change
        if(dlg->getStatus() != old_dlg_status)
            dlg->setStatus(old_dlg_status);
    }
out:
    sent_requests.erase(ri);

    return processed;
}

bool UACAuth::onSendRequest(AmSipRequest& req, int& flags)
{
    // add authentication header if nonce is already there
    string result;
    CLASS_DBG("onSendRequest(). nonce:'%s'", challenge.nonce.data());
    if(!(flags & SIP_FLAGS_NOAUTH) &&
       !challenge.nonce.empty() &&
       do_auth(challenge, challenge_code,
               req.method, dlg->getRemoteUri(), &req.body, result))
    {
        // add headers
        if (req.hdrs == "\r\n" || req.hdrs == "\r" || req.hdrs == "\n")
            req.hdrs = result;
        else
            req.hdrs.insert(req.hdrs.begin(), result.begin(), result.end());

        nonce_reuse = true;
    } else {
        nonce_reuse = false;
    }

    DBG("adding %d to list of sent requests. nonce_reuse:%d", req.cseq, nonce_reuse);
    sent_requests[req.cseq] = SIPRequestInfo(
        req.method, &req.body, req.hdrs, flags//,
        // TODO: fix this!!!
        /*dlg->getOAState()*/);
    return false;
}


bool UACAuth::onSendReply(const AmSipRequest&, AmSipReply&, int&)
{
    return false;
}

inline void w_MD5Update(MD5_CTX *ctx, const string& s)
{
    MD5Update(ctx, (const unsigned char *)s.data(), s.length());
}

/** time-constant string compare function, but leaks timing of length mismatch */
bool UACAuth::tc_isequal(const std::string& s1, const std::string& s2)
{
    if(s1.length() != s2.length())
        return false;

    bool res = false;

    for(size_t i=0;i<s1.length();i++)
        res |= s1[i]^s2[i];

    return !res;
}

/** time-constant string compare function, but leaks timing of length mismatch */
bool UACAuth::tc_isequal(const char* s1, const char* s2, size_t len)
{
    bool res = false;

    for(size_t i=0;i<len;i++)
        res |= s1[i]^s2[i];

    return !res;
}

bool UACAuth::do_auth(
    const unsigned int code, const string& auth_hdr,
    const string& method, const string& uri,
    const AmMimeBody* body, string& result)
{
    if(!auth_hdr.length()) {
        DBG("empty auth header.");
        return false;
    }

    if(!challenge.parse(auth_hdr)) {
        DBG("error parsing auth header '%s'", auth_hdr.c_str());
        return false;
    }

    challenge_code = code;

    return do_auth(challenge, code, method, uri, body, result);
}


bool UACAuth::do_auth(
    const UACAuthDigestChallenge& challenge,
    const unsigned int code,
    const string& method, const string& uri,
    const AmMimeBody* body, string& result)
{
    if((challenge.algorithm.length()) &&
       (challenge.algorithm != "MD5") &&
       (challenge.algorithm != "md5"))
    {
        DBG("unsupported algorithm: '%s'", challenge.algorithm.c_str());
        return false;
    }

    DBG("realm='%s', nonce='%s', qop='%s'",
        challenge.realm.c_str(), 
        challenge.nonce.c_str(),
        challenge.qop.c_str());

    if(credential->realm.length()
       && (credential->realm != challenge.realm))
    {
        DBG("authentication realm mismatch ('%s' vs '%s').",
            credential->realm.c_str(),challenge.realm.c_str());
    }

    HASHHEX ha1;
    HASHHEX ha2;
    HASHHEX hentity;
    HASHHEX response;
    bool qop_auth=false;
    bool qop_auth_int=false;
    string cnonce;
    string qop_value;

    if(!challenge.qop.empty()) {

        qop_auth = key_in_list(challenge.qop,"auth");
        qop_auth_int = key_in_list(challenge.qop,"auth-int");

        if(qop_auth || qop_auth_int) {
            cnonce = int2hex(get_random(),true);
            if(challenge.nonce == nonce)
                nonce_count++;
            else
                nonce_count = 1;

            if(qop_auth_int) {
                string body_str;
                if(body)
                    body->print(body_str);
                uac_calc_hentity(body_str,hentity);
                qop_value = "auth-int";
            } else {
                qop_value = "auth";
            }
        }
    }

    /* do authentication */
    uac_calc_HA1( challenge, credential, cnonce, ha1);
    uac_calc_HA2( method, uri, challenge, qop_auth_int ? hentity : nullptr, ha2);
    uac_calc_response( ha1, ha2, challenge, cnonce, qop_value, int2hex(nonce_count), response);
    DBG("calculated response = %s", response);

    // compile auth response
    result = ((code==401) ?
        SIP_HDR_COLSP(SIP_HDR_AUTHORIZATION) :
        SIP_HDR_COLSP(SIP_HDR_PROXY_AUTHORIZATION));

    result += "Digest username=\"" + credential->user + "\", "
        "realm=\"" + challenge.realm + "\", "
        "nonce=\"" + challenge.nonce + "\", "
        "uri=\"" + uri + "\", ";

    if (challenge.opaque.length())
        result += "opaque=\"" + challenge.opaque + "\", ";

    if (!qop_value.empty())
        result += "qop=" + qop_value + ", "
                  "cnonce=\"" + cnonce + "\", "
                  "nc=" + int2hex(nonce_count,true) + ", ";

    result += "response=\"" + string((char*)response) + "\", algorithm=MD5" CRLF;

    DBG("Auth req hdr: '%s'", result.c_str());

    return true;
}

/* 
 * calculate H(A1)
 */
void UACAuth::uac_calc_HA1(
    const UACAuthDigestChallenge& challenge,
    const UACAuthCred* _credential,
    string /*cnonce*/,
    HASHHEX sess_key)
{
    if (nullptr == _credential)
        return;

    MD5_CTX Md5Ctx;
    HASH HA1;

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, _credential->user);
    w_MD5Update(&Md5Ctx, ":");
    // use realm from challenge
    w_MD5Update(&Md5Ctx, challenge.realm);
    w_MD5Update(&Md5Ctx, ":");
    w_MD5Update(&Md5Ctx, _credential->pwd);
    MD5Final(HA1, &Md5Ctx);

    // MD5sess ...not supported
    // 	if ( flags & AUTHENTICATE_MD5SESS )
    // 	  {
    // 		MD5Init(&Md5Ctx);
    // 		MD5Update(&Md5Ctx, HA1, HASHLEN);
    // 		MD5Update(&Md5Ctx, ":", 1);
    // 		MD5Update(&Md5Ctx, challenge.nonce.c_str(), challenge.nonce.length());
    // 		MD5Update(&Md5Ctx, ":", 1);
    // 		MD5Update(&Md5Ctx, cnonce.c_str(), cnonce.length());
    // 		MD5Final(HA1, &Md5Ctx);
    // 	  }; 
    cvt_hex(HA1, sess_key);
}


/* 
 * calculate H(A2)
 */
void UACAuth::uac_calc_HA2(
    const string& method, const string& uri,
    const UACAuthDigestChallenge& /*challenge*/,
    HASHHEX hentity,
    HASHHEX HA2Hex)
{
    static unsigned char hc[1] = {':'};
    MD5_CTX Md5Ctx;
    HASH HA2;

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, method);
    MD5Update(&Md5Ctx, hc, 1);
    w_MD5Update(&Md5Ctx, uri);

    if( hentity != 0 )
    {
        MD5Update(&Md5Ctx, hc, 1);
        MD5Update(&Md5Ctx, hentity, HASHHEXLEN);
    }

    MD5Final(HA2, &Md5Ctx);
    cvt_hex(HA2, HA2Hex);
}

/*
 * calculate H(body)
 */
void UACAuth::uac_calc_hentity(const string& body, HASHHEX hentity)
{
    MD5_CTX Md5Ctx;
    HASH h;

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, body);
    MD5Final(h, &Md5Ctx);
    cvt_hex(h,hentity);
}

/* 
 * calculate request-digest/response-digest as per HTTP Digest spec 
 */
void UACAuth::uac_calc_response(HASHHEX ha1, HASHHEX ha2,
    const UACAuthDigestChallenge& challenge, const string& cnonce,
    const string& qop_value, const string& nonce_count_str, HASHHEX response)
{
    static unsigned char hc[1] = {':'};
    MD5_CTX Md5Ctx;
    HASH RespHash;

    MD5Init(&Md5Ctx);
    MD5Update(&Md5Ctx, ha1, HASHHEXLEN);
    MD5Update(&Md5Ctx, hc, 1);
    w_MD5Update(&Md5Ctx, challenge.nonce);
    MD5Update(&Md5Ctx, hc, 1);


    if(!qop_value.empty()) {
        w_MD5Update(&Md5Ctx, nonce_count_str);
        MD5Update(&Md5Ctx, hc, 1);
        w_MD5Update(&Md5Ctx, cnonce);
        MD5Update(&Md5Ctx, hc, 1);
        w_MD5Update(&Md5Ctx, qop_value);
        MD5Update(&Md5Ctx, hc, 1);
    }

    MD5Update(&Md5Ctx, ha2, HASHHEXLEN);
    MD5Final(RespHash, &Md5Ctx);
    cvt_hex(RespHash, response);
}

/** calculate nonce: time-stamp H(time-stamp private-key) */
string UACAuth::calcNonce()
{
    string result;
    HASHHEX hash;
    MD5_CTX Md5Ctx;
    HASH RespHash;

    time_t now = time(nullptr);
    result = int2hex(now, true);

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, result);
    w_MD5Update(&Md5Ctx, server_nonce_secret);
    MD5Final(RespHash, &Md5Ctx);
    cvt_hex(RespHash, hash);

    return result+string((const char*)hash);
}

/** check nonce integrity. @return true if correct */
UACAuth::nonce_check_result_t UACAuth::checkNonce(const string& nonce)
{
    HASHHEX hash;
    MD5_CTX Md5Ctx;
    HASH RespHash;

#define INT_HEX_LEN int(2*sizeof(int))

    if(nonce.size() != INT_HEX_LEN+HASHHEXLEN) {
        DBG("wrong nonce length (expected %u, got %zd)", INT_HEX_LEN+HASHHEXLEN, nonce.size());
        return NCR_WRONG;
    }

    unsigned int nonce_time = 0;
    if(hex2int(std::string(nonce.c_str(), INT_HEX_LEN), nonce_time)) {
        DBG("wrong nonce value(error hex to int conversion)");
        return NCR_WRONG;
    }
    nonce_time += nonce_expire;
    time_t now = time(nullptr);
    if(nonce_time < now) {
        DBG("wrong nonce value(nonce expired)");
        return NCR_EXPIRED;
    }

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, nonce.substr(0,INT_HEX_LEN));
    w_MD5Update(&Md5Ctx, server_nonce_secret);
    MD5Final(RespHash, &Md5Ctx);
    cvt_hex(RespHash, hash);

    return tc_isequal((const char*)hash, &nonce[INT_HEX_LEN], HASHHEXLEN) ?
        NCR_OK : NCR_WRONG;
}

void UACAuth::setServerSecret(const string& secret) {
    server_nonce_secret = secret;
    DBG("Server Nonce secret set");
}

void UACAuth::setAllowedQops(int allowed_qop_mask) {
    allowed_qop_types = allowed_qop_mask;
    if(allowed_qop_types & QOP_AUTH) {
        qop_str_value = "auth";
    }
    if(allowed_qop_types & QOP_AUTH_INT) {
        if(!qop_str_value.empty()) qop_str_value += ",";
            qop_str_value += "auth-int";
    }
}

void UACAuth::setNonceExpire(int nonce_expire)
{
    UACAuth::nonce_expire = nonce_expire;
}

void UACAuth::fetchAuthentication(const AmSipRequest *req, AmArg &ret)
{
    string auth_hdr = getHeader(req->hdrs, "Authorization");

    if (auth_hdr.size()) {
        UACAuthDigestChallenge r_challenge;

        if (r_challenge.parse(auth_hdr)) {
            ret["realm"] = r_challenge.realm;
            ret["username"] = r_challenge.find_attribute("username");
            ret["uri"] = r_challenge.find_attribute("uri");
        }
    }
}

void UACAuth::checkAuthentication(
    const AmSipRequest* req,  const vector<string>& realms, const string& user,
    const string& pwd,
    const string& default_realm,
    AmArg& ret)
{
    if(req->method == SIP_METH_ACK || req->method == SIP_METH_CANCEL) {
        DBG("letting pass %s request without authentication", req->method.c_str());
        ret.push(200);
        ret.push("OK");
        ret.push("");
        return;
    }

    string auth_hdr = getHeader(req->hdrs, "Authorization");
    bool authenticated = false;
    string internal_reason;
    int internal_code = UACAuthGeneric;
    string r_realm;

    if(auth_hdr.size()) {
        UACAuthDigestChallenge r_challenge;

        if(!r_challenge.parse(auth_hdr)) {
            DBG("Auth: failed to parse Authorization header");
            internal_code = UACAuthHeaderParse;
            internal_reason = "Parsing error";
            goto auth_end;
        }

        string r_response = r_challenge.find_attribute("response");
        string r_username = r_challenge.find_attribute("username");
        string r_uri = r_challenge.find_attribute("uri");
        string r_cnonce = r_challenge.find_attribute("cnonce");
        r_realm = r_challenge.realm;

        DBG("got realm '%s' nonce '%s', qop '%s', response '%s', username '%s' uri '%s' cnonce '%s'",
            r_challenge.realm.c_str(), r_challenge.nonce.c_str(), r_challenge.qop.c_str(),
            r_response.c_str(), r_username.c_str(), r_uri.c_str(), r_cnonce.c_str() );

        if(std::find(realms.begin(), realms.end(), r_realm) == realms.end()) {
            DBG("Auth: unknown realm '%s'", r_realm.c_str());
            internal_code = UACAuthRealmMismatch;
            internal_reason = "Realm mismatch";
            goto auth_end;
        }

        if(r_response.size() != HASHHEXLEN) {
            DBG("Auth: response length mismatch (wanted %u hex chars): '%s'", HASHHEXLEN, r_response.c_str());
            internal_code = UACAuthResponseLength;
            internal_reason = "Response length mismatch";
            goto auth_end;
        }

        if(user != r_username) {
            DBG("Auth: user mismatch: '%s' vs '%s'", user.c_str(), r_username.c_str());
            internal_code = UACAuthUserMismatch;
            internal_reason = "User mismatch";
            goto auth_end;
        }

        nonce_check_result_t ret = checkNonce(r_challenge.nonce);
        if(ret == NCR_WRONG) {
            DBG("Auth: incorrect nonce '%s'", r_challenge.nonce.c_str());
            internal_code = UACAuthNonceIncorrect;
            internal_reason = "Incorrect nonce";
            goto auth_end;
        } else if(ret == NCR_EXPIRED) {
            DBG("Auth: nonce '%s' expired", r_challenge.nonce.c_str());
            internal_code = UACAuthNonceExpired;
            internal_reason = "Nonce expired";
            goto auth_end;
        }

        // we don't check the URI
        // if (r_uri != req->r_uri) {
        //   DBG("Auth: incorrect URI in request: '%s'", r_challenge.nonce.c_str());
        //   goto auth_end;
        // }

        UACAuthCred credential;
        credential.user = user;
        credential.pwd = pwd;

        unsigned int client_nonce_count = 1;
        string client_nonce_count_str(default_nonce_count);
        HASHHEX ha1;
        HASHHEX ha2;
        HASHHEX hentity;
        HASHHEX response;
        bool    qop_auth=false;
        bool    qop_auth_int=false;
        string  qop_value;

        if(!r_challenge.qop.empty()) {
            if(r_challenge.qop == "auth")
                qop_auth = true;
            else if(r_challenge.qop == "auth-int")
                qop_auth_int = true;

            if(qop_auth || qop_auth_int) {
                // get nonce count from request
                client_nonce_count_str = r_challenge.find_attribute("nc");
                if(hex2int(client_nonce_count_str, client_nonce_count)) {
                    DBG("Error parsing nonce_count '%s'", client_nonce_count_str.c_str());
                    internal_code = UACAuthNonceCountParse;
                    internal_reason = "Error parsing nonce_count";
                    goto auth_end;
                }

                DBG("got client_nonce_count %u", client_nonce_count);

                // auth-int? calculate hentity
                if(qop_auth_int) {
                    string body_str;
                    if(!req->body.empty())
                        req->body.print(body_str);
                    uac_calc_hentity(body_str, hentity);
                    qop_value = "auth-int";
                } else {
                    qop_value = "auth";
                }
            }
        }

        uac_calc_HA1(r_challenge, &credential, r_cnonce, ha1);
        uac_calc_HA2(req->method, r_uri, r_challenge, qop_auth_int ? hentity : nullptr, ha2);
        uac_calc_response( ha1, ha2, r_challenge, r_cnonce, qop_value, client_nonce_count_str, response);
        DBG("calculated our response vs request: '%s' vs '%s'", response, r_response.c_str());

        if(tc_isequal((const char*)response, r_response.c_str(), HASHHEXLEN)) {
            DBG("Auth: authentication successfull");
            internal_reason = "Response matched";
            authenticated = true;
        } else {
            DBG("Auth: authentication NOT successfull");
            internal_code = UACAuthResponseNotMatched;
            internal_reason = "Response NOT matched";
        }
    } else {
        internal_code = UACAuthNoAuthHeader;
        internal_reason = "no Authorization header";
    }

  auth_end:
    if(authenticated) {
        ret.push(200);
        ret.push("OK");
        ret.push("");
    } else {
        ret.push(401);
        ret.push("Unauthorized");
        if(!r_realm.empty() && internal_code != UACAuthRealmMismatch) {
            ret.push(getChallengeHeader(r_realm));
        } else {
            ret.push(getChallengeHeader(default_realm));
        }
    }
    ret.push(internal_reason);
    ret.push(internal_code);
}

string UACAuth::getChallengeHeader(const string& realm)
{
    return SIP_HDR_COLSP(SIP_HDR_WWW_AUTHENTICATE) "Digest "
           "realm=\""+realm+"\", "
           "qop=\"" + qop_str_value + "\", "
           "nonce=\""+calcNonce()+"\"\r\n";
}

void UACAuth::checkAuthenticationByHA1(
    const AmSipRequest* req, const string& realm,
    const string& user, const string& HA1, AmArg& ret)
{
    if(req->method == SIP_METH_ACK || req->method == SIP_METH_CANCEL)
    {
        DBG("letting pass %s request without authentication", req->method.c_str());
        ret.push(200);
        ret.push("OK");
        ret.push("");
        return;
    }

    string auth_hdr = getHeader(req->hdrs, "Authorization");
    bool authenticated = false;

    if(auth_hdr.size()) {
        UACAuthDigestChallenge r_challenge;

        if(!r_challenge.parse(auth_hdr)) {
            DBG("Auth: failed to parse Authorization header");
            goto auth_end;
        }

        string r_response = r_challenge.find_attribute("response");
        string r_username = r_challenge.find_attribute("username");
        string r_uri = r_challenge.find_attribute("uri");
        string r_cnonce = r_challenge.find_attribute("cnonce");

        DBG("got realm '%s' nonce '%s', qop '%s', response '%s', username '%s' uri '%s' cnonce '%s'",
            r_challenge.realm.c_str(), r_challenge.nonce.c_str(), r_challenge.qop.c_str(),
            r_response.c_str(), r_username.c_str(), r_uri.c_str(), r_cnonce.c_str() );

        if(r_response.size() != HASHHEXLEN) {
            DBG("Auth: response length mismatch (wanted %u hex chars): '%s'", HASHHEXLEN, r_response.c_str());
            goto auth_end;
        }

        if(realm != r_challenge.realm) {
            DBG("Auth: realm mismatch: required '%s' vs '%s'", realm.c_str(), r_challenge.realm.c_str());
            goto auth_end;
        }

        if(user != r_username) {
            DBG("Auth: user mismatch: '%s' vs '%s'", user.c_str(), r_username.c_str());
            goto auth_end;
        }

        nonce_check_result_t ret = checkNonce(r_challenge.nonce);
        if(ret == NCR_WRONG) {
            DBG("Auth: incorrect nonce '%s'", r_challenge.nonce.c_str());
            goto auth_end;
        } else if(ret == NCR_EXPIRED) {
            DBG("Auth: nonce '%s' expired", r_challenge.nonce.c_str());
            goto auth_end;
        }

        // we don't check the URI
        // if (r_uri != req->r_uri) {
        //   DBG("Auth: incorrect URI in request: '%s'", r_challenge.nonce.c_str());
        //   goto auth_end;
        // }

        unsigned int client_nonce_count = 1;
        string nonce_count_str(default_nonce_count);
        HASHHEX ha1;
        strncpy((char *)ha1, HA1.c_str(), HASHHEXLEN);
        HASHHEX ha2;
        HASHHEX hentity;
        HASHHEX response;
        bool    qop_auth=false;
        bool    qop_auth_int=false;
        string  qop_value;

        if(!r_challenge.qop.empty()) {
            if(r_challenge.qop == "auth")
                qop_auth = true;
            else if(r_challenge.qop == "auth-int")
                qop_auth_int = true;

            if(qop_auth || qop_auth_int) {

                // get nonce count from request
                string nonce_count_str = r_challenge.find_attribute("nc");
                if(hex2int(nonce_count_str, client_nonce_count)) {
                    DBG("Error parsing nonce_count '%s'", nonce_count_str.c_str());
                    goto auth_end;
                }

                DBG("got client_nonce_count %u", client_nonce_count);

                // auth-int? calculate hentity
                if(qop_auth_int){
                    string body_str;
                    if(!req->body.empty())
                        req->body.print(body_str);
                    uac_calc_hentity(body_str, hentity);
                    qop_value = "auth-int";
                } else {
                    qop_value = "auth";
                }
            }
        }

        uac_calc_HA2(req->method, r_uri, r_challenge, qop_auth_int ? hentity : NULL, ha2);
        uac_calc_response( ha1, ha2, r_challenge, r_cnonce, qop_value, nonce_count_str, response);
        DBG("calculated our response vs request: '%s' vs '%s'", response, r_response.c_str());

        if(!strncmp((const char*)response, r_response.c_str(), HASHHEXLEN)) {
            DBG("Auth: authentication successfull");
            authenticated = true;
        } else {
            DBG("Auth: authentication NOT successfull");
        }
    }

  auth_end:
    if (authenticated) {
        ret.push(200);
        ret.push("OK");
        ret.push("");
    } else {
        ret.push(401);
        ret.push("Unauthorized");
        ret.push(SIP_HDR_COLSP(SIP_HDR_WWW_AUTHENTICATE) "Digest "
                 "realm=\""+realm+"\", "
                 "qop=\"auth,auth-int\", "
                 "nonce=\""+calcNonce()+"\"\r\n");
    }
}
