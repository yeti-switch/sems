#include "OptionsSingleProbe.h"

#include "AmArgValidator.h"
#include "AmUriParser.h"
#include "AmSession.h"
#include "sip/parse_via.h"
#include "sip/parse_uri.h"

vector<string> ProbersMetricGroup::metrics_keys_names = {
    "options_probe_last_reply_code",
    "options_probe_last_reply_delay_ms"
};

/*vector<string> ProbersMetricGroup::metrics_help_strings = {
    ""
};*/

static bool transport_protocol_validator(const AmArg &a) {
    int id = a.asInt();
    if(id < sip_transport::UDP || id > sip_transport::WSS) {
        ERROR("invalid SIP transport id %d. expected values within interval [%d,%d]",
              id, sip_transport::UDP, sip_transport::WSS);
        return false;
    }
    return true;
};

static bool sip_schema_validator(const AmArg &a) {
    int id = a.asInt();
    if(id < sip_uri::SIP || id > sip_uri::SIPS) {
        ERROR("invalid SIP schema id %d. expected values within interval [%d,%d]",
              id, sip_uri::SIP, sip_uri::SIPS);
        return false;
    }
    return true;
};

static AmArgHashValidator SipProbeAmArgValidator({
    {"id", true, {AmArg::Int}},
    {"name", true, {AmArg::CStr}},
    {"ruri_domain", true, {AmArg::CStr}},
    {"from_uri", true, {AmArg::CStr}},
    {"to_uri", true, {AmArg::CStr}},
    {"interval", true, {AmArg::Int}},
    {"ruri_username", false, {AmArg::CStr}},
    {"transport_protocol_id", false, {AmArg::Int}, transport_protocol_validator},
    {"sip_schema_id", false, {AmArg::Int}, sip_schema_validator},
    {"contact_uri", false, {AmArg::CStr}},
    {"proxy", false, {AmArg::CStr}},
    {"proxy_transport_protocol_id", false, {AmArg::Int}, transport_protocol_validator},
    {"append_headers", false, {AmArg::CStr}},
    {"sip_interface_name", false, {AmArg::CStr}},
    {"auth_username", false, {AmArg::CStr}},
    {"auth_password", false, {AmArg::CStr}}
});

SipSingleProbe::SipSingleProbe()
  : transport_protocol_id(sip_transport::UDP),
    proxy_transport_protocol_id(sip_transport::UDP),
    sip_schema_id(sip_uri::SIP),
    active_dialog(false),
    dlg(this)
{}

void SipSingleProbe::patch_transport(string &uri, int transport_protocol_id)
{
    switch(transport_protocol_id) {
    case sip_transport::UDP: break;
    case sip_transport::TCP:
    case sip_transport::TLS: {
        auto transport_name = transport_str(transport_protocol_id);
        DBG("%s patch uri to use %.*s transport. current value is: '%s'",
            tag.c_str(),transport_name.len, transport_name.s, uri.c_str());
        AmUriParser parser;
        parser.uri = uri;
        if(!parser.parse_uri()) {
            ERROR("%s Error parsing '%s' for protocol patching to %.*s. leave it as is",
                 tag.c_str(),parser.uri.c_str(), transport_name.len, transport_name.s);
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
                          tag.c_str(),v.size()>1?v[1].c_str():"");
                    can_patch = false;
                    break;
                }
            }
            if(can_patch) {
                parser.uri_param+=";transport=";
                parser.uri_param+=c2stlstr(transport_name);
                uri = parser.uri_str();
                DBG("%s uri patched to: '%s'",
                    tag.c_str(),uri.c_str());
            }
        } else {
            parser.uri_param = "transport=";
            parser.uri_param+=c2stlstr(transport_name);
            uri = parser.uri_str();
            DBG("%s uri patched to: '%s'",
                tag.c_str(),uri.c_str());
        }
    } break;
    default:
        ERROR("%s transport_protocol_id %d is not supported yet. ignore it",
              tag.c_str(),transport_protocol_id);
    }
}

string SipSingleProbe::preprocess_append_headers()
{
    string s;
    size_t p = 0;
    bool is_escaped = false;
    while (p<append_headers.length()) {
        if(is_escaped) {
            switch (append_headers[p]) {
            case 'r': s += '\r'; break;
            case 'n': s += '\n'; break;
            case 't': s += '\t'; break;
            default: s += append_headers[p]; break;
            }
            is_escaped = false;
        } else {
            if (append_headers[p]=='\\') {
                if (p==append_headers.length()-1) {
                    s += '\\'; // add single \ at the end
                } else {
                    is_escaped = true;
                }
            } else {
                s+=append_headers[p];
            }
        }
        p++;
    }
    //ensure CRLF
    if(s.size() > 2 &&
       (s[s.size()-2] != '\r' ||
        s[s.size()-1] != '\n'))
    {
        while ((s[s.size()-1] == '\r') ||
               (s[s.size()-1] == '\n'))
        {
            s.erase(s.size()-1);
        }
        s += "\r\n";
    }
    return s;
}

bool SipSingleProbe::initFromAmArg(const AmArg &a)
{
#define ASSIGN_MANDATORY_STR(name) name = a[#name].asCStr();
#define ASSIGN_MANDATORY_INT(name) name = a[#name].asInt();
#define ASSIGN_OPTIONAL_STR(name)  if(a.hasMember(#name)) name = a[#name].asCStr();
#define ASSIGN_OPTIONAL_INT(name) if(a.hasMember(#name)) name = a[#name].asInt();

    if(!SipProbeAmArgValidator.validate(a)) {
        DBG("data validation failed");
        return false;
    }
    ASSIGN_MANDATORY_INT(id);
    ASSIGN_MANDATORY_STR(name);
    ASSIGN_MANDATORY_STR(ruri_domain);
    ASSIGN_MANDATORY_STR(from_uri);
    ASSIGN_MANDATORY_STR(to_uri);
    interval = std::chrono::seconds(a["interval"].asInt());

    ASSIGN_OPTIONAL_STR(ruri_username);
    ASSIGN_OPTIONAL_INT(transport_protocol_id);
    ASSIGN_OPTIONAL_INT(sip_schema_id);
    ASSIGN_OPTIONAL_STR(contact_uri);
    ASSIGN_OPTIONAL_STR(proxy);
    ASSIGN_OPTIONAL_INT(proxy_transport_protocol_id);
    ASSIGN_OPTIONAL_STR(append_headers);
    ASSIGN_OPTIONAL_STR(sip_interface_name);
    ASSIGN_OPTIONAL_STR(auth_username);
    ASSIGN_OPTIONAL_STR(auth_password);

    tag = AmSession::getNewId();

    //process variables
    cred.realm = ruri_domain;
    cred.user = auth_username;
    cred.user = auth_password;

    AmUriParser uri_parser;
    req.method = "OPTIONS";
    req.user = ruri_username;

    uri_parser.uri_host = ruri_domain;
    ensure_ipv6_reference(uri_parser.uri_host);
    if(sip_uri::SIPS==sip_schema_id) {
        uri_parser.uri_scheme = "sips";
    }
    //add transport
    if(sip_transport::UDP!=transport_protocol_id &&
       sip_uri::SIPS!=sip_schema_id)
    {
        uri_parser.uri_param+= "transport=";
        uri_parser.uri_param+= c2stlstr(transport_str(transport_protocol_id));
    }

    req.r_uri = uri_parser.uri_str();
    uri_parser.uri_param.clear();   //remove transport for To/From/Contact headers

    uri_parser.uri_user = ruri_username;

    req.from = uri_parser.nameaddr_str();
    req.from_tag = tag;

    req.to       = req.from;
    req.to_tag   = "";

    req.callid   = AmSession::getNewId();

    if(!contact_uri.empty()) req.from_uri = contact_uri;

    dlg.initFromLocalRequest(req);
    dlg.cseq = 50;

    // set outbound proxy as next hop
    if (!proxy.empty()) {
        dlg.outbound_proxy = proxy;
        patch_transport(dlg.outbound_proxy,proxy_transport_protocol_id);
    } else if (!AmConfig.outbound_proxy.empty()) {
        dlg.outbound_proxy = AmConfig.outbound_proxy;
    }

    if(!sip_interface_name.empty() && sip_interface_name != "default") {
        map<string,unsigned short>::const_iterator name_it =
            AmConfig.sip_if_names.find(sip_interface_name);
        if(name_it == AmConfig.sip_if_names.end()) {
            ERROR("prober %i: specified sip_interface_name '%s' does not exist as a signaling interface",
                id, sip_interface_name.data());
            return false;
        }
        dlg.setOutboundInterface(name_it->second);
        dlg.setOutboundInterface(AT_V4);
        dlg.setOutboundProtoId(0);
    }

    //process contact_uri and append hdrs
    options_flags = SIP_FLAGS_NOCONTACT;
    if(!contact_uri.empty()) {
        options_hdrs = SIP_HDR_COLSP(SIP_HDR_CONTACT) "<" + contact_uri + ">" + CRLF;
    }
    options_hdrs += preprocess_append_headers();

    return true;
}

bool SipSingleProbe::process(timep &now)
{
    //DBG("process probe %i %s %s", id, name.data(), tag.data());
    if(now < recheck_time) return false;

    //DBG("recheck time reached. resend OPTIONS request");

    if(active_dialog) {
        /* timer fired before final reply for prev request received
         * skip request sending and increase recheck time */
        recheck_time += interval;
    }

    if (dlg.sendRequest(req.method, nullptr, options_hdrs, options_flags) < 0) {
        DBG("failed to send OPTIONS. ruri: %s",req.r_uri.data());
    }

    active_dialog = true;
    last_send_time = now;
    recheck_time = now + interval;

    return false;
}

void SipSingleProbe::onSipReply(
    const AmSipRequest& req,
    const AmSipReply& reply,
    AmBasicSipDialog::Status old_status)
{
    DBG("got sip reply. code:%d",reply.code);
    active_dialog = false;
    last_reply_code = reply.code;
    last_reply_reason = reply.reason;
    last_reply_delay = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now() - last_send_time);
    last_reply_contact = !reply.contact.empty() ? reply.contact : getHeader(reply.hdrs, "Contact", "m", false);
}

void SipSingleProbe::getInfo(AmArg &a)
{
    a["id"] = id;
    a["name"]= name;
    a["interval"] = interval.count();
    a["local_tag"] = dlg.getLocalTag();

    a["ruri"] =  dlg.getRemoteUri();
    a["from"] =  dlg.getLocalParty();
    a["to"] =  dlg.getRemoteParty();
    a["contact"] =  contact_uri;
    a["proxy"] = dlg.outbound_proxy;
    a["append_headers"] = append_headers;
    a["sip_interface_name"] = sip_interface_name;

    a["last_reply_code"] = last_reply_code;
    a["last_reply_reason"] = last_reply_reason;
    a["last_reply_contact"] = last_reply_contact;
    a["last_reply_delay_ms"] = last_reply_delay.count();
}

void SipSingleProbe::serializeStats(map<string, string> &labels, unsigned long long *values) const
{
    labels["id"] = std::to_string(id);
    labels["name"] = name;
    labels["interval"] = std::to_string(interval.count());
    labels["local_tag"] = dlg.getLocalTag();
    labels["ruri"] =  dlg.getRemoteUri();
    labels["from"] =  dlg.getLocalParty();
    labels["to"] =  dlg.getRemoteParty();

    values[ProbersMetricGroup::PROBE_VALUE_LAST_REPLY_CODE] = last_reply_code;
    values[ProbersMetricGroup::PROBE_VALUE_LAST_REPLY_DELAY_MS] = last_reply_delay.count();
}
