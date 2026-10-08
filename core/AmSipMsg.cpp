#include <string.h>
#include <stdlib.h>
#include "AmUtils.h"
#include "AmSipMsg.h"
#include "AmSipHeaders.h"
#include "sip/sip_trans.h"
#include "sip/sip_parser.h"
#include "sip/msg_logger.h"
#include "SipCtrlInterface.h"

#include <sstream>

bool AmSipReply::init(const sip_msg *msg)
{
    return _SipCtrlInterface::sip_msg2am_reply(msg, *this);
}

AmSipRequest::AmSipRequest()
    : _AmSipMsgInDlg()
    , max_forwards(-1)
{
}

bool AmSipRequest::init(const sip_msg *msg, const trans_ticket *tt_)
{
    if (tt_)
        tt = *tt_;
    auto callback = [tt_](const sip_msg *req, int reply_code, const cstring &reason) -> int {
        if (tt_)
            return trans_layer::instance()->send_sf_error_reply(tt_, req, reply_code, reason);
        return 0;
    };
    return _SipCtrlInterface::sip_msg2am_request(msg, callback, *this);
}

string getHeader(const AmSipHeaderMap &hdrs, std::string_view hdr_name, bool single)
{
    if (hdr_name.empty())
        return "";

    auto [it, end] = hdrs.equal_range(hdr_name);
    if (it == end)
        return "";
    if (single)
        return it->second;

    string ret = it->second;
    for (++it; it != end; ++it) {
        ret.append(", ");
        ret.append(it->second);
    }
    return ret;
}

bool hasHeader(const AmSipHeaderMap &hdrs, std::string_view hdr_name)
{
    return hdrs.find(hdr_name) != hdrs.end();
}

bool removeHeader(AmSipHeaderMap &hdrs, std::string_view hdr_name)
{
    auto [it, end] = hdrs.equal_range(hdr_name);
    if (it == end)
        return false;
    hdrs.erase(it, end);
    return true;
}

/** collect trimmed tags of all hdr_name headers and remove these headers from hdrs */
static vector<string> takeOptionTags(AmSipHeaderMap &hdrs, const string &hdr_name)
{
    vector<string> tags;
    auto [first, end] = hdrs.equal_range(hdr_name);
    for (auto it = first; it != end; ++it)
        for (const auto &o : explode(it->second, ","))
            tags.push_back(trim(o, " "));
    hdrs.erase(first, end);
    return tags;
}

/** put tags back as a single hdr_name header */
static void putOptionTags(AmSipHeaderMap &hdrs, const string &hdr_name, const vector<string> &tags)
{
    if (tags.empty())
        return;
    string v;
    for (const auto &t : tags) {
        if (!v.empty())
            v += ", ";
        v += t;
    }
    hdrs.emplace(hdr_name, std::move(v));
}

void addOptionTags(AmSipHeaderMap &hdrs, const string &hdr_name, const vector<string> &tags)
{
    for (auto it = tags.rbegin(); it != tags.rend(); ++it)
        addOptionTag(hdrs, hdr_name, *it);
}

void addOptionTag(AmSipHeaderMap &hdrs, const string &hdr_name, const string &tag)
{
    auto tags = takeOptionTags(hdrs, hdr_name);
    if (std::find(tags.begin(), tags.end(), tag) == tags.end())
        tags.insert(tags.begin(), tag);
    putOptionTags(hdrs, hdr_name, tags);
}

void removeOptionTag(AmSipHeaderMap &hdrs, const string &hdr_name, const string &tag)
{
    auto tags = takeOptionTags(hdrs, hdr_name);
    tags.erase(std::remove(tags.begin(), tags.end(), tag), tags.end());
    putOptionTags(hdrs, hdr_name, tags);
}

/** canonical name for compact forms which sip parser does not resolve itself.
 *  TODO: move into sip parser (parse_header_type) so sip_header::name is canonical for everyone */
static const char *expand_compact_name(const cstring &name)
{
    if (name.len != 1)
        return nullptr;
    switch (name.s[0] | 0x20) {
    case 'a': return "Accept-Contact";
    case 'b': return "Referred-By";
    case 'd': return "Request-Disposition";
    case 'e': return "Content-Encoding";
    case 'j': return "Reject-Contact";
    case 'k': return "Supported";
    case 'n': return "Identity-Info";
    case 'o': return "Event";
    case 'r': return "Refer-To";
    case 's': return "Subject";
    case 'u': return "Allow-Events";
    case 'x': return "Session-Expires";
    case 'y': return "Identity";
    default:  return nullptr;
    }
}

void addHeader(AmSipHeaderMap &hdrs, const sip_header &h)
{
    string value = c2stlstr(h.value);

    // RFC 3261 7.3.1: line break and leading WSP of the folded line are a single SP
    size_t rpos = 0;
    while ((rpos = value.find_first_of("\r\n", rpos)) != string::npos) {
        size_t epos = value.find_first_not_of("\r\n \t", rpos);
        value.replace(rpos, (epos == string::npos ? value.size() : epos) - rpos, " ");
        rpos++;
    }

    if (const char *name = expand_compact_name(h.name))
        hdrs.emplace(name, std::move(value));
    else
        hdrs.emplace(c2stlstr(h.name), std::move(value));
}

string headers2string(const AmSipHeaderMap &hdrs)
{
    string ret;
    for (const auto &[name, value] : hdrs) {
        ret += name;
        ret += ": ";
        ret += value;
        ret += "\r\n";
    }
    return ret;
}

struct format_member {
    const string &member;
    const char   *name;
    format_member(const string &member, const char *name)
        : member(member)
        , name(name)
    {
    }
};

std::ostream &operator<<(std::ostream &out, const format_member &fmt)
{
    if (!fmt.member.empty())
        out << fmt.name << ':' << fmt.member << ";";
    return out;
}

struct format_member_brackets {
    const string &member;
    const char   *name;
    format_member_brackets(const string &member, const char *name)
        : member(member)
        , name(name)
    {
    }
};

std::ostream &operator<<(std::ostream &out, const format_member_brackets &fmt)
{
    if (!fmt.member.empty())
        out << fmt.name << ":[" << fmt.member << "];";
    return out;
}

string AmSipRequest::print() const
{
    std::ostringstream buf;

    buf << method << " [" << format_member(r_uri, "r-uri") << format_member(callid, "i")
        << format_member(int2str(cseq), "cseq") << format_member(from_tag, "l-tag") << format_member(to_tag, "r-tag")
        << format_member_brackets(route, "rtset") << format_member(contact, "m") <<

        format_member_brackets(headers2string(hdrs), "hdr") <<
        // TODO: find some good debug info to print here
        // format_member(content_type, "c") <<
        // format_member_brackets(body, "body") <<

        format_member(user, "user") << format_member(domain, "domain") << format_member(from_uri, "f-uri")
        << format_member(from, "from") << format_member(to, "to") << "]";

    return buf.str();
}

void AmSipRequest::log(msg_logger *logger, msg_sensor *sensor) const
{
    DBG3("AmSipRequest::log(logger = %p,sensor = %p)", logger, sensor);
    tt.lock_bucket();
    const sip_trans *t = tt.get_trans();
    if (t) {
        sip_msg *msg = t->msg;
        if (logger)
            logger->log(msg->buf, msg->len, &msg->remote_ip, &msg->local_ip, msg->u.request->method_str);
        if (sensor)
            sensor->feed(msg->buf, msg->len, &msg->remote_ip, &msg->local_ip, msg_sensor::PTYPE_SIP);
    }
    tt.unlock_bucket();
}

string AmSipReply::print() const
{
    std::ostringstream buf;

    buf << " [" << format_member(int2str(code), "code") << format_member_brackets(reason, "phrase")
        << format_member(callid, "i") << format_member(int2str(cseq), "cseq") <<
        // format_member(method, "cseq meth") <<
        format_member(from_tag, "from-tag") << format_member(to_tag, "to-tag") <<
        // format_member(next_hop, "nhop") <<
        format_member_brackets(route, "rtset") << format_member(contact, "m") <<

        format_member_brackets(headers2string(hdrs), "hdr") <<
        // TODO: find some good debug info to print here
        // format_member(content_type, "c") <<
        // format_memberB(body, "body") <<

        format_member(contact, "contact") << "]";

    return buf.str();
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 2
 * End:
 */
