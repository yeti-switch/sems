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

bool AmSipReply::init(const sip_msg* msg)
{
    return _SipCtrlInterface::sip_msg2am_reply(msg, *this);
}

AmSipRequest::AmSipRequest()
  : _AmSipMsgInDlg(),
    max_forwards(-1)
{}

bool AmSipRequest::init(const sip_msg* msg, const trans_ticket* tt_)
{
    if(tt_) tt = *tt_;
    auto callback = [tt_](const sip_msg* req, int reply_code, const cstring& reason)->int {
        if(tt_)
            return trans_layer::instance()->send_sf_error_reply(tt_, req, reply_code, reason);
        return 0;
    };
    return _SipCtrlInterface::sip_msg2am_request(msg, callback, *this);
}

string getHeader(const string& hdrs,const string& hdr_name, bool single)
{
    if(hdr_name.empty())
        return "";

    size_t pos1;
    size_t pos2;
    size_t pos_s;
    size_t skip = 0;
    string ret = "";

    while(findHeader(hdrs, hdr_name, skip, pos1, pos2, pos_s)) {
        if(skip) {
            ret.append(", ");
        } else {
            if(single) return hdrs.substr(pos1,pos2-pos1);
        }

        ret.append(hdrs.substr(pos1,pos2-pos1));
        skip = pos2+1;
    }
    return ret;
}

string getHeader(const string& hdrs,const string& hdr_name,
                 const string& compact_hdr_name, bool single)
{
    string res = getHeader(hdrs, hdr_name, single);
    if(!res.length())
        return getHeader(hdrs, compact_hdr_name, single);
    return res;
}

bool hasHeader(const string& hdrs,const string& hdr_name)
{
    size_t skip = 0, pos1 = 0, pos2 = 0, hdr_start = 0;
    return findHeader(hdrs, hdr_name, skip, pos1, pos2, hdr_start);
}

bool findHeader(const string& hdrs,const string& hdr_name, const size_t skip,
                size_t& pos1, size_t& pos2, size_t& hdr_start)
{
    if(skip >= hdrs.length()) return false;

    unsigned int p;
    char* hdr = strdup(hdr_name.c_str());
    const char* hdrs_c = hdrs.c_str() + skip;
    char* hdr_c = hdr;
    const char* hdrs_end = hdrs.c_str() + hdrs.length();
    const char* hdr_end = hdr_c + hdr_name.length();

    while(hdr_c != hdr_end) {
        if('A' <= *hdr_c && *hdr_c <= 'Z')
            *hdr_c -= 'A' - 'a';
        hdr_c++;
    }

    while(hdrs_c != hdrs_end) {
        hdr_c = hdr;

        while((hdrs_c != hdrs_end) && (hdr_c != hdr_end)) {
            char c = *hdrs_c;
            if('A' <= *hdrs_c && *hdrs_c <= 'Z')
                c -= 'A' - 'a';
            if(c != *hdr_c)
                break;
            hdr_c++;
            hdrs_c++;
        }

        if(hdr_c == hdr_end) {
            // matched whole of needle.
            // ...all of current header?
            const char* srccol = hdrs_c;
            while(*srccol==' ' || *srccol=='\t')
                srccol++;
            if (*srccol == ':')
                break; // was end of current hdr
            // current hdr just starts with hdr, continue search
        }

        while((hdrs_c != hdrs_end) && (*hdrs_c != '\n'))
            hdrs_c++;

        if(hdrs_c != hdrs_end)
            hdrs_c++;
    }

    if(hdr_c == hdr_end) {
        hdr_start = hdrs_c - hdrs.c_str();

        while((hdrs_c != hdrs_end) && (*hdrs_c == ' '))
            hdrs_c++;

        if((hdrs_c != hdrs_end) && (*hdrs_c == ':')) {
            hdrs_c++;
            while((hdrs_c != hdrs_end) && (*hdrs_c == ' '))
                hdrs_c++;

            p = hdrs_c - hdrs.c_str();
            string::size_type p_end = p;
            while(p_end < hdrs.size() &&
                hdrs[p_end] != '\r' &&
                hdrs[p_end] != '\n')
            {
                p_end++;
            }

            free(hdr);
            // return hdrs.substr(p,p_end-p);
            pos1 = p;
            pos2 = p_end;
            return true;
        }
    }

    free(hdr);
    //    return "";
    return false;
}

bool removeHeader(string& hdrs, const string& hdr_name)
{
    size_t pos1, pos2, hdr_start;
    bool found = false;
    while(findHeader(hdrs, hdr_name, 0, pos1, pos2, hdr_start)) {
        while(pos2 < hdrs.length() &&
            (hdrs[pos2]=='\r' || hdrs[pos2]=='\n'))
        {
            pos2++;
        }

        hdr_start -= hdr_name.length();
        hdrs.erase(hdr_start, pos2 - hdr_start);
        found = true;
    }

    return found;
}

void addOptionTags(string& hdrs, const string& hdr_name, const vector<string>& tags)
{
    for(auto it = tags.rbegin(); it != tags.rend(); ++it)
        addOptionTag(hdrs, hdr_name, *it);
}

void addOptionTag(string& hdrs, const string& hdr_name, const string& tag)
{
    // see if option tag already exists
    string options = getHeader(hdrs, hdr_name);
    if(options.size()) {
        std::vector<string> option_entries = explode(options, ",");
        for(std::vector<string>::iterator it=option_entries.begin();
            it != option_entries.end(); it++)
        {
            if (trim(*it," ") == tag)
            // found - no need to add again
            return;
        }

        // tag not found - add our tag to the (first) hdr_name header
        size_t pos1; size_t pos2; size_t hdr_start;
        if(!findHeader(hdrs, hdr_name, 0, pos1, pos2, hdr_start)) {
            ERROR("internal error: header '%s' disappeared in-between (hdrs = '%s'!",
                  hdr_name.c_str(), hdrs.c_str());
            hdrs += hdr_name + COLSP + tag + CRLF;
            return;
        }

        hdrs.insert(pos1, tag+", ");
    } else {
        // hdr does not exist - add it
        hdrs += hdr_name + COLSP + tag + CRLF;
    }
}

void removeOptionTag(string& hdrs, const string& hdr_name, const string& tag)
{
    string options = getHeader(hdrs, hdr_name);

    // does hdr hdr_name exist?
    if(options.empty())
        return;

    // todo: optimize by doing inplace
    std::vector<string> options_v = explode(options, ",");
    string o_hdr;
    bool found = false;
    for(std::vector<string>::iterator it=options_v.begin();
        it != options_v.end(); it++)
    {
        if(trim(*it, " ")==tag) {
            found = true;
            continue;
        }

        if(it != options_v.begin())
            o_hdr = ", ";

        o_hdr+=*it;
    }

    if(!found)
        return;

    removeHeader(hdrs, hdr_name);

    if(o_hdr.empty())
        return;

    hdrs += hdr_name + COLSP + o_hdr + CRLF;
}

struct format_member
{
    const string &member;
    const char *name;
    format_member(const string &member, const char *name)
      : member(member),
        name(name)
    {}
};

std::ostream& operator<<(std::ostream& out, const format_member& fmt)
{
    if(!fmt.member.empty())
        out << fmt.name << ':' << fmt.member << ";";
    return out;
}

struct format_member_brackets
{
    const string &member;
    const char *name;
    format_member_brackets(const string &member, const char *name)
      : member(member),
        name(name)
    {}
};

std::ostream& operator<<(std::ostream& out, const format_member_brackets& fmt)
{
    if(!fmt.member.empty())
        out << fmt.name << ":[" << fmt.member << "];";
    return out;
}

string AmSipRequest::print() const
{
    std::ostringstream buf;

    buf << method << " [" <<
        format_member(r_uri, "r-uri") <<
        format_member(callid, "i") <<
        format_member(int2str(cseq), "cseq") <<
        format_member(from_tag, "l-tag") <<
        format_member(to_tag, "r-tag") <<
        format_member_brackets(route, "rtset") <<
        format_member(contact, "m") <<

        format_member_brackets(hdrs, "hdr") <<
        //TODO: find some good debug info to print here
        //format_member(content_type, "c") <<
        //format_member_brackets(body, "body") <<

        format_member(user, "user") <<
        format_member(domain, "domain") <<
        format_member(from_uri, "f-uri") <<
        format_member(from, "from") <<
        format_member(to, "to") <<
    "]";

    return buf.str();
}

void AmSipRequest::log(msg_logger *logger,msg_sensor *sensor) const
{
    DBG3("AmSipRequest::log(logger = %p,sensor = %p)",logger,sensor);
    tt.lock_bucket();
    const sip_trans* t = tt.get_trans();
    if(t) {
        sip_msg* msg = t->msg;
        if(logger)
            logger->log(msg->buf,msg->len,&msg->remote_ip,
                        &msg->local_ip,msg->u.request->method_str);
        if(sensor)
            sensor->feed(msg->buf,msg->len,&msg->remote_ip,
                         &msg->local_ip,msg_sensor::PTYPE_SIP);
    }
    tt.unlock_bucket();
}

string AmSipReply::print() const
{
    std::ostringstream buf;

    buf << " [" <<
        format_member(int2str(code), "code") <<
        format_member_brackets(reason, "phrase") <<
        format_member(callid, "i") <<
        format_member(int2str(cseq), "cseq") <<
        //format_member(method, "cseq meth") <<
        format_member(from_tag, "from-tag") <<
        format_member(to_tag, "to-tag") <<
        //format_member(next_hop, "nhop") <<
        format_member_brackets(route, "rtset") <<
        format_member(contact, "m") <<

        format_member_brackets(hdrs, "hdr") <<
        //TODO: find some good debug info to print here
        //format_member(content_type, "c") <<
        //format_memberB(body, "body") <<

        format_member(contact, "contact") <<
    "]";

    return buf.str();
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 2
 * End:
 */
