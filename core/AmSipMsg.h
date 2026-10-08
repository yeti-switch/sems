#ifndef __AMSIPMSG_H__
#define __AMSIPMSG_H__
#include "AmArg.h"
#include "AmMimeBody.h"

#include <string>
#include <string_view>
#include <map>
#include <algorithm>
#include <strings.h>
using std::string;

#include "sip/trans_layer.h"
#include "sip/msg_sensor.h"

/** case-insensitive, transparent comparator for SIP header names */
struct ci_less {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const
    {
        int r = strncasecmp(a.data(), b.data(), std::min(a.size(), b.size()));
        return r ? r < 0 : a.size() < b.size();
    }
};

using AmSipHeaderMap = std::multimap<string, string, ci_less>;

/* enforce common naming in Req&Rpl */
class _AmSipMsgInDlg : public AmObject {
  public:
    string from;
    string from_tag;

    string to;
    string to_tag;

    string callid;

    unsigned int cseq;
    string       cseq_method;

    unsigned int rseq;

    string route;
    string contact;

    AmSipHeaderMap hdrs;

    AmMimeBody body;

    // transaction ticket from sip stack
    trans_ticket tt;

    string         remote_ip;
    unsigned short remote_port;
    string         local_ip;
    unsigned short local_port;
    string         actual_ip;
    unsigned short actual_port;
    string         trsp;

    timeval      recv_timestamp;
    unsigned int transport_id;

    _AmSipMsgInDlg()
        : cseq(0)
        , rseq(0)
        , actual_port(0)
        , transport_id(0)
    {
    }
    virtual ~_AmSipMsgInDlg() {}

    virtual string print() const = 0;
};

#ifdef PROPAGATE_UNPARSED_REPLY_HEADERS

struct AmSipHeader {
    string name, value;
    AmSipHeader() {}
    AmSipHeader(const string &_name, const string &_value)
        : name(_name)
        , value(_value)
    {
    }
    AmSipHeader(const cstring &_name, const cstring &_value)
        : name(_name.s, _name.len)
        , value(_value.s, _value.len)
    {
    }
};

#endif

/** \brief represents a SIP reply */
class AmSipReply : public _AmSipMsgInDlg {
  public:
    unsigned int code;
    string       reason;
    string       to_uri;
    bool         local_reply;
#ifdef PROPAGATE_UNPARSED_REPLY_HEADERS
    list<AmSipHeader> unparsed_headers;
#endif

    AmSipReply()
        : _AmSipMsgInDlg()
        , code(0)
        , local_reply(false)
    {
    }

    ~AmSipReply() {}

    bool   init(const sip_msg *msg);
    string print() const;
};


/** \brief represents a SIP request */
class AmSipRequest : public _AmSipMsgInDlg {
  public:
    string method;

    string scheme;
    string user;
    string domain;
    string r_uri;
    string from_uri;

    string       rack_method;
    unsigned int rack_cseq;

    vector<string> vias; // Via values in message order
    string         via1;
    string         via_branch;
    bool           first_hop;

    int max_forwards;

    unsigned short local_if;
    unsigned short proto_idx;

    AmSipRequest();
    ~AmSipRequest() {}

    bool   init(const sip_msg *msg, const trans_ticket *tt = 0);
    string print() const;
    void   log(msg_logger *logger, msg_sensor *sensor) const;
};

/** @return first value of hdr_name if single, else all values joined with ", " */
string getHeader(const AmSipHeaderMap &hdrs, std::string_view hdr_name, bool single = false);

/** @return whether header hdr_name is in hdrs */
bool hasHeader(const AmSipHeaderMap &hdrs, std::string_view hdr_name);

/** remove all occurences of hdr_name
    @return true if something was removed */
bool removeHeader(AmSipHeaderMap &hdrs, std::string_view hdr_name);

/** add an option tag @param tag to list @param hdr_name */
void addOptionTag(AmSipHeaderMap &hdrs, const string &hdr_name, const string &tag);

/** add an option tags @param tags to list @param hdr_name */
void addOptionTags(AmSipHeaderMap &hdrs, const string &hdr_name, const vector<string> &tags);

/** remove an option tag @param tag from list @param hdr_name */
void removeOptionTag(AmSipHeaderMap &hdrs, const string &hdr_name, const string &tag);

struct sip_header;

/** add parsed header to hdrs. folded lines are joined, compact names expanded */
void addHeader(AmSipHeaderMap &hdrs, const sip_header &h);

/** serialize to "Name: value CRLF ..." */
string headers2string(const AmSipHeaderMap &hdrs);

/** parse "Name: value CRLF ..." with sip parser and add entries to hdrs
 *  @return false on malformed input (nothing is added then) */
bool parseHeadersString(const string &hdrs_str, AmSipHeaderMap &hdrs);

/** get the value of key @param name from PARAM_HDR header in hdrs */
string get_session_param(const AmSipHeaderMap &hdrs, const string &name);

/** parse the PARAM_HDR header and extracts the parameters into a map */
void parse_app_params(const AmSipHeaderMap &hdrs, std::map<string, string> &app_params);

#endif /* __AMSIPMSG_H__ */


/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 2
 * End:
 */
