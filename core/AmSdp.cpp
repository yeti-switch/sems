/*
 *parse or be parsed
 */


#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "AmSdp.h"
#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmSession.h"

#include "amci/amci.h"
#include "sip/resolver.h"
#include "log.h"

#include <stdexcept>

#include <string>
#include <map>
using std::string;
using std::map;

#include <cctype>
#include <algorithm>

// Not on Solaris!
#if !defined (__SVR4) && !defined (__sun)
#include "strings.h"
#endif

#define CR   '\r'
#define LF   '\n'
#define CRLF "\r\n"

static const string sendonly("sendonly");
static const string recvonly("recvonly");
static const string sendrecv("sendrecv");
static const string inactive("inactive");
static const string ptime("ptime");

static void parse_session_attr(AmSdp* sdp_msg, char* s, char** next);
static bool parse_sdp_line_ex(AmSdp* sdp_msg, char*& s);
static char* parse_sdp_connection(AmSdp* sdp_msg, char* s, char t);
static void parse_sdp_media(AmSdp* sdp_msg, char* s);
static char* parse_sdp_attr(AmSdp* sdp_msg, char* s);
static char* parse_ice_candidate(SdpMedia* media, char* s);
static void parse_sdp_origin(AmSdp* sdp_masg, char* s);

inline char* get_next_line(char* s);
inline char* skip_till_next_line(char* s, size_t& line_len);
static char* is_eql_next(char* s);
static char* parse_until(char* s, char end);
static char* parse_until(char* s, char* end, char c);
static bool contains(char* s, char* next_line, char c);
static bool is_wsp(char s);

static MediaType media_type(std::string media);
static TransProt transport_type(std::string transport);
static CryptoProfile crypto_profile(std::string profile, bool& alternative);
static bool attr_check(std::string attr);

enum parse_st {SDP_DESCR, SDP_MEDIA};
enum sdp_connection_st {NET_TYPE, ADDR_TYPE, IP4, IP6};
enum sdp_media_st {MEDIA, PORT, PROTO, FMT}; 
enum sdp_attr_rtpmap_st {TYPE, ENC_NAME, CLK_RATE, ENC_PARAM};
enum sdp_attr_crypto_st {TAG, PROFILE, KEY, SESS_PARAM};
enum sdp_attr_candidate_st {FND, COMPID, TRANSPORT, PRIORITY, CADDR, CPORT, CTYPE, RADDR, RPORT, ATTR_NAME, ATTR_VALUE};
enum sdp_attr_fmtp_st {FORMAT, FORMAT_PARAM};
enum sdp_origin_st {USER, ID, VERSION_ST, NETTYPE, COMMON_ADDR, UNICAST_ADDR};

// inline functions

inline string net_t_2_str(int nt)
{
    switch(nt){
        case NT_IN: return "IN";
        default: return "<unknown network type>";
    }
}

inline string addr_t_2_str(int at)
{
    switch(at){
        case AT_V4: return "IP4";
        case AT_V6: return "IP6";
        default: return "<unknown address type>";
    }
}


inline string media_t_2_str(int mt)
{
    switch(mt) {
        case MT_AUDIO: return "audio";
        case MT_VIDEO: return "video";
        case MT_APPLICATION: return "application";
        case MT_TEXT: return "text";
        case MT_MESSAGE: return "message";
        case MT_IMAGE: return "image";
        default: return "<unknown media type>";
    }
}

inline string profile_t_2_str(int pt, bool alternative)
{
    switch(pt){
        case CP_AES128_CM_SHA1_80: return "AES_CM_128_HMAC_SHA1_80";
        case CP_AES128_CM_SHA1_32: return "AES_CM_128_HMAC_SHA1_32";
        case CP_AES256_CM_SHA1_80: return alternative ? "AES_CM_256_HMAC_SHA1_80" : "AES_256_CM_HMAC_SHA1_80";
        case CP_AES256_CM_SHA1_32: return alternative ? "AES_CM_256_HMAC_SHA1_32" : "AES_256_CM_HMAC_SHA1_32";
        case CP_NULL_SHA1_80: return "NULL_HMAC_SHA1_80";
        case CP_NULL_SHA1_32: return "NULL_HMAC_SHA1_32";
//         case CP_AEAD_AES_128_GCM: return "AEAD_AES_256_GCM";
//         case CP_AEAD_AES_256_GCM: return "AEAD_AES_256_GCM";
//         case CP_AES192_CM_SHA1_80: return "AES_CM_192_HMAC_SHA1_80";
//         case CP_AES192_CM_SHA1_32: return "AES_CM_192_HMAC_SHA1_32";
        default: return "<unknown_profile_type>";
    }
}

inline string transport_ice_2_str(int tp)
{
  switch(tp){
  case ICTR_UDP: return "UDP";
  case ICTR_TCP: return "TCP";
  default: return "<unknown transport type>";
  }
}

inline string ice_candidate_2_str(int ic)
{
  switch(ic){
  case ICT_HOST: return "host";
  case ICT_PRFLX: return "prflx";
  case ICT_SRFLX: return "srflx";
  case ICT_RELAY: return "relay";
  default: return "<unknown candidate type>";
  }
}

bool SdpConnection::operator == (const SdpConnection& other) const
{
    return network == other.network && addrType == other.addrType
           && address == other.address;
}

bool SdpOrigin::operator == (const SdpOrigin& other) const
{
    return user == other.user && sessId == other.sessId
           && sessV == other.sessV && conn == other.conn;
}

bool SdpPayload::operator == (const SdpPayload& other) const
{
    return payload_type == other.payload_type && encoding_name == other.encoding_name
           && clock_rate == other.clock_rate && encoding_param == other.encoding_param;
}

string SdpConnection::debugPrint() const {
    return addr_t_2_str(addrType) + " " + address;
}

string SdpMedia::debugPrint() const {
    string payload_list;
    for(std::vector<SdpPayload>::const_iterator it=
        payloads.begin(); it!= payloads.end(); it++)
    {
        if (it != payloads.begin())
            payload_list+=" ";
        payload_list+=int2str(it->payload_type);
    }
    return "port "+int2str(port) + ", payloads: "+payload_list;
}

string SdpMedia::type2str(int type)
{
    return media_t_2_str(type);
}

TransProt SdpMedia::str2transport(string type)
{
    return transport_type(type);
}

bool SdpPayload::operator == (int r)
{
    DBG("pl == r: payload_type = %i; r = %i", payload_type, r);
    return payload_type == r;
}

string SdpKeyInfo::print() const
{
    return "inline:"+ key;
}

string SdpCrypto::print() const
{
    string ret("a=crypto:");
    ret += int2str(tag);
    ret += " ";
    ret += profile_t_2_str(profile, alt_alias);
    for(auto key:keys) {
        ret += " ";
        ret += key.print();
    }
    return ret + CRLF;
}

CryptoProfile SdpCrypto::str2profile(string str)
{
    bool alt = false;
    return crypto_profile(str, alt);
}

string SdpCrypto::profile2str(CryptoProfile profile)
{
    return profile_t_2_str(profile, false);
}

string SdpIceCandidate::print() const
{
    string data("a=candidate:");
    data += foundation + " " + int2str(comp_id) + " ";
    data += transport_ice_2_str(transport) + " ";
    data += int2str((unsigned int)priority) + " " + conn.address + " ";
    data += "typ " + ice_candidate_2_str(type);
    if(type != ICT_HOST) {
        data += " " + rel_conn.address;
    }
    for(auto attr : attrs) {
        data += " " + attr.first + " " + attr.second;
    }
    data += CRLF;
    return data;
}

IceCandidateType SdpIceCandidate::str2type(string str)
{
    if(str == "host") {
        return ICT_HOST;
    } else if(str == "prflx") {
        return ICT_PRFLX;
    } else if(str == "srflx") {
        return ICT_SRFLX;
    } else if(str == "relay") {
        return ICT_RELAY;
    } else {
        return ICT_NONE;
    }
}

string SdpAttribute::print() const
{
    if (value.empty())
        return "a="+attribute+CRLF;
    else
        return "a="+attribute+":"+value+CRLF;
}

bool SdpAttribute::operator==(const SdpAttribute& other) const
{
    return attribute==other.attribute && (value.empty() || (value==other.value));
}

bool SdpAttribute::operator < (const SdpAttribute& other) const
{
    return attribute<other.attribute;
}

bool SdpMedia::operator == (const SdpMedia& other) const
{
    if (payloads.empty()) {
        if (!other.payloads.empty())
        return false;
    } else if (other.payloads.empty()) {
        return false;
    } else {
        std::pair<vector<SdpPayload>::const_iterator, vector<SdpPayload>::const_iterator> pl_mismatch
            = std::mismatch(payloads.begin(), payloads.end(), other.payloads.begin());
        if (pl_mismatch.first != payloads.end() || pl_mismatch.second != other.payloads.end())
            return false;
    }

    if (attributes.empty()) {
        if (!other.attributes.empty()) {
            return false;
        }
    } else {
        std::pair<vector<SdpAttribute>::const_iterator, vector<SdpAttribute>::const_iterator> a_mismatch
            = std::mismatch(attributes.begin(), attributes.end(), other.attributes.begin());
        if (a_mismatch.first != attributes.end() || a_mismatch.second != other.attributes.end())
            return false;
    }

    return type == other.type && port == other.port && nports == other.nports
           && transport == other.transport && conn == other.conn && dir == other.dir
           && send == other.send && recv == other.recv;
}

//
// class RtcpAddress: Methods
//
bool RtcpAddress::parse(const string &src)
{
    port = 0;
    nettype.clear();
    addrtype.clear();
    address.clear();

    size_t len = src.size();
    if (len < 1) return false;

    enum { PORT, NET_TYPE, ADDR_TYPE, COMMON_ADDR } s = PORT;

    // parsing (somehow) according to RFC 3605
    //    rtcp-attribute =  "a=rtcp:" port  [nettype space addrtype space
    //                             connection-address] CRLF
    // nettype, addrtype is ignored
    for (size_t i = 0; i < len; ++i) {
        switch(s) {
        case (PORT):
            if (src[i] >= '0' && src[i] <= '9') port = port * 10 + (src[i] - '0');
            else if (src[i] == ' ') s = NET_TYPE;
            else return false; // error
            break;
        case NET_TYPE:
            if (src[i] == ' ') s = ADDR_TYPE;
            else nettype += src[i];
            break;
        case ADDR_TYPE:
            if (src[i] == ' ') s = COMMON_ADDR;
            else addrtype += src[i];
            break;
        case COMMON_ADDR:
            address += src[i];
            break;
        }
    }
    return s == PORT ||
           (s == COMMON_ADDR && !address.empty());
    // FIXME: nettype, addrtype and addr should be verified
}

string RtcpAddress::print()
{
    string s(int2str(port));
    if (!address.empty())
        s += " IN " + addrtype + " " + address;
    return s;
}

RtcpAddress::RtcpAddress(const string &attr_value): port(0)
{
    if (!parse(attr_value))
        throw std::runtime_error("can't parse rtcp attribute value");
}


//
// class AmSdp: Methods
//
AmSdp::AmSdp()
  : version(0),
    origin(),
    sessionName(),
    conn(),
    setup(S_UNDEFINED),
    send(true),
    recv(true),
    media(),
    use_ice(false)
{
    origin.user = AmConfig.sdp_origin;
    origin.sessId = get_random();
    origin.sessV = get_random();
}

AmSdp::AmSdp(const AmSdp& p_sdp_msg)
  : version(p_sdp_msg.version),
    origin(p_sdp_msg.origin),
    sessionName(p_sdp_msg.sessionName),
    conn(p_sdp_msg.conn),
    attributes(p_sdp_msg.attributes),
    setup(p_sdp_msg.setup),
    send(p_sdp_msg.send),
    recv(p_sdp_msg.recv),
    media(p_sdp_msg.media),
    use_ice(p_sdp_msg.use_ice)
{}

int AmSdp::parse(const char* _sdp_msg)
{
    struct sockaddr_storage ss;
    char* s = const_cast<char*>(_sdp_msg);
    clear();

    bool ret = true;
    try {
        ret = parse_sdp_line_ex(this,s);
    } catch(const std::out_of_range &oor){
        ERROR("AmSdp::parse() got Out of Range exception: %s",oor.what());
    } catch(std::exception &e){
        ERROR("AmSdp::parse() got generic exception: %s",e.what());
    } catch(...){
        ERROR("AmSdp::parse() got unknown exception");
    }

    if(!ret && conn.address.empty()){
        for(vector<SdpMedia>::iterator it = media.begin();
            !ret && (it != media.end()); ++it)
        {
            //address (c= line) must be present if stream is enabled
            ret = it->conn.address.empty() && !it->port;
            if(ret){
                ERROR("A connection field must be field must be present in every "
                      "media description or at the session level");
                break;
            }
        }
    }

    if(!ret && use_ice) {
        for(vector<SdpMedia>::iterator it = media.begin();
            !ret && (it != media.end()); ++it)
        {
            if(!it->is_use_ice()) {
                if(ice_pwd.empty() || ice_ufrag.empty()) {
                    ERROR("absent ice parameter on session level");
                    return true;
                }
                it->is_ice = true;
                it->ice_pwd = ice_pwd;
                it->ice_ufrag = ice_ufrag;
            }
        }
    }

    //validate session-level connection line
    if(!conn.address.empty()) {
        dns_handle dh;
        dns_priority priority = Dualstack;
        if(conn.addrType == AT_V4) {
            priority = IPv4_only;
        } else if(conn.addrType == AT_V6) {
            priority = IPv6_only;
        }

        if (resolver::instance()->resolve_name(conn.address.c_str(),&dh,&ss,priority) < 0) {
            ERROR("invalid session level connection line with address: %s",conn.address.c_str());
            return true;
        }
    }

    for(vector<SdpMedia>::iterator it = media.begin();
        !ret && (it != media.end()); ++it)
    {
        //propagate session-level mode attributes to the media-level if not exist
        it->set_mode_if_missed(send,recv);

        //validate media-level connection line
        const string &addr = it->conn.address;
        if(!addr.empty()) {
            dns_handle dh;
            dns_priority priority = Dualstack;
            if(it->conn.addrType == AT_V4) {
                priority = IPv4_only;
            } else if(it->conn.addrType == AT_V6) {
                priority = IPv6_only;
            }
            if (resolver::instance()->resolve_name(addr.c_str(),&dh,&ss,priority) < 0) {
                ERROR("invalid media level connection line with address: %s",addr.c_str());
                return true;
            }
        }

        if(it->setup == S_UNDEFINED && setup != S_UNDEFINED) it->setup = setup;
    }

    //remove duplicate session attributes
    std::sort(attributes.begin(),attributes.end());
    attributes.erase(std::unique(attributes.begin(),attributes.end()),attributes.end());

    //remove duplicate media attributes
    for(vector<SdpMedia>::iterator it = media.begin();
        it != media.end(); ++it)
    {
        vector<SdpAttribute> &attrs  = (*it).attributes;
        std::sort(attrs.begin(),attrs.end());
        attrs.erase(std::unique(attrs.begin(),attrs.end()),attrs.end());
    }

    return ret;
}

void AmSdp::print(string& body) const
{
    string out_buf = "v="+int2str(version)+"\r\n"
           "o="+origin.user+" "+int2str(origin.sessId)+" "+
           int2str(origin.sessV)+" IN ";

    if (!origin.conn.address.empty())
        if (origin.conn.address.find(".") != std::string::npos)
            out_buf += "IP4 " + origin.conn.address + "\r\n";
        else
            out_buf += "IP6 " + origin.conn.address + "\r\n";
    else if (!conn.address.empty())
        if (conn.address.find(".") != std::string::npos)
            out_buf += "IP4 " + conn.address + "\r\n";
        else
            out_buf += "IP6 " + conn.address + "\r\n";
    else if (media.size() && !media[0].conn.address.empty())
        if (media[0].conn.address.find(".") != std::string::npos)
            out_buf += "IP4 " + media[0].conn.address + "\r\n";
        else
            out_buf += "IP6 " + media[0].conn.address + "\r\n";
    else
        out_buf += "IP4 0.0.0.0\r\n";

    out_buf +=
        "s="+sessionName+"\r\n";
    if (!conn.address.empty()) {
        if (conn.address.find(".") != std::string::npos)
            out_buf += "c=IN IP4 ";
        else
            out_buf += "c=IN IP6 ";
        out_buf += conn.address + "\r\n";
    }

    out_buf += "t=0 0\r\n";

    // add attributes (session level)
    for (std::vector<SdpAttribute>::const_iterator a_it=
         attributes.begin(); a_it != attributes.end(); a_it++)
    {
        out_buf += a_it->print();
    }

    for(std::vector<SdpMedia>::const_iterator media_it = media.begin();
        media_it != media.end(); media_it++)
    {
        out_buf += "m=" + media_t_2_str(media_it->type) + " " + int2str(media_it->port) + " " + transport_p_2_str(media_it->transport);

        string options;

        auto is_t38_transport = media_it->transport==TP_UDPTL
                                || media_it->transport==TP_UDPTLSUDPTL;

        if (media_it->transport == TP_RTPAVP
            || media_it->transport == TP_RTPAVPF
            || media_it->transport == TP_RTPSAVP
            || media_it->transport == TP_RTPSAVPF
            || media_it->transport == TP_UDPTLSRTPSAVP
            || media_it->transport == TP_UDPTLSRTPSAVPF)
        {
            for(std::vector<SdpPayload>::const_iterator pl_it = media_it->payloads.begin();
                pl_it != media_it->payloads.end(); pl_it++)
            {
                out_buf += " " + int2str(pl_it->payload_type);

                // "a=rtpmap:" line
                if (!pl_it->encoding_name.empty()) {
                    options += "a=rtpmap:" + int2str(pl_it->payload_type) + " "
                               + pl_it->encoding_name + "/" + int2str(pl_it->clock_rate);

                    if(pl_it->encoding_param > 0) {
                        options += "/" + int2str(pl_it->encoding_param);
                    }

                    options += "\r\n";
                }

                // "a=fmtp:" line
                if(pl_it->sdp_format_parameters.size()) {
                    options += "a=fmtp:" + int2str(pl_it->payload_type) + " "
                               + pl_it->sdp_format_parameters + "\r\n";
                }
            }
        } else {
            // for other transports (UDP/UDPTL) just print out fmt
            out_buf += " " + media_it->fmt;
            // ... and continue with c=, attributes, ...
        }

        if (!media_it->conn.address.empty())
            out_buf += "\r\nc=IN " + addr_t_2_str(media_it->conn.addrType) +
                       " " + media_it->conn.address;

        if (media_it->rtcp_port)
            out_buf += "\r\na=rtcp:" + int2str(media_it->rtcp_port);

        if (!media_it->rtcp_conn.address.empty())
            out_buf += " IN " + addr_t_2_str(media_it->rtcp_conn.addrType) + 
                    " " + media_it->rtcp_conn.address;

        out_buf += "\r\n" + options;

        for (std::vector<SdpCrypto>::const_iterator c_it=
             media_it->crypto.begin(); c_it != media_it->crypto.end(); c_it++)
        {
            out_buf += c_it->print();
        }

        if(media_it->is_dtls_srtp() || media_it->is_dtls_udptl())
            out_buf += "a=fingerprint:" + media_it->fingerprint.hash + " " + media_it->fingerprint.value + "\r\n";

        if(media_it->is_ice) {
            out_buf += "a=ice-pwd:" + media_it->ice_pwd + CRLF;
            out_buf += "a=ice-ufrag:" + media_it->ice_ufrag + CRLF;
            for (std::vector<SdpIceCandidate>::const_iterator c_it=
                 media_it->ice_candidate.begin(); c_it != media_it->ice_candidate.end(); c_it++)
            {
                out_buf += c_it->print();
            }
        }

        // "a=rtcp-mux" line
        if(media_it->is_multiplex) {
            out_buf += "a=rtcp-mux\r\n";
        }

#ifdef WITH_ZRTP
        if(media_it->zrtp_hash.is_use) {
            out_buf += "a=zrtp-hash:" ZRTP_VERSION " " + media_it->zrtp_hash.hash + "\r\n";
        }
#endif/*WITH_ZRTP*/

        if(!is_t38_transport) {
            if(media_it->frame_size && !is_t38_transport) {
                out_buf += "a=ptime:" + int2str(media_it->frame_size) + "\r\n";
            }

            if(media_it->send){
                if(media_it->recv){
                    out_buf += "a=sendrecv\r\n";
                } else {
                    out_buf += "a=sendonly\r\n";
                }
            } else {
                if(media_it->recv){
                    out_buf += "a=recvonly\r\n";
                } else {
                    out_buf += "a=inactive\r\n";
                }
            }

            if(media_it->setup == S_UNDEFINED) {
                switch (media_it->dir) {
                    case SdpMedia::DirActive:  out_buf += "a=direction:active\r\n"; break;
                    case SdpMedia::DirPassive: out_buf += "a=direction:passive\r\n"; break;
                    case SdpMedia::DirBoth:  out_buf += "a=direction:both\r\n"; break;
                    case SdpMedia::DirUndefined: break;
                }
            }

            switch (media_it->setup) {
                case S_ACTIVE:  out_buf += "a=setup:active\r\n"; break;
                case S_PASSIVE: out_buf += "a=setup:passive\r\n"; break;
                case S_ACTPASS: out_buf += "a=setup:actpass\r\n"; break;
                case S_HOLD: out_buf += "a=setup:holdconn\r\n"; break;
                case S_UNDEFINED: break;
            }
        } //if(!is_t38_transport)

        // add attributes (media level)
        for (std::vector<SdpAttribute>::const_iterator a_it=
            media_it->attributes.begin(); a_it != media_it->attributes.end(); a_it++)
        {
            out_buf += a_it->print();
        }
    }
    body = out_buf;
}

vector<const SdpPayload*> AmSdp::telephoneEventPayload() const
{
    return findPayload("telephone-event");
}

vector<const SdpPayload*> AmSdp::findPayload(const string& name) const
{
    vector<const SdpPayload*> payloads;
    vector<SdpMedia>::const_iterator m_it;

    for (m_it = media.begin(); m_it != media.end(); ++m_it) {
        vector<SdpPayload>::const_iterator it = m_it->payloads.begin();
        for(; it != m_it->payloads.end(); ++it) {
            if (it->encoding_name == name) {
                payloads.push_back(new SdpPayload(*it));
            }
        }
    }
    return payloads;
}

bool AmSdp::operator == (const AmSdp& other) const
{
    if(recv != other.recv)
        return false;

    if(send != other.send)
        return false;

    if (attributes.empty()) {
        if (!other.attributes.empty())
            return false;
    } else if (other.attributes.empty()) {
        return false;
    } else {
        std::pair<vector<SdpAttribute>::const_iterator, vector<SdpAttribute>::const_iterator> a_mismatch
            = std::mismatch(attributes.begin(), attributes.end(), other.attributes.begin());

        if (a_mismatch.first != attributes.end() || a_mismatch.second != other.attributes.end())
            return false;
    }

    if (media.empty()) {
        if (!other.media.empty())
            return false;
    } else if (other.media.empty()) {
        return false;
    } else {
        std::pair<vector<SdpMedia>::const_iterator, vector<SdpMedia>::const_iterator> m_mismatch
            = std::mismatch(media.begin(), media.end(), other.media.begin());
        if (m_mismatch.first != media.end() || m_mismatch.second != other.media.end())
            return false;
    }

    return version == other.version && origin == other.origin
           && sessionName == other.sessionName && uri == other.uri && conn == other.conn;
}

void AmSdp::clear()
{
    version = 0;
    origin  = SdpOrigin();
    sessionName.clear();
    uri.clear();
    conn = SdpConnection();
    attributes.clear();
    media.clear();
    l_origin = SdpOrigin();
    send = true;
    recv = true;
}

void AmSdp::getInfo(AmArg &ret)
{
    ret.assertArray();
    for(vector<SdpMedia>::const_iterator it = media.begin(); it != media.end(); ++it) {
        AmArg a;
        const SdpMedia &m = *it;
        a["type"] = media_t_2_str(m.type);
        AmArg &payloads = a["payloads"];

        std::vector<SdpPayload>::const_iterator pit= m.payloads.begin();
        for(;pit!= m.payloads.end(); pit++) {
            AmArg a;
            const SdpPayload &p = *pit;
            a["encoding_name"] = p.encoding_name;
            a["clock_rate"] = p.clock_rate;
            a["payload_type"] = p.payload_type;
            payloads.push(a);
        }
        ret.push(a);
    }
}

void SdpMedia::calcAnswer(
    const AmPayloadProvider* payload_prov,
    SdpMedia& answer) const
{
    if(!recv) answer.send = false;
    if(!send) answer.recv = false;

    switch(dir){
    case SdpMedia::DirBoth:
        answer.dir = SdpMedia::DirBoth;
        break;
    case SdpMedia::DirActive:
        answer.dir = SdpMedia::DirPassive;
        break;
    case SdpMedia::DirPassive:
        answer.dir = SdpMedia::DirActive;
        break;
    case SdpMedia::DirUndefined:
        answer.dir = SdpMedia::DirUndefined;
        break;
    }

    // Calculate the intersection with the offered set of payloads
    vector<SdpPayload>::const_iterator it = payloads.begin();
    for(; it!= payloads.end(); ++it) {
        amci_payload_t* a_pl = nullptr;
        if(it->payload_type < DYNAMIC_PAYLOAD_TYPE_START) {
            // try static payloads
            a_pl = payload_prov->payload(it->payload_type);
        }

        if( a_pl) {
            answer.payloads.push_back(
                SdpPayload(a_pl->payload_id,
                    a_pl->name,
                    a_pl->advertised_sample_rate,
                    0));
        } else {
            // Try dynamic payloads
            // and give a chance to broken
            // implementation using a static payload number
            // for dynamic ones.
            int int_pt = payload_prov->
                getDynPayload(it->encoding_name,
                              it->clock_rate,
                              it->encoding_param);
            if(int_pt != -1) {
                answer.payloads.push_back(*it);
            }
        }
    }
}

void SdpMedia::set_mode_if_missed(bool _send, bool _recv)
{
    if(has_mode_attribute)
        return;
    send = _send;
    recv = _recv;
}

//parser
static bool parse_sdp_line_ex(AmSdp* sdp_msg, char*& s)
{
    if (!s) return true; // SDP can't be empty, return error (true really used for failure?)

    char* next = nullptr;
    size_t line_len = 0;
    parse_st state;
    //default state
    state=SDP_DESCR;

    DBG("parsing SDP message...");

    while(*s != '\0') {
        switch(state) {
        case SDP_DESCR:
            switch(*s){
            case 'v': {
                s = is_eql_next(s);
                next = skip_till_next_line(s, line_len);
                if (line_len) {
                    string version(s, line_len);
                    str2i(version, sdp_msg->version);
                    //	    DBG("parse_sdp_line_ex: found version '%s'", version.c_str());
                } else {
                    sdp_msg->version = 0;
                }
                s = next;
                state = SDP_DESCR;
                break;
            }
            case 'o':
                //DBG("parse_sdp_line_ex: found origin");
                s = is_eql_next(s);
                parse_sdp_origin(sdp_msg, s);
                s = get_next_line(s);
                state = SDP_DESCR;
                break;
            case 's': {
                s = is_eql_next(s);
                next = skip_till_next_line(s, line_len);
                if (line_len) {
                    sdp_msg->sessionName = string(s, line_len);
                } else {
                    sdp_msg->sessionName.clear();
                }
                s = next;
                break;
            }
            case 'u': {
                s = is_eql_next(s);
                next = skip_till_next_line(s, line_len);
                if (line_len) {
                    sdp_msg->uri = string(s, line_len);
                } else {
                    sdp_msg->uri.clear();
                }
                s = next;
            } break;
            case 'i':
            case 'e':
            case 'p':
            case 'b':
            case 't':
            case 'k':
                s = is_eql_next(s);
                s = skip_till_next_line(s, line_len);
                state = SDP_DESCR;
                break;
            case 'a':
                s = is_eql_next(s);
                parse_session_attr(sdp_msg, s, &next);
                // next = get_next_line(s);
                // parse_sdp_attr(sdp_msg, s);
                s = next;
                state = SDP_DESCR;
                break;
            case 'c':
                s = is_eql_next(s);
                s = parse_sdp_connection(sdp_msg, s, 'd');
                state = SDP_DESCR;
                break;
            case 'm':
                //DBG("parse_sdp_line_ex: found media");
                state = SDP_MEDIA;
                break;
            default: {
                next = skip_till_next_line(s, line_len);
                if (line_len) {
                    sdp_msg->uri = string(s, line_len);
                } else {
                    sdp_msg->uri.clear();
                }

                next = skip_till_next_line(s, line_len);
                if (line_len) {
                    DBG("parse_sdp_line: skipping unknown Session description %s=",
                    string(s, line_len).c_str());
                }
                s = next;
                break;
            }
        } break; //case SDP_DESCR

        case SDP_MEDIA:
            switch(*s){
            case 'm':
                s = is_eql_next(s);
                parse_sdp_media(sdp_msg, s);
                s = skip_till_next_line(s, line_len);
                state = SDP_MEDIA;
                break;
            case 'i':
                s = is_eql_next(s);
                s = skip_till_next_line(s, line_len);
                state = SDP_MEDIA;
                break;
            case 'c':
                s = is_eql_next(s);
                //DBG("parse_sdp_line: found media connection");
                s = parse_sdp_connection(sdp_msg, s, 'm');
                state = SDP_MEDIA;
                break;
            case 'b':
                s = is_eql_next(s);
                s = skip_till_next_line(s, line_len);
                state = SDP_MEDIA;
                break;
            case 'k':
                s = is_eql_next(s);
                s = skip_till_next_line(s, line_len);
                state = SDP_MEDIA;
                break;
            case 'a':
                s = is_eql_next(s);
                s = parse_sdp_attr(sdp_msg, s);
                state = SDP_MEDIA;
                break;
            default: {
                next = skip_till_next_line(s, line_len);
                if (line_len) {
                    DBG("parse_sdp_line: skipping unknown Media description '%.*s'",
                        static_cast<int>(line_len), s);
                }
                s = next;
                break;
            }
        } break; //case SDP_MEDIA
        } //switch(state)
    } //while(*s != '\0')

    return false;
}


static char* parse_sdp_connection(AmSdp* sdp_msg, char* s, char t)
{
    char* connection_line=s;
    char* next = nullptr;
    char* next_line = nullptr;
    size_t line_len = 0;
    int parsing=1;

    SdpConnection c;

    next_line = skip_till_next_line(s, line_len);
    if (line_len <= 7) { // should be at least c=IN IP4 ...
        DBG("short connection line '%.*s'",
            static_cast<int>(line_len), s);
        return next_line;
    }

    sdp_connection_st state;
    state = NET_TYPE;

    //DBG("parse_sdp_line_ex: parse_sdp_connection: parsing sdp connection");

    while(parsing) {
        switch(state) {
        case NET_TYPE:
            //Ignore NET_TYPE since it is always IN, fixme
            c.network = NT_IN; // fixme
            connection_line +=3; // fixme
            state = ADDR_TYPE;
            break;
        case ADDR_TYPE: {
            string addr_type(connection_line,3);
            string addr_type_uc = addr_type;
            std::transform(addr_type_uc.begin(), addr_type_uc.end(), addr_type_uc.begin(), toupper);
            connection_line +=4;
            if(addr_type_uc == "IP4") {
                c.addrType = AT_V4;
                state = IP4;
            } else if(addr_type_uc == "IP6") {
                c.addrType = AT_V6;
                state = IP6;
            } else {
                DBG("parse_sdp_connection: Unknown addr_type in c-line: '%s'", addr_type.c_str());
                c.addrType = AT_NONE;
                parsing = 0; // ???
            } break;
        }
        case IP4: {
            if(contains(connection_line, next_line, '/')) {
                next = parse_until(s, '/');
                c.address = string(connection_line,static_cast<size_t>(next-connection_line)-2);
            } else {
                c.address = string(connection_line, line_len-7);
            }
            parsing = 0;
            break;
        }
        case IP6: {
            if(contains(connection_line, next_line, '/')){
                next = parse_until(s, '/');
                c.address = string(connection_line, static_cast<size_t>(next-connection_line)-2);
            } else {
                c.address = string(connection_line, line_len-7);
            }
            parsing = 0;
            break;
        } } //switch(state)
    } //while(parsing)

    if(t == 'd') {
        sdp_msg->conn = c;
        DBG("SDP: got session level connection: %s", c.debugPrint().c_str());
    } else if(t == 'm'){
        SdpMedia& media = sdp_msg->media.back();
        media.conn = c;
        DBG("SDP: got media level connection: %s", c.debugPrint().c_str());
    }

    //DBG("parse_sdp_line_ex: parse_sdp_connection: done parsing sdp connection");
    return next_line;
}


static void parse_sdp_media(AmSdp* sdp_msg, char* s)
{
    SdpMedia m;

    sdp_media_st state;
    state = MEDIA;
    int parsing = 1;
    char* media_line=s;
    char* next=nullptr;
    char* line_end=nullptr;
    line_end = get_next_line(media_line);
    SdpPayload payload;
    unsigned int payload_type;

    //DBG("parse_sdp_line_ex: parse_sdp_media: parsing media description...");
    m.dir = SdpMedia::DirBoth;

    while(parsing) {
        switch(state) {
        case MEDIA: {
            next = parse_until(media_line, ' ');
            string media;
            if (next > media_line)
                media = string(media_line, static_cast<size_t>(next-media_line)-1);
            m.type = media_type(media);
            if(m.type == MT_NONE) {
                ERROR("parse_sdp_media: Unknown media type");
            }
            media_line = next;
            state = PORT;
            break;
        }
        case PORT: {
            next = parse_until(media_line, ' ');
            //check for multiple ports
            if(contains(media_line, next, '/')) {
                //port number
                next = parse_until(media_line, '/');
                string port;
                if (next > media_line)
                    port = string(media_line, static_cast<size_t>(next-media_line)-1);
                str2i(port, m.port);
                //number of ports
                media_line = next;
                next = parse_until(media_line, ' ');
                string nports;
                if (next > media_line)
                    nports = string(media_line, static_cast<size_t>(next-media_line)-1);
                str2i(nports, m.nports);
            } else {
                //port number
                next = parse_until(media_line, ' ');
                string port;
                if (next > media_line)
                    port = string(media_line, static_cast<size_t>(next-media_line)-1);
                str2i(port, m.port);
                media_line = next;
            }
            state = PROTO;
            break;
        }
        case PROTO: {
            next = parse_until(media_line, ' ');
            string proto;
            if (next > media_line)
                proto = string(media_line, static_cast<size_t>(next-media_line)-1);
            // if(transport_type(proto) < 0){
            //   ERROR("parse_sdp_media: Unknown transport protocol");
            //   state = FMT;
            //   break;
            // }
            m.transport = transport_type(proto);
            if(m.transport == TP_NONE){
                DBG("Unknown transport protocol: %s",proto.c_str());
            }
            media_line = next;
            state = FMT;
            break;
        }
        case FMT: {
            if (m.transport == TP_RTPAVP
                || m.transport  == TP_RTPAVPF
                || m.transport == TP_RTPSAVP
                || m.transport == TP_RTPSAVPF
                || m.transport == TP_UDPTLSRTPSAVP
                || m.transport == TP_UDPTLSRTPSAVPF)
            {
                if (contains(media_line, line_end, ' ')) {
                    next = parse_until(media_line, ' ');
                    string value;
                    if (next > media_line)
                        value = string(media_line, static_cast<size_t>(next-media_line)-1);
                    if (!value.empty()) {
                        payload.type = m.type;
                        str2i(value, payload_type);
                        payload.payload_type = static_cast<int>(payload_type);
                        m.payloads.push_back(payload);
                    }
                    media_line = next;
                } else {
                    string last_value;
                    if (line_end>media_line) {
                        if (*line_end == '\0') {
                            // last line in message
                            last_value = string(media_line, static_cast<size_t>(line_end-media_line));
                        } else {
                            last_value = string(media_line, static_cast<size_t>(line_end-media_line)-1);
                        }
                    }
                    if (!last_value.empty()) {
                        payload.type = m.type;
                        str2i(last_value, payload_type);
                        payload.payload_type = static_cast<int>(payload_type);
                        m.payloads.push_back(payload);
                    }
                    parsing = 0;
                }
            } else {
                line_end--;
                while (line_end > media_line &&
                       (*line_end == '\r' || *line_end == '\n'))
                {
                    line_end--;
                }
                if (line_end>media_line)
                    m.fmt = string(media_line,static_cast<size_t>(line_end-media_line)+1);
                DBG("set media fmt to '%s'", m.fmt.c_str());
                parsing = 0;
            }
        } break; //case FMT
        } //switch(state)
    } //while(parsing)

    sdp_msg->media.push_back(m);

    DBG("SDP: got media: %s", m.debugPrint().c_str());
    //DBG("parse_sdp_line_ex: parse_sdp_media: done parsing media description ");
    return;
}

// session level attribute
static void parse_session_attr(AmSdp* sdp_msg, char* s, char** next) {
    size_t line_len = 0;
    *next = skip_till_next_line(s, line_len);
    if (*next == s) {
        WARN("premature end of SDP in session attr");
        while (**next != '\0') (*next)++;
        return;
    }
    char* attr_end = *next-1;
    while (attr_end >= s &&
          ((*attr_end == LF) || (*attr_end == CR)))
    {
        attr_end--;
    }

    if (*attr_end == ':') {
        WARN("incorrect SDP: value attrib without value: '%s'",
             string(s, static_cast<size_t>(attr_end-s)+1).c_str());
        return;
    }

    char* col = parse_until(s, attr_end, ':');

    if (col == attr_end) {
        // property attribute
        SdpAttribute a(string(s, static_cast<size_t>(attr_end-s)+1));

        // process mode attributes
        if(a.attribute == sendonly) {
            sdp_msg->send = true;
            sdp_msg->recv = false;
        } else if(a.attribute == inactive) {
            sdp_msg->send = false;
            sdp_msg->recv = false;
        } else if(a.attribute == recvonly) {
            sdp_msg->send = false;
            sdp_msg->recv = true;
        } else if (a.attribute == sendrecv) {
            sdp_msg->send = true;
            sdp_msg->recv = true;
        }

        //add mode attributes to the unparsed ones for back-compatibility
        //!TODO: rewrite appropriate classes to use send/recv flags
        sdp_msg->attributes.push_back(a);
        // DBG("got session attribute '%.*s", (int)(attr_end-s+1), s);
    } else {
        SdpAttribute a(string(s, static_cast<size_t>(col-s)-1), string(col, static_cast<size_t>(attr_end-col)+1));
        if(a.attribute == "ice-pwd") {
            sdp_msg->use_ice = true;
            sdp_msg->ice_pwd = a.value;
            DBG("SDP: got ice request session ice_pwd %s", a.value.c_str());
            return;
        } else if(a.attribute == "ice-ufrag") {
            sdp_msg->use_ice = true;
            sdp_msg->ice_ufrag = a.value;
            DBG("SDP: got ice request session ice_ufrag %s", a.value.c_str());
            return;
        } else if(a.attribute == "setup") {
            if (a.value == "active") {
                sdp_msg->setup=S_ACTIVE;
            } else if (a.value == "passive") {
                sdp_msg->setup=S_PASSIVE;
            } else if (a.value == "actpass") {
                sdp_msg->setup=S_ACTPASS;
            } else if (a.value == "holdconn") {
                sdp_msg->setup=S_HOLD;
            } else {
                DBG("found unknown value for session attribute 'setup'");
            }
            return;
        }
        // value attribute
        sdp_msg->attributes.push_back(a);
        // DBG("got session attribute '%.*s:%.*s'", (int)(col-s-1), s, (int)(attr_end-col+1), col);
    }
}

// media level attribute
static char* parse_sdp_attr(AmSdp* sdp_msg, char* s)
{
    if(sdp_msg->media.empty()){
        ERROR("While parsing media options: no actual media !");
        return s;
    }

    SdpMedia& media = sdp_msg->media.back();

    sdp_attr_rtpmap_st rtpmap_st;
    sdp_attr_fmtp_st fmtp_st;
    sdp_attr_crypto_st crypto_st;
    rtpmap_st = TYPE;
    fmtp_st = FORMAT;
    crypto_st = TAG;
    char* attr_line=s;
    char* next=nullptr;
    char* line_end=nullptr;
    size_t line_len = 0;
    int parsing = 1;
    line_end = skip_till_next_line(attr_line, line_len);

    unsigned int payload_type = 0, clock_rate = 0, encoding_param = 0;
    string encoding_name, params;

    string attr;
    if (!contains(attr_line, line_end, ':')) {
        attr = string(attr_line, line_len);
        attr_check(attr);
        parsing = 0;
    } else {
        next = parse_until(attr_line, ':');
        attr = string(attr_line, static_cast<size_t>(next-attr_line)-1);
        attr_line = next;
    }

    if(attr == "rtpmap") {
        while(parsing) {
            switch(rtpmap_st) {
            case TYPE: {
                next = parse_until(attr_line, ' ');
                string type(attr_line, static_cast<size_t>(next-attr_line)-1);
                str2i(type,payload_type);
                attr_line = next;
                rtpmap_st = ENC_NAME;
                break;
            }
            case ENC_NAME: {
                if(contains(s, line_end, '/')) {
                    next = parse_until(attr_line, '/');
                    string enc_name(attr_line, static_cast<size_t>(next-attr_line)-1);
                    encoding_name = enc_name;
                    attr_line = next;
                    rtpmap_st = CLK_RATE;
                    break;
                } else {
                    rtpmap_st = ENC_PARAM;
                    break;
                }
            }
            case CLK_RATE: {
                // check for posible encoding parameters after clock rate
                if(contains(attr_line, line_end, '/')) {
                    next = parse_until(attr_line, '/');
                    string clk_rate(attr_line, static_cast<size_t>(next-attr_line)-1);
                    str2i(clk_rate, clock_rate);
                    attr_line = next;
                    rtpmap_st = ENC_PARAM;
                    //last line check
                } else if (*line_end == '\0') {
                    string clk_rate(attr_line, static_cast<size_t>(line_end-attr_line));
                    str2i(clk_rate, clock_rate);
                    parsing = 0;
                    //more lines to come
                } else {
                    string clk_rate(attr_line, static_cast<size_t>(line_end-attr_line)-1);
                    str2i(clk_rate, clock_rate);
                    parsing=0;
                }
                break;
            }
            case ENC_PARAM: {
                next = parse_until(attr_line, ' ');
                if(next < line_end) {
                    string value(attr_line, static_cast<size_t>(next-attr_line)-1);
                    str2i(value, encoding_param);
                    attr_line = next;
                    rtpmap_st = ENC_PARAM;
                } else {
                    string last_value(attr_line, static_cast<size_t>(line_end-attr_line)-1);
                    str2i(last_value, encoding_param);
                    parsing = 0;
                }
                break;
            } } //switch(rtpmap_st)
        } //while(parsing)

        //DBG("found media attr 'rtpmap' type '%d'", payload_type);
        vector<SdpPayload>::iterator pl_it;

        for(pl_it=media.payloads.begin();
            (pl_it != media.payloads.end()) && (pl_it->payload_type != int(payload_type));
            ++pl_it);

        if(pl_it != media.payloads.end()) {
            *pl_it = SdpPayload(
                int(payload_type),
                encoding_name,
                int(clock_rate),
                int(encoding_param));
        }

    } else if(attr == "fmtp") {
        while(parsing) {
            switch(fmtp_st) { // fixme
            case FORMAT: {
                next = parse_until(attr_line, line_end, ' ');
                string fmtp_format(attr_line, static_cast<size_t>(next-attr_line)-1);
                str2i(fmtp_format, payload_type);
                attr_line = next;
                fmtp_st = FORMAT_PARAM;
                break;
            }
            case FORMAT_PARAM: {
                char* param_end = line_end-1;
                while (is_wsp(*param_end))
                    param_end--;
                if(attr_line >= param_end) {
                    DBG("empty param for fmtp. ignore it");
                } else {
                    params = string(attr_line, static_cast<size_t>(param_end-attr_line)+1);
                }
                parsing = 0;
            } break; }
        }

        //DBG("found media attr 'fmtp' for payload '%d': '%s'",
        //  payload_type, params.c_str());

        vector<SdpPayload>::iterator pl_it;
        for(pl_it=media.payloads.begin();
            (pl_it != media.payloads.end()) && (pl_it->payload_type != int(payload_type));
            pl_it++);

        if(pl_it != media.payloads.end())
            pl_it->sdp_format_parameters = params;
    } else if(attr == "rtcp") {
        next = parse_until(attr_line, line_end, ' ');
        string port(attr_line, int(next-attr_line)-1);
        int rtcpport;
        str2int(port, rtcpport);
        if(rtcpport != 9) {
            media.rtcp_port = rtcpport;
            if(next != line_end) {
                attr_line = next;
                AmSdp tmpsdp;
                parse_sdp_connection(&tmpsdp, attr_line, 'd');
                media.rtcp_conn = tmpsdp.conn;
            }
        } else {
            DBG("Ignore rtcp attribute");
        }
    } else if(attr == "rtcp-mux") {
        media.is_multiplex = true;
    } else if(attr == "crypto") {
        media.crypto.emplace_back();
        SdpCrypto &crypto = media.crypto.back();
        while(attr_line < line_end) {
            next = parse_until(attr_line, line_end, ' ');
            switch(crypto_st) {
            case TAG: {
                string tag_number(attr_line, static_cast<size_t>(next-attr_line)-1);
                str2i(tag_number, crypto.tag);
                crypto_st = PROFILE;
                break;
            }
            case PROFILE: {
                string profile(attr_line, static_cast<size_t>(next-attr_line)-1);
                crypto.profile = crypto_profile(profile, crypto.alt_alias);
                crypto_st = KEY;
                break;
            }
            case KEY: {
                char* key_data = parse_until(attr_line, next, ':');
                if(key_data < line_end) {
                    string method = string(attr_line, static_cast<size_t>(key_data-attr_line)-1);
                    if(method == "inline") {
                        crypto.keys.emplace_back();
                        SdpKeyInfo &info = crypto.keys.back();
                        size_t line_len;
                        next = skip_till_next_line(key_data, line_len);
                        char* key_end = parse_until(key_data, key_data+line_len+1, '|');
                        info.key = string(key_data, static_cast<size_t>(key_end-key_data-1));
                        //TODO: parse parameters as described in https://tools.ietf.org/html/rfc4568#section-9.2
                        info.lifetime = 0;
                        info.mki = 1;
                        break;
                    }
                }
                crypto_st = SESS_PARAM;
            }
            case SESS_PARAM: {
                string param(attr_line, static_cast<size_t>(next-attr_line)-1);
                crypto.sp.push_back(param);
            }
            } //switch(crypto_st)
            attr_line = next;
        } //while(attr_line < line_end)
    } else if(attr == "fingerprint") {
        next = parse_until(attr_line, line_end, ' ');
        media.fingerprint.hash = string(attr_line, int(next-attr_line)-1);
        attr_line = next;
        size_t val_len = 0;
        next = skip_till_next_line(attr_line, val_len);
        media.fingerprint.value = string(attr_line, val_len);
  } else if(attr == "ice-pwd") {
    size_t val_len = 0;
    next = skip_till_next_line(attr_line, val_len);
    media.ice_pwd = string(attr_line, val_len);
    media.is_ice = true;
    DBG("SDP: got ice request media ice_pwd %s", media.ice_pwd.c_str());
  } else if(attr == "ice-ufrag") {
    size_t val_len = 0;
    next = skip_till_next_line(attr_line, val_len);
    media.ice_ufrag = string(attr_line, val_len);
    media.is_ice = true;
    DBG("SDP: got ice request media ufrag %s", media.ice_ufrag.c_str());
  } else if(attr == "candidate") {
    next = parse_ice_candidate(&media, attr_line);
  } else if (attr == "setup") {
    if (parsing) {
      size_t dir_len = 0;
      next = skip_till_next_line(attr_line, dir_len);
      string value(attr_line, dir_len);
      if (value == "active") {
        media.setup=S_ACTIVE;
      } else if (value == "passive") {
        media.setup=S_PASSIVE;
      } else if (value == "actpass") {
        media.setup=S_ACTPASS;
      } else if (value == "holdconn") {
        media.setup=S_HOLD;
      } else {
            DBG("found unknown value for media attribute 'setup'");
      }
    } else {
      DBG("ignoring direction attribute without value");
    }
#ifdef WITH_ZRTP
  } else if (attr == "zrtp-hash") {
        next = parse_until(attr_line, line_end, ' ');
        string version(attr_line, int(next-attr_line)-1);
        if(version == ZRTP_VERSION) {
            media.zrtp_hash.is_use = true;
            attr_line = next;
            size_t val_len = 0;
            next = skip_till_next_line(attr_line, val_len);
            media.zrtp_hash.hash = string(attr_line, val_len);
        } else {
            DBG("unsupported zrtp version in 'zrtp-hash' attribute");
        }
#endif/*WITH_ZRTP*/
  } else if (attr == "direction") {
    if (parsing) {
      size_t dir_len = 0;
      next = skip_till_next_line(attr_line, dir_len);
      string value(attr_line, dir_len);
      if (value == "active") {
        media.dir=SdpMedia::DirActive;
	// DBG("found media attr 'direction' value '%s'", (char*)value.c_str());
      } else if (value == "passive") {
        media.dir=SdpMedia::DirPassive;
	//DBG("found media attr 'direction' value '%s'", (char*)value.c_str());
      } else if (value == "both") {
            media.dir=SdpMedia::DirBoth;
	//DBG("found media attr 'direction' value '%s'", (char*)value.c_str());
      } else {
	DBG("found unknown value for media attribute 'direction'");
      }
    } else {
      DBG("ignoring direction attribute without value");
    }
  } else if (attr == sendrecv) {
    media.send = true;
    media.recv = true;
    media.has_mode_attribute = true;
  } else if (attr == sendonly) {
    media.send = true;
    media.recv = false;
    media.has_mode_attribute = true;
  } else if (attr == recvonly) {
    media.send = false;
    media.recv = true;
    media.has_mode_attribute = true;
  } else if (attr == inactive) {
    media.send = false;
    media.recv = false;
    media.has_mode_attribute = true;
  } else if (attr == ptime) {
    size_t attr_len = 0;
    string value;
    next = skip_till_next_line(attr_line, attr_len);
    value = string (attr_line, attr_len);
    str2int(value, media.frame_size);
    adjust_media_frame_size(media.frame_size);
  } else {
    attr_check(attr);
    string value;
    if (parsing) {
      size_t attr_len = 0;
      next = skip_till_next_line(attr_line, attr_len);
      value = string (attr_line, attr_len);
    }

    // if (value.empty()) {
    //   DBG("got media attribute '%s'", attr.c_str());
    // } else {
    //   DBG("got media attribute '%s':'%s'", attr.c_str(), value.c_str());
    // }
    media.attributes.push_back(SdpAttribute(attr, value));
  }
  return line_end;
}

static char* parse_ice_candidate(SdpMedia* media, char* s)
{
    SdpIceCandidate candidate;
    sdp_attr_candidate_st cd_st = FND;
    size_t line_len;
    int idata;
    char *line_end = skip_till_next_line(s, line_len), *next = s, *param = s;
    int parsing = 1;
    string data, attr;
    while(parsing) {
        next = parse_until(param, line_end, ' ');
        if((next - s) > (int)line_len) {
            next -= (next - s) - line_len - 1;
        }
        if(param == next) {
            break;
        }
        switch(cd_st) {
            case FND:
                candidate.foundation = string(param, int(next-param)-1);
                cd_st = COMPID;
                break;
            case COMPID:
                data = string(param, int(next-param)-1);
                if(!str2int(data, (int&)candidate.comp_id)) {
                    ERROR("invalid component id of ice candidate attribute %s", data.c_str());
                    parsing = 0;
                    break;
                }
                cd_st = TRANSPORT;
                break;
            case TRANSPORT:
                data = string(param, int(next-param)-1);
                if(strcasecmp(data.c_str(),"tcp") == 0) {
                    candidate.transport = ICTR_TCP;
                } else if(strcasecmp(data.c_str(), "udp") == 0) {
                    candidate.transport = ICTR_UDP;
                } else {
                    ERROR("invalid transport of ice candidate attribute %s", data.c_str());
                    parsing = 0;
                    break;
                }
                cd_st = PRIORITY;
                break;
            case PRIORITY:
                data = string(param, int(next-param)-1);
                if(!str2int(data, (int&)candidate.priority)) {
                    ERROR("invalid priority of ice candidate attribute %s", data.c_str());
                    parsing = 0;
                    break;
                }
                cd_st = CADDR;
                break;
            case CADDR:
            case RADDR:
                data = string(param, int(next-param)-1);
                if(cd_st == RADDR && data == "raddr") {
                    break;
                }
                if(cd_st == CADDR)
                    candidate.conn.network = NT_IN;
                else if(cd_st == RADDR)
                    candidate.rel_conn.network = NT_IN;
                if(data.find_first_of(":") != string::npos) {
                    if(cd_st == CADDR)
                        candidate.conn.addrType = AT_V6;
                    else if(cd_st == RADDR)
                        candidate.rel_conn.addrType = AT_V6;
                } else if(data.find_first_of(".") != string::npos) {
                    if(cd_st == CADDR)
                        candidate.conn.addrType = AT_V4;
                    else if(cd_st == RADDR)
                        candidate.rel_conn.addrType = AT_V4;
                } else {
                    ERROR("invalid address of ice candidate attribute %s", data.c_str());
                    parsing = 0;
                    break;
                }
                attr = data + " ";
                cd_st = (cd_st == CADDR) ? CPORT : RPORT;
                break;
            case CPORT:
            case RPORT:
                data = string(param, int(next-param)-1);
                if(cd_st == RPORT && data == "rport") {
                    break;
                }
                if(!str2int(data, idata)) {
                    ERROR("invalid port of ice candidate attribute %s", data.c_str());
                    parsing = 0;
                    break;
                }
                else if(idata == 9) {
                    DBG("ingnore port 9 for ice candidate");
                    parsing = 0;
                    break;
                }
                attr += data;
                if(cd_st == CPORT)
                    candidate.conn.address = attr;
                else if(cd_st == RPORT)
                    candidate.rel_conn.address = attr;
                cd_st = (cd_st == CPORT) ? CTYPE : ATTR_NAME;
                break;
            case CTYPE:
                data = string(param, int(next-param)-1);
                if(data != "typ") {
                    ERROR("invalid argument of ice candidate attribute %s must be \'typ\'", data.c_str());
                    parsing = 0;
                    break;
                }
                param = next;
                next = parse_until(param, line_end, ' ');
                if((next - s) > (int)line_len) {
                    next -= (next - s) - line_len - 1;
                }
                if(next != param) {
                    data = string(param, int(next-param)-1);
                }
                candidate.type = SdpIceCandidate::str2type(data);
                if(candidate.type == ICT_NONE) {
                    ERROR("invalid candidate type of ice candidate attribute %s", data.c_str());
                    parsing = 0;
                } else if(candidate.type == ICT_HOST) {
                    cd_st = ATTR_NAME;
                } else {
                    cd_st = RADDR;
                }
                break;
            case ATTR_NAME:
                attr = string(param, next);
                cd_st = ATTR_VALUE;
                break;
            case ATTR_VALUE:
                data = string(param, int(next-param)-1);
                candidate.attrs.insert(std::make_pair(attr, data));
                cd_st = ATTR_NAME;
                break;
        }
        param = next;
    }
    if(parsing) {
        media->ice_candidate.push_back(candidate);
        DBG("SDP: got ice candidate: type %s via %s %s",
            ice_candidate_2_str(candidate.type).c_str(), transport_ice_2_str(candidate.transport).c_str(), candidate.conn.debugPrint().c_str());
    }
    return line_end;
}

static void parse_sdp_origin(AmSdp* sdp_msg, char* s)
{
    char* origin_line = s;
    char* next=nullptr;
    char* line_end=nullptr;
    size_t line_len=0;
    line_end = skip_till_next_line(s, line_len);

    sdp_origin_st origin_st;
    origin_st = USER;
    int parsing = 1;

    SdpOrigin origin;

    //DBG("parse_sdp_line_ex: parse_sdp_origin: parsing sdp origin");

    while(parsing){
        switch(origin_st) {
        case USER: {
            next = parse_until(origin_line, ' ');
            if(next > line_end) {
                DBG("parse_sdp_origin: ST_USER: Incorrect number of value in o=");
                origin_st = UNICAST_ADDR;
                break;
            }
            string user(origin_line, static_cast<size_t>(next-origin_line)-1);
            origin.user = user;
            origin_line = next;
            origin_st = ID;
            break;
        }
        case ID: {
            next = parse_until(origin_line, ' ');
            if(next > line_end) {
                DBG("parse_sdp_origin: ST_ID: Incorrect number of value in o=");
                origin_st = UNICAST_ADDR;
                break;
            }
            string id(origin_line, static_cast<size_t>(next-origin_line)-1);
            str2i(id, origin.sessId);
            origin_line = next;
            origin_st = VERSION_ST;
            break;
        }
        case VERSION_ST: {
            next = parse_until(origin_line, ' ');
            if(next > line_end) {
                DBG("parse_sdp_origin: ST_VERSION: Incorrect number of value in o=");
                origin_st = UNICAST_ADDR;
                break;
            }
            string version(origin_line, static_cast<size_t>(next-origin_line)-1);
            str2i(version, origin.sessV);
            origin_line = next;
            origin_st = NETTYPE;
            break;
        }
        case NETTYPE: {
            next = parse_until(origin_line, ' ');
            if(next > line_end) {
                DBG("parse_sdp_origin: ST_NETTYPE: Incorrect number of value in o=");
                origin_st = UNICAST_ADDR;
                break;
            }
            string net_type(origin_line, static_cast<size_t>(next-origin_line)-1);
            origin.conn.network = NT_IN; // fixme
            origin_line = next;
            origin_st = COMMON_ADDR;
            break;
        }
        case COMMON_ADDR: {
            next = parse_until(origin_line, ' ');
            if(next > line_end) {
                DBG("parse_sdp_origin: ST_ADDR: Incorrect number of value in o=");
                origin_st = UNICAST_ADDR;
                break;
            }

            string addr_type(origin_line, static_cast<size_t>(next-origin_line)-1);
            if(addr_type == "IP4") {
                origin.conn.addrType = AT_V4;
            } else if(addr_type == "IP6") {
                origin.conn.addrType = AT_V6;
            } else {
                DBG("parse_sdp_connection: Unknown addr_type in o line: '%s'", addr_type.c_str());
                origin.conn.addrType = AT_NONE;
            }

            origin_line = next;
            origin_st = UNICAST_ADDR;
            break;
        }
        case UNICAST_ADDR: {
            next = parse_until(origin_line, ' ');
            if (next != origin_line) {
                //check if line contains more values than allowed
                if(next > line_end) {
                    size_t addr_len = 0;
                    skip_till_next_line(origin_line, addr_len);
                    origin.conn.address = string(origin_line, addr_len);
                } else {
                    DBG("parse_sdp_origin: 'o=' contains more values than allowed; these values will be ignored");
                    origin.conn.address = string(origin_line, static_cast<size_t>(next-origin_line)-1);
                }
            } else {
                origin.conn.address = "";
            }
            parsing = 0;
            break;
        } } //switch(origin_st)
    } //while(parsing)s

    sdp_msg->origin = origin;

    //DBG("parse_sdp_line_ex: parse_sdp_origin: done parsing sdp origin");
    return;
}

/*
 *HELPER FUNCTIONS
 */

static bool contains(char* s, char* next_line, char c)
{
    char* line=s;
    while((line != next_line-1) && (*line)) {
        if(*line == c)
            return true;
        line++;
    }
    return false;
}

static bool is_wsp(char s) {
    return s==' ' || s == '\r' || s == '\n' || s == '\t';
}

static char* parse_until(char* s, char end)
{
    char* line=s;
    while(*line && *line != end ){
        line++;
    }
    line++;
    return line;
}

static char* parse_until(char* s, char* end, char c)
{
    char* line=s;
    while(line<end && *line && *line != c ) {
        line++;
    }
    if (line<end)
        line++;
    return line;
}

static char* is_eql_next(char* s)
{
    char* current_line=s;
    if(*(++current_line) != '=') {
        DBG("parse_sdp_line: expected '=' but found <%c> ", *current_line);
    }
    current_line +=1;
    return current_line;
}

inline char* get_next_line(char* s)
{
    char* next_line=s;
    //search for next line
    while( *next_line != '\0') {
        if(*next_line == CR) {
            next_line++;
            if (*next_line == LF) {
                next_line++;
                break;
            } else {
                continue;
            }
        } else if (*next_line == LF) {
            next_line++;
            break;
        }
        next_line++;
    }

    return next_line;
}

/* skip to 0, CRLF or LF;
   @return line_len length of current line
   @return start of next line
*/
inline char* skip_till_next_line(char* s, size_t& line_len)
{
    char* next_line=s;
    line_len = 0;

    //search for next line
    while( *next_line != '\0') {
        if (*next_line == CR) {
            next_line++;
            if (*next_line == LF) {
                next_line++;
                break;
            } else {
                continue;
            }
        } else if (*next_line == LF){
            next_line++;
            break;
        }
        line_len++;
        next_line++;
    }

    return next_line;
}

/*
 *Check if known media type is used
 */
static MediaType media_type(std::string media)
{
    if(media == "audio")
        return MT_AUDIO;
    else if(media == "video")
        return MT_VIDEO;
    else if(media == "application")
        return MT_APPLICATION;
    else if(media == "text")
        return MT_TEXT;
    else if(media == "message")
        return MT_MESSAGE;
    else if(media == "image")
        return MT_IMAGE;
    else
        return MT_NONE;
}

static TransProt transport_type(string transport)
{
    string transport_uc = transport;
    std::transform(transport_uc.begin(), transport_uc.end(), transport_uc.begin(), toupper);

    if(transport_uc == "RTP/AVP")
        return TP_RTPAVP;
    else if(transport_uc == "RTP/AVPF")
        return TP_RTPAVPF;
    else if(transport_uc == "UDP")
        return TP_UDP;
    else if(transport_uc == "RTP/SAVP")
        return TP_RTPSAVP;
    else if(transport_uc == "RTP/SAVPF")
        return TP_RTPSAVPF;
    else if(transport_uc == "UDP/TLS/RTP/SAVP")
        return TP_UDPTLSRTPSAVP;
    else if(transport_uc == "UDP/TLS/RTP/SAVPF")
        return TP_UDPTLSRTPSAVPF;
    else if(transport_uc == "UDP/TLS/UDPTL")
        return TP_UDPTLSUDPTL;
    else if(transport_uc == "UDPTL")
        return TP_UDPTL;
    else
        return TP_NONE;
}


static CryptoProfile crypto_profile(std::string profile, bool& alternative)
{
    string profile_uc = profile;
    std::transform(profile_uc.begin(), profile_uc.end(), profile_uc.begin(), toupper);

    alternative = false;
    if(profile_uc == "AES_CM_128_HMAC_SHA1_32")
        return CP_AES128_CM_SHA1_32;
    else if(profile_uc == "AES_CM_128_HMAC_SHA1_80")
        return CP_AES128_CM_SHA1_80;
//    else if(profile_uc == "AES_CM_192_HMAC_SHA1_32")
//        return CP_AES192_CM_SHA1_32;
//    else if(profile_uc == "AES_CM_192_HMAC_SHA1_80")
//        return CP_AES192_CM_SHA1_80;
    else if(profile_uc == "AES_CM_256_HMAC_SHA1_32") {
        alternative = true;
        return CP_AES256_CM_SHA1_32;
    } else if(profile_uc == "AES_CM_256_HMAC_SHA1_80") {
        alternative = true;
        return CP_AES256_CM_SHA1_80;
    } else if(profile_uc == "AES_256_CM_HMAC_SHA1_32")
        return CP_AES256_CM_SHA1_32;
    else if(profile_uc == "AES_256_CM_HMAC_SHA1_80")
        return CP_AES256_CM_SHA1_80;
//    else if(profile_uc == "AEAD_AES_128_GCM")
//        return CP_AEAD_AES_128_GCM;
//    else if(profile_uc == "AEAD_AES_256_GCM")
//        return CP_AEAD_AES_256_GCM;
    else if(profile_uc == "NULL_HMAC_SHA1_32")
        return CP_NULL_SHA1_32;
    else if(profile_uc == "NULL_HMAC_SHA1_80")
        return CP_NULL_SHA1_80;
    else
        return CP_NONE;
}

/*
*Check if known attribute name is used
*/
static bool attr_check(std::string attr)
{
    if(attr == "cat")
        return true;
    else if(attr == "keywds")
        return true;
    else if(attr == "tool")
        return true;
    else if(attr == "ptime")
        return true;
    else if(attr == "maxptime")
        return true;
    else if(attr == "recvonly")
        return true;
    else if(attr == "sendrecv")
        return true;
    else if(attr == "sendonly")
        return true;
    else if(attr == "inactive")
        return true;
    else if(attr == "orient")
        return true;
    else if(attr == "type")
        return true;
    else if(attr == "charset")
        return true;
    else if(attr == "sdplang")
        return true;
    else if(attr == "lang")
        return true;
    else if(attr == "framerate")
        return true;
    else if(attr == "quality")
        return true;
    else if(attr == "both")
        return true;
    else if(attr == "active")
        return true;
    else if(attr == "passive")
        return true;
    else if(attr == "rtcp-mux")
        return true;
    else {
        DBG("unknown attribute: %s", attr.c_str());
        return false;
    }
}

