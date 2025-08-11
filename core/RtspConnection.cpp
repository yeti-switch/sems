#include "AmSessionContainer.h"
#include <sstream>
#include <string>
#include <map>
#include <queue>
#include <algorithm>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>


#include "RtspClient.h"
#include "RtspAudio.h"
#include "RtspConnection.h"


#define likely(expr)   __builtin_expect(!!(expr), 1)
#define unlikely(expr) __builtin_expect(!!(expr), 0)

using std::ostringstream;
using std::string;
using namespace Rtsp;

static const int RTSP_BUFFER_SIZE = 2048;


static const char *Method_str[] = { "Unknown", "DESCRIBE", "PLAY",    "PAUSE",
                                    "SETUP",   "TEARDOWN", "OPTIONS", "PLAY_NOTIFY" };

static const char *Header_str[] = { "Unknown", "Accept",        "Content-Type", "Content-Length",
                                    "CSeq",    "Session",       "Transport",    "Date",
                                    "Range",   "Notify-Reason", "RTP-Info",     "X-Samplerate-Hint" };

static const char *Notify_rsn_str[] = { "unknown", "end-of-stream", "media-properties-update", "scale-change" };


static int str2method(const char *str, size_t str_len)
{
    for (int i = PLAY_NOTIFY; i > 0; --i)
        if (!strncasecmp(Method_str[i], str, str_len))
            return i;

    return RTSP_UNKNOWN;
}


static int str2hdr(const char *str, size_t str_len)
{
    for (int i = H_RTP_Info; i > 0; --i)
        if (!strncasecmp(Header_str[i], str, str_len))
            return i;

    return H_UNPARSED;
}


static int str2NotifyReason(const char *str, size_t str_len)
{
    for (int i = NR_scale_change; i > 0; --i)
        if (!strncasecmp(Notify_rsn_str[i], str, str_len))
            return i;

    return RTSP_UNKNOWN;
}


/** Request-Line = Method SP Request-URI SP RTSP-Version CRLF */
void RtspMsg::parse_request_line(const char *line, size_t len)
{
    const char *sp0 = static_cast<const char *>(memchr(line, ' ', len)),
               *sp1 = sp0 ? static_cast<const char *>(memchr(sp0 + 1, ' ', len - (sp0 - line) - 1)) : NULL;

    if (unlikely(!sp0 || !sp1)) {
        ERROR("Can't parse request line '%s'", line);
        return;
    }

    method  = str2method(line, sp0 - line);
    uri     = string(sp0 + 1, sp1 - sp0 - 1);
    version = string(sp1 + 1, len - (sp1 - line) - 1);
}


/** Status-Line = RTSP-Version SP Status-Code SP Reason-Phrase CRLF */
void RtspMsg::parse_status_line(const char *line, size_t len)
{
    const char *sp0 = static_cast<const char *>(memchr(line, ' ', len)),
               *sp1 = sp0 ? static_cast<const char *>(memchr(sp0 + 1, ' ', len - (sp0 - line) - 1)) : NULL;

    if (unlikely(!sp0 || !sp1)) {
        ERROR("Can't parse status line '%s'", line);
        return;
    }

    version = string(line, sp0 - line);
    code    = atoi(sp0);
    reason  = string(sp1 + 1, len - (sp1 - line) - 1);
}


/** workaround for leading space (must be a zero char) "ssrc= aaabbbb" */
static void hextrim(string &v, unsigned int &result)
{
    // ltrim to hex char
    v.erase(v.begin(), std::find_if(v.begin(), v.end(), [](unsigned char ch) { return std::isxdigit(ch); }));

    // rtrim to hex char
    v.erase(std::find_if(v.begin(), v.end(), [](unsigned char ch) { return !std::isxdigit(ch); }), v.end());
    hex2int(v, result);
}


void RtspMsg::process_header(int hdr, const char *v, size_t vl)
{
#define SRV_PORT_PARAM "server_port="
#define STREAMID_PARAM "streamid="
#define RTPTIME_PARAM  "rtptime="
#define SSRC_PARAM     "ssrc="
    const char *s;

    switch (hdr) {
    case H_CSeq:          cseq = atoi(v); break;

    case H_ContentLength: ContentLength = atoi(v); break;

    /** Transport: RTP/AVP;unicast;source=x.x.x.x;client_port=1026-1027;server_port=8000-8001;ssrc=C6237B32 */
    case H_Transport:
    {
        // search for server_port parameter
        if ((s = strstr(v, SRV_PORT_PARAM))) {
            s += sizeof(SRV_PORT_PARAM) - 1;
            r_rtp_port = atoi(s);
        };

        if ((s = strstr(v, SSRC_PARAM))) {
            s += sizeof(SSRC_PARAM) - 1;
            string v(s);
            hextrim(v, ssrc);
            DBG("H_Transport ssrc=%04x", ssrc);
        }
        break;
    }

    /** Session: 21A3F0B1;timeout=65 */
    case H_Session:
    {
        const char *s = (const char *)memchr(v, ';', vl);
        session_id    = s ? string(v, s - v) : string(v, vl);
        break;
    }

    case H_Notify_Reason: notify_reason = str2NotifyReason(v, vl); break;

    case H_RTP_Info:
        if ((s = strstr(v, STREAMID_PARAM))) {
            s += sizeof(STREAMID_PARAM) - 1;
            streamid = atoi(s);
        };
        if ((s = strstr(v, RTPTIME_PARAM))) {
            s += sizeof(RTPTIME_PARAM) - 1;
            rtptime = atol(s);
        };
        if ((s = strstr(v, SSRC_PARAM))) {
            s += sizeof(SSRC_PARAM) - 1;
            string v(s);
            hextrim(v, ssrc);
            DBG("H_RTP_Info ssrc=%04x", ssrc);
        };
        break;

    default:;
    }

#undef SRV_PORT_PARAM
#undef STREAMID_PARAM
#undef RTPTIME_PARAM
}


void RtspMsg::parse_header_line(const char *line, size_t len)
{
    const char *val = strchr(line, ':');

    if (!val)
        return;

    size_t hdr_len = val - line;
    int    hdr     = str2hdr(line, hdr_len);

    if (hdr == H_UNPARSED)
        return;

    ++val; // skip ':'
    len -= hdr_len + 1;

    // ltrim()
    while (len && isspace(*val)) {
        val++;
        --len;
    }

    process_header(hdr, val, len);

    header[hdr] = string(val, len);
}


void RtspMsg::parse_msg(int type, const string &data)
{
    const char *s = data.data(), *p;

    rtptime = 0;

    while ((p = strstr(s, "\r\n"))) {

        size_t len = p - s;

        if (len) {
            if (s == data.data()) {

                if (type == RTSP_REQUEST)
                    parse_request_line(s, len);
                else
                    parse_status_line(s, len);

            } else
                parse_header_line(s, len);
        }

        s = (p + 2);

        if (!len)
            break; /** CRLF CRLF*/
    }

    ssize_t processed = s - data.data(), tail = data.length() - processed;

    if (!ContentLength)
        size = processed;
    else {
        /// check if we got all content data
        if (tail >= ContentLength) {
            body = string(s, ContentLength);
            size = processed + ContentLength;
        } else
            size = 0;
    }
}

RtspMsg::RtspMsg(MSG_TYPE _type, const string &data)
    : type(_type)
    , ssrc(0)
    , cseq(0)
    , code(0)
    , r_rtp_port(0)
    , ContentLength(0)
    , size(0)
{
    parse_msg(type, data);
}

RtspMsg::RtspMsg(int method, const string &_uri, uint64_t owner_id)
    : owner_id(owner_id)
    , type(RTSP_REQUEST)
    , method(method)
    , version("RTSP/1.0")
    , uri(_uri)
{
}

RtspSession::RtspSession(RtspClient *_agent, const sockaddr_storage &_saddr, int _slot)
    : agent(_agent)
    , slot(_slot)
    , cseq(0)
    , fd(-1)
    , saddr(_saddr)
    , state(Closed)
{
    am_inet_pton(agent->localMediaIP().c_str(), &l_saddr);
    am_set_port(&l_saddr, 0);

    reconnect_interval = agent->getReconnectInterval();

    connect();
}


RtspSession::~RtspSession()
{
    if (fd == -1)
        return;

    ::close(fd);
}


void RtspSession::close()
{
    DBG("####### %s %s:%d state=%d", __func__, am_inet_ntop(&saddr).c_str(), am_get_port(&saddr), state);

    {
        AmLock l(cseq2id_mutex);
        cseq2id_map.clear();
    }

    state = Closed;
    cseq  = 0;
    buffer.clear();

    if (fd == -1)
        return;

    ::close(fd); /** close() delete sockfd from epoll set */
    fd = -1;
}


/** send RTSP OPTIONS as HELLO for starting connection and check server status */
void RtspSession::init_connection()
{
    rtspSendMsg(RtspMsg(OPTIONS, "*"));
}


/**
    Request-Line = Method SP Request-URI SP RTSP-Version CRLF

    Send formated request structure
    return CSeq
*/
int RtspSession::rtspSendMsg(const RtspMsg &msg)
{
    ostringstream ss;

    uint32_t _cseq = (msg.type == RTSP_REQUEST ? ++cseq : msg.cseq);

    if (msg.type == RTSP_REQUEST)
        ss << Method_str[msg.method] << " rtsp://" << am_inet_ntop(&saddr) << ":" << am_get_port(&saddr)
           << "/" + msg.uri + " " + msg.version + "\r\n";
    else
        ss << msg.version << " " << msg.code << " " << msg.reason << "\r\n";

    ss << "CSeq: " << _cseq << "\r\n";

    for (auto &hdr : msg.header)
        ss << Header_str[hdr.first] << ": " << hdr.second << "\r\n";

    if (session_id.length())
        ss << "Session: " + session_id + "\r\n";

    if (msg.body.length()) {
        ss << "\r\n" + msg.body + "\r\n";
    }

    ss << "\r\n";

    string requst_body = ss.str();

    DBG("\n%s", requst_body.c_str());

    if (::send(fd, requst_body.c_str(), requst_body.length(), MSG_NOSIGNAL) == -1) {
        ERROR("RtspSession::request send(): %s", strerror(errno));
        close();
        return 0;
    }

    /** Store CSeq for stream */
    if (msg.owner_id) {
        AmLock l(cseq2id_mutex);
        cseq2id_map.insert(std::pair<uint32_t, uint64_t>(_cseq, msg.owner_id));
    }

    return _cseq;
}


void RtspSession::process_response(RtspMsg &msg)
{
    DBG("\n%.*s", (int)buffer.size(), buffer.data());

    if (!msg.code) {
        ERROR("####### RtspSession::process_response() response.code=0, garbage in buffer ???");
        close();
        return;
    }

    if (msg.code == agent->shutdown_code()) {
        state = RtspSession::Shuttingdown;
        DBG("RTSP server in shutdown mode %u %s", msg.code, msg.reason.c_str());
    } else
        state = RtspSession::Active;

    session_id = msg.session_id;

    if (unlikely(!msg.cseq)) {
        ERROR("###### NOT found CSeq header in response");
        return;
    }

    {
        AmLock l(cseq2id_mutex);

        auto it = cseq2id_map.find(msg.cseq);

        if (it == cseq2id_map.end())
            return;

        msg.owner_id = it->second;

        cseq2id_map.erase(it);
    }

    agent->onRtspReply(msg);
}


void RtspSession::process_server_request(RtspMsg &req)
{
    DBG("\n%.*s", (int)buffer.size(), buffer.data());

    RtspMsg msg = RtspMsg(RTSP_REPLY);

    msg.version    = req.version;
    msg.cseq       = req.cseq;
    msg.session_id = req.session_id;

    if (req.method == PLAY_NOTIFY) {

        msg.code   = 200;
        msg.reason = "OK";

        if (req.notify_reason == NR_end_of_stream)
            agent->onRtspPlayNotify(req);
        else
            ERROR("Unsupported Notify-reason");

    } else {
        msg.code   = 405;
        msg.reason = "Method Not Allowed";
    }

    rtspSendMsg(msg);
}


/**
 * RFC 2326
 *
 *    Request-Line = Method SP Request-URI SP RTSP-Version CRLF; 6.1 Request Line
 *
 *
 *    Response =  Status-Line ; Section 7.1
 *    *( general-header   ; Section 5
 *    | response-header   ; Section 7.1.2
 *    | entity-header )   ; Section 8.1
 *    CRLF
 *    [ message-body ]    ; Section 4.3
 *
 *   Status-Line = RTSP-Version SP Status-Code SP Reason-Phrase CRLF
 *
 *   RTSP-Version = "RTSP" "/" 1*DIGIT "." 1*DIGIT
 */

static inline bool is_rtsp_status_line(const char *data, size_t data_length)
{
    const char  *rtsp_ver_str = "RTSP/";
    const size_t len          = strlen(rtsp_ver_str);

    return data_length > len && strncmp(data, rtsp_ver_str, len) == 0;
}


size_t RtspSession::parse_server_response()
{
    RtspMsg msg = RtspMsg(RTSP_REPLY, buffer);

    if (msg.size)
        process_response(msg);

    return msg.size;
}


size_t RtspSession::parse_server_request()
{
    RtspMsg msg = RtspMsg(RTSP_REQUEST, buffer);

    if (msg.size)
        process_server_request(msg);

    return msg.size;
}


void RtspSession::in_event()
{
    for (;;) {
        char    buf[RTSP_BUFFER_SIZE];
        ssize_t bytes = ::recv(fd, buf, sizeof(buf), MSG_NOSIGNAL);

        if (unlikely(bytes == -1)) {

            if (errno != EAGAIN) {
                ERROR("%s: %s", __func__, strerror(errno));
                close();
            }

            return;
        }

        buffer.assign(buf, bytes);

        if (bytes < RTSP_BUFFER_SIZE)
            break;
    }

    /**
     * if we didn't get all body according to Content-Length
     * processed_bytes is ZERO
     */
    // One empty line (CRLF) to indicate the end of the header section;
    const std::string s{ "\r\n\r\n" };

    while (buffer.find(s) != std::string::npos) {

        size_t processed_bytes =
            is_rtsp_status_line(buffer.data(), buffer.size()) ? parse_server_response() : parse_server_request();
        if (processed_bytes)
            buffer.erase(0, processed_bytes);
        else
            break;
    }
}


bool RtspSession::epoll_link(int op, uint32_t events)
{
    struct epoll_event ev;

    bzero(&ev, sizeof(struct epoll_event));
    ev.events  = events;
    ev.data.fd = slot;

    return agent->link(fd, op, ev);
}


void RtspSession::on_timer(uint64_t timer_val)
{
    if (state == Active || timer_val - last_activity < (uint64_t)reconnect_interval)
        return;

    close();
    connect();
}


void RtspSession::connect()
{
    last_activity = agent->get_timer_val();

    if ((fd = ::socket(saddr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
        ERROR("socket(): %m");
        return;
    }
    SOCKET_LOG("socket(saddr.ss_family(%d), SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP ) = %d", saddr.ss_family, fd);

    if (::bind(fd, reinterpret_cast<sockaddr *>(&l_saddr), SA_len(&l_saddr)) == -1)
        ERROR("bind(): %m");

    state = Connected;

    if (::connect(fd, reinterpret_cast<sockaddr *>(&saddr), SA_len(&saddr)) == -1) {
        if (errno == EINPROGRESS)
            state = Connecting;
        else {
            close();
            return;
        }
    }

    uint32_t events = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR;

    if (state != Connected)
        events |= EPOLLOUT;

    if (!epoll_link(EPOLL_CTL_ADD, events))
        close();

    if (state == Connected)
        init_connection();
}


void RtspSession::handler(uint32_t ev)
{
    if (ev & ~(EPOLLIN | EPOLLOUT)) {
        int       err = 0;
        socklen_t len = sizeof(err);

        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

        ERROR("%s: fd=%d %s [%s]:%u", __func__, fd, err ? strerror(err) : "Peer shutdown", am_inet_ntop(&saddr).c_str(),
              am_get_port(&saddr));

        close();
        return;
    }

    if (ev & EPOLLIN)
        in_event();

    if (ev & EPOLLOUT) {
        state = Connected;

        DBG("%s fd=%d connected [%s]:%u", __func__, fd, am_inet_ntop(&saddr).c_str(), am_get_port(&saddr));

        if (epoll_link(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))
            init_connection();
        else
            close();
    }
}
