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
#include "RtspConnection.h"
#include "RtspAudio.h"

using std::string;
using std::ostringstream;


static const int RTSP_BUFFER_SIZE                = 2048;


static const char *Method_str[] = { "DESCRIBE", "PLAY", "PAUSE", "SETUP", "TEARDOWN", "OPTIONS" };
static const char *Header_str[] = { "Unknown", "Accept", "Content-Type", "Content-Length", "CSeq", "Session", "Transport", "Date" };


RtspMessage::Hdr RtspMessage::str2hdr(const char *hdr)
{
    for( int i = RtspMessage::HDR_Accept; i< RtspMessage::HEADER_MAX; ++i )
        if(!strcmp(const_cast<char*>(Header_str[i]), hdr))
            return (RtspMessage::Hdr)i;

    return HDR_Unknown;
}


RtspResponse::RtspResponse(char *msg, int length)
    : RtspMessage(RtspMessage::Response), size(0),ContentLength(0), CSeq(0), code(0), r_rtp_port(0)
{
    char *p, *s =  msg;

    while( (p=strstr(s, "\r\n")) )
    {
        *p = 0;
        int len = strlen(s);

        if(len)
        {
            if( s == msg )
                parse_status_line(s);
            else
                parse_header_line(s,len);
        }
        s = (p+2);

        if(!len)
            break; /** CRLF CRLF*/
    }

    if(ContentLength)
        body = string(s, ContentLength);

    size = std::min( static_cast<long>(length), (s + ContentLength) - msg);
}


void RtspResponse::parse_status_line(char *line)
{
    char *p, *ver=NULL, *code_str=NULL, *reason= NULL;

    if((p=strstr(line, " ")))
    {
        *p = 0;
        ver = line;
        line = ++p;

        if( (p=strstr(line, " ")) )
        {
            *p = 0;
            code_str = line;
            reason = ++p;
        }
    }

    if(ver && code_str && reason)
    {
        version    = ver;
        code       = atoi(code_str);
        reason     = reason;
    }
}


void RtspResponse::parse_header_line(char *line, size_t len)
{
    char *h=line, *val;

    if(!(val=strstr(line, ": ")))
        return;

    size_t hdr_len = val-h;

    *val = 0;
    val +=2;

    Hdr hdr = str2hdr(h);

    process_header(hdr, val, len-hdr_len);

    header[hdr] = val;
}


void RtspResponse::process_header(const Hdr hdr, char *v, size_t vl)
{
#define SRV_PORT_PARAM "server_port="
    char *s, *e;

    switch(hdr)
    {
        case HDR_CSeq:              CSeq = atoi(v); break;

        case HDR_ContentLength:     ContentLength = atoi(v); break;

        case HDR_Transport:
        { /** Transport: RTP/AVP;unicast;source=x.x.x.x;client_port=1026-1027;server_port=8000-8001;ssrc=C6237B32 */
            //search for server_port parameter
            if((s = strstr(v, SRV_PORT_PARAM)) ) {
                s += sizeof(SRV_PORT_PARAM)-1;
                //cut params
                e = (char *)memchr(s, ';', vl - (s-v));
                if(e) *e = 0;
                r_rtp_port = atoi(s);
            };
            break;
        }

        case HDR_Session:
        { /** Session: 21A3F0B1;timeout=65 */
            //cut parameters
            char *s = (char *)memchr(v, ';', vl);
            if(s) *s = 0;

            session_id = v;
            break;
        };
        default:;
    }

#undef SRV_PORT_PARAM
}


RtspStream::RtspStream(RtspAudio *_audio, string _uri)
    : state(RtspStream::Disconnected), server(0), audio(_audio), uri(_uri)
{}


void RtspStream::close()
{
    if(server)
    {
        struct RtspRequest req(RtspRequest::METH_TEARDOWN, uri);
        server->request(req, this);
    }

    //audio->sendEvent(AmAudioEvent::noAudio);
}


RtspStream::~RtspStream()
{
    DBG("####### RtspStream::~RtspStream() %p", this);

    if(server)
    {
       server->removeStream(this);
       DBG("Removed from server");
    }
}

void RtspStream::update(const string &_uri)
{
    if(server && uri.length()) // state == plaing
    {
        struct RtspRequest req(RtspRequest::METH_TEARDOWN, uri);
        server->request(req, this);
    }

    uri = _uri;
}


void RtspStream::describe()
{
    if(server)
    {
        struct RtspRequest req(RtspRequest::METH_DESCRIBE, uri);
        server->request(req, this);
    }
}


void RtspStream::setup(int l_port)
{
    if(server)
    {
        DBG("####### RtspStream::setup() server->state %d", server->get_state());

        struct RtspRequest req(RtspRequest::METH_SETUP, uri);
        req.header[RtspRequest::HDR_Transport] = "RTP/AVP;unicast;client_port=" + int2str(l_port)+"-"+int2str(l_port + 1);
        server->request(req, this);
    }
}


void RtspStream::play(RtspResponse &response)
{
    if( !uri.length() )
    {
        ERROR("%s Uri must be set by setup()", __func__);
        return;
    }

    try
    {
        audio->initRtpAudio(response.r_rtp_port);

        if(server)
        {
            struct RtspRequest req(RtspRequest::METH_PLAY, uri);
            server->request(req,this);
            audio->play();
        }
    }
    catch (AmSession::Exception &e)
    {
        DBG("####### catched AmSession::Exception(%d,%s)", e.code, e.reason.c_str());
    }
}


void RtspStream::response(RtspResponse &response)
{
    RtspMessage::HeaderIterator it;

    DBG("####### RtspStream::response() got CSeq %d code %d", response.CSeq, response.code);

    /** Check ContentType header after DESCRIBE request */
    it = response.header.find(RtspMessage::HDR_ContentType);

    if( it != response.header.end() && strstr(it->second.c_str(), "application/sdp") )
    {
        try
        {
            int l_port = audio->initRtpAudio_by_sdp(response.body.c_str());
            setup(l_port);

        } catch (AmSession::Exception &e)
        {
            INFO("####### catched AmSession::Exception(%d,%s)", e.code, e.reason.c_str());
        }
    }

    /** Check Transport header after SETUP request */
    it  = response.header.find(RtspMessage::HDR_Transport);
    if( it != response.header.end() )
        play(response);
}







MediaServer::MediaServer(RtspClient *_dispatcher, const sockaddr_storage &_saddr, int _slot)
    : dispatcher(_dispatcher),saddr( _saddr ), state( Closed ), CSeq(0), slot(_slot)
{
    DBG("### %s %s:%d", __func__, am_inet_ntop(&saddr).c_str(), am_get_port(&saddr));

    am_inet_pton(dispatcher->localMediaIP().c_str(), &l_saddr);

    connect();
}


MediaServer::~MediaServer()
{
    DBG("### %s", __func__);
    ::close(fd);
}


void MediaServer::removeStream(RtspStream *stream)
{
    for( CSecStreamIterator sit = CSeq2StreamMap.begin(); sit != CSeq2StreamMap.end(); ++sit )
        if(sit->second == stream)
            CSeq2StreamMap.erase(sit);
}


void MediaServer::close()
{
    DBG("####### %s %s:%d state=%d", __func__,
        am_inet_ntop(&saddr).c_str(), am_get_port(&saddr), state);

    if( fd != -1 )
    {
        ::close(fd);    /** close() delete sockfd from epoll set */
        fd = -1;

    }

    CSeq = 0;
    state = MediaServer::Closed;

    // We need to send AmAudioEvent::noAudio to all streams on this server
    //AmEventDispatcher::instance()->post(session->getLocalTag(),
      //                      new AmAudioEvent(AmAudioEvent::noAudio) );

    CSeq2StreamMap.clear();
}


/** send RTSP OPTIONS as HELLO for starting connection and check server status */
void MediaServer::init_connection()
{
    struct RtspRequest req(RtspRequest::METH_OPTIONS, "*");
    request(req);
}


/**
    Request-Line = Method SP Request-URI SP RTSP-Version CRLF

    Send formated request structure
    return CSeq
*/
void MediaServer::request(RtspRequest &request, RtspStream *stream)
{
    ostringstream ss;

    ss << Method_str[request.method] << " rtsp://" << am_inet_ntop(&saddr) \
        << ":" << am_get_port(&saddr) << "/" + request.uri + " RTSP/1.0\r\n";

    ss << "CSeq: " << (++CSeq) << "\r\n";

    for(RtspMessage::HeaderIterator it = request.header.begin(); it != request.header.end(); ++it)
        ss << Header_str[it->first] << ": " << it->second << "\r\n";

    if(session_id.length())
        ss << "Session: " + session_id  + "\r\n";

    ss <<  "\r\n";

    string requst_body = ss.str();

    DBG("MediaServer::send_request\n%s", requst_body.c_str());

    if(::send(fd, requst_body.c_str(), requst_body.length(), MSG_NOSIGNAL) == -1)
    {
        ERROR("MediaServer::request send(): %s\n", strerror(errno));
        close();
        return;
    }

    /** Store CSeq for stream */
    if(stream)
    {
        std::pair<CSecStreamIterator, bool> result;

        result = CSeq2StreamMap.insert( std::make_pair(CSeq, stream) );

        DBG("####### MediaServer::request() stream %p", stream);

        if( result.second  )
            DBG("####### INSERTED %s", stream->uri.c_str());
        else
            DBG("####### UPDATED %s ??? ", stream->uri.c_str());
    }
}


void MediaServer::process_response(RtspResponse &response)
{
    if( !response.code )
    {
        ERROR("####### MediaServer::process_response() response.code=0, garbage in buffer ???");
        close();
        return;
    }

    if( response.code ==  dispatcher->shutdown_code() )
    {
        state = MediaServer::Shuttingdown;
        DBG("RTSP server in shutdown mode %u %s", response.code, response.reason.c_str());
    }
    else
        state = MediaServer::Active;

    session_id = response.session_id;

    if(response.CSeq)
    {
        /** Lookup stream by CSeq id */
        CSecStreamIterator sit = CSeq2StreamMap.find(response.CSeq);

        if( sit != CSeq2StreamMap.end() )
        {
            RtspStream *stream  = sit->second;

            if(response.code == 200 )
                stream->response(response);
            else
                AmSessionContainer::instance()->postEvent(
                            stream->audio->getLocalTag(),
                            new RtspNoFileEvent(stream->uri));

            //INFO("CSeq2StreamMap.erase %p", stream);
            //CSeq2StreamMap.erase(sit);
        }
        else
            DBG("###### NO stream for CSeq %d", response.CSeq);
    }
    else
        DBG("###### NOT found CSeq header in response");


}


/**
 * RFC 2326
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
void MediaServer::process_response_buffer(char *buffer, int length)
{
    char *s = buffer;

    while(length > 0)
    {
        RtspResponse response = RtspResponse(s, length);

        DBG("####### RTSP server response %u %s CSeq=%d", response.code, response.reason.c_str(), response.CSeq);

        if(!response.size)
            break;

        process_response(response);

        if(response.size != (size_t)length)
            DBG("####### MediaServer::process_response_buffer() length=%d size=%ld", length, response.size);

        s += response.size;
        length -= response.size;
    }
}


void MediaServer::in_event()
{
    char buffer[RTSP_BUFFER_SIZE];
    int length;

    // nread = ::read( fd, &payload, sizeof(payload)-1 );?

    while( (length = ::recv(fd, buffer, RTSP_BUFFER_SIZE-1, MSG_NOSIGNAL)) > 0 )
    {
        buffer[length] = 0;

        process_response_buffer(buffer, length);
    };

    //INFO("####### %s length=%d errno=%d %s", __func__, length, errno, strerror(errno));

    if( length  == -1 &&  errno == EAGAIN)
        return;

    ERROR("%s: %s", __func__, strerror(errno));
    close();
}


bool MediaServer::epoll_link(int op, uint32_t events)
{
    struct epoll_event ev;

    ev.events   = events;
    ev.data.fd  = slot;

    return dispatcher->link(fd, op, ev);
}


void MediaServer::on_timer(uint64_t timer_val)
{
    if( state != Active && timer_val - last_activity > (uint64_t)reconnect_interval )
    {
        close();
        connect();
    }
}


void MediaServer::connect()
{
    last_activity = dispatcher->get_timer_val();


    if( (fd = ::socket(saddr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP )) == -1 ) {
        ERROR("socket(): %m");
        return;
    }

    if( ::bind(fd, reinterpret_cast<sockaddr *>(&l_saddr), SA_len(&l_saddr)) == -1 )
        ERROR("bind(): %m");

    state = Connected;

    if(::connect( fd, reinterpret_cast<sockaddr *>(&saddr), SA_len(&saddr)) == -1) {
        if( errno == EINPROGRESS )
            state = Connecting;
        else {
            close();
            return;
        }
    }

    uint32_t events = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR;

    if(state != Connected)
        events |= EPOLLOUT;

    if( !epoll_link(EPOLL_CTL_ADD, events) )
        close();

    if(state == Connected)
        init_connection();
}


void print_events(const char *func, uint32_t events)
{

    char buf[128];
    int len = 0;
    buf[0] = 0;

    if(events & EPOLLIN)    len += sprintf(&buf[len],"EPOLLIN ");
    if(events & EPOLLOUT)   len += sprintf(&buf[len],"EPOLLOUT ");
    if(events & EPOLLPRI)   len += sprintf(&buf[len],"EPOLLPRI ");
    if(events & EPOLLERR)   len += sprintf(&buf[len],"EPOLLERR ");
    if(events & EPOLLHUP)   len += sprintf(&buf[len],"EPOLLHUP ");
    if(events & EPOLLRDHUP) len += sprintf(&buf[len],"EPOLLRDHUP ");

    // INFO("%s: handler: 0x%08x %s",  func, events, buf);
}


void MediaServer::handler(uint32_t ev)
{
    // INFO("%s: fd=%d ",__func__, fd);

    print_events(__func__, ev);

    if(ev & ~(EPOLLIN | EPOLLOUT))
    {
        int err = 0;
        socklen_t len = sizeof(err);

        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

        ERROR("%s: fd=%d %s [%s]:%u",
            __func__, fd,
            err ? strerror(err) : "Peer shutdown",
            am_inet_ntop(&saddr).c_str(), am_get_port(&saddr));

        close();
        return;
    }

    if( ev & EPOLLIN )
        in_event();

    if( ev & EPOLLOUT )
    {
        state = Connected;

        DBG("%s fd=%d connected [%s]:%u", __func__, fd,
             am_inet_ntop(&saddr).c_str(), am_get_port(&saddr) );

        if( epoll_link(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR) )
            init_connection();
        else
            close();
    }
}
