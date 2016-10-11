#pragma once

#include "AmSession.h"
#include "RtspAudio.h"
#include "RtspClient.h"

#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <map>



class RtspClient;
class RtspAudio;
class MediaServer;


struct RtspMessage {
    typedef enum {
        Request = 0,
        Response
    } RtspMessageType;
    RtspMessageType type;

    typedef enum {
        HDR_Unknown = 0,
        HDR_Accept,
        HDR_ContentType,
        HDR_ContentLength,
        HDR_CSeq,
        HDR_Session,
        HDR_Transport,
        HDR_Date,
        HEADER_MAX
    } Hdr;

    typedef std::map<const Hdr, string> Header;
    typedef Header::const_iterator  HeaderIterator;

    Header header;

    RtspMessage(RtspMessageType type): type(type) {}

    static Hdr str2hdr(const char *hdr);
};



struct RtspRequest: public RtspMessage {

    typedef enum {
        METH_DESCRIBE,
        METH_PLAY,
        METH_PAUSE,
        METH_SETUP,
        METH_TEARDOWN,
        METH_OPTIONS,
        METH_MAX
    } Method;
    Method method;

    string uri;

    RtspRequest() : RtspMessage(RtspMessage::Request) {}
    RtspRequest(Method _method, const string &_uri)
        : RtspMessage(RtspMessage::Request), method(_method), uri(_uri) {}

    inline void operator()(Method _method, const string &_uri)
    {
        method = _method;
        uri = _uri;
        header.clear();
    }
};


class RtspResponse : public RtspMessage {

    void parse_status_line(char *line);

  public:

    string              version;
    int                 code;
    string              reason;
    int                 CSeq;
    int                 ContentLength;
    size_t              size;
    unsigned short int  r_rtp_port;
    string              session_id;
    string              body;

    RtspResponse(char *msg, int length);
    void parse_header_line(char *line, size_t len);
    void process_header(const Hdr hdr, char *v, size_t vl);
};


struct RtspStream {

    typedef enum {
        Disconnected = 0,
        Connected,
        Playing,
    } State;

    State       state;
    RtspAudio   *audio;
    MediaServer *server;
    string      uri;
    //std::queue<string>  requestQueue;
    RtspRequest         request;
    //RtspResponse        response;

    RtspStream(RtspAudio *_audio, string _uri);
    //RtspStream(RtspStream * const &orig) {}
    ~RtspStream();

    void update(const string &_uri);
    void response(RtspResponse &response);
    void describe();
    void setup(int l_port);
    void play(RtspResponse &response);
    void close();
};


class MediaServer // : virtual protected EpollFD, TimerFD
{
    public:
        typedef enum {
            Closed = 0,
            Connecting,
            Connected,
            Active,
            Shuttingdown
        } state_t;

    private:

        typedef std::map<int, RtspStream *> CSecStreamMap;
        typedef CSecStreamMap::iterator     CSecStreamIterator;


        RtspClient              *dispatcher;

        CSecStreamMap           CSeq2StreamMap;
        string                  session_id;
        int                     CSeq;

        int                     fd;
        int                     slot;
        int                     reconnect_interval;
        uint64_t                last_activity;
        sockaddr_storage        l_saddr;
        sockaddr_storage        saddr;
        state_t                 state;
        char                    payload[USHRT_MAX];

        MediaServer() {}
        void close();
        void connect();
        void init_connection();
        bool epoll_link(int op, uint32_t events);
        void in_event();

    public:
        MediaServer(RtspClient *_dispatcher,const sockaddr_storage &_saddr, int _slot);
        ~MediaServer();

        void                process_response(RtspResponse &response);
        void                process_response_buffer(char *buffer, int length);
        void                async_IO_event(int events);
        void                request(RtspRequest &request, RtspStream *stream = 0);
        void                removeStream(RtspStream *stream);
        size_t              map_size() { return CSeq2StreamMap.size();  }
        state_t             get_state() { return state; }
        void                handler(uint32_t ev);
        void                on_timer(uint64_t timer_val);
};

