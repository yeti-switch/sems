#pragma once

#include "AmSession.h"

#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <map>
using std::map;

class RtspClient;
class RtspAudio;

namespace Rtsp {

typedef enum {
    RTSP_UNKNOWN = 0,
    RTSP_REQUEST,
    RTSP_REPLY
} MSG_TYPE;


enum {
    DESCRIBE = 1,
    PLAY,
    PAUSE,
    SETUP,
    TEARDOWN,
    OPTIONS,
    PLAY_NOTIFY
};


enum {
    H_UNPARSED = 0,
    H_Accept,
    H_ContentType,
    H_ContentLength,
    H_CSeq,
    H_Session,
    H_Transport,
    H_Date,
    H_Range,
    H_Notify_Reason,
    H_RTP_Info,
};


enum {
    NR_end_of_stream = 1,
    NR_media_properties_update,
    NR_scale_change,
};


struct RtspMsg {

    typedef std::map<int, string> Header;
    typedef Header::const_iterator  HeaderIterator;

    uint64_t        owner_id;

    MSG_TYPE        type;
    int             method;
    int             notify_reason;
    int             streamid;
    int             cseq;

    int             code;

    Header          header;

    string          version;
    string          reason;
    string          session_id;
    string          uri;

    unsigned short int  r_rtp_port;
    int             ContentLength;
    string          body;

    size_t          size;

    RtspMsg() {}

    RtspMsg(MSG_TYPE type) : type(type) {}
    RtspMsg(MSG_TYPE type, const string &data);
    RtspMsg(int method, const string &_uri, uint64_t owner_id = 0);

    void    parse_request_line(const char *line, size_t len);
    void    parse_status_line(const char *line, size_t len);
    void    parse_header_line(const char *hdr, size_t len);
    void    process_header(int hdr, const char *v, size_t vl);
    void    parse_msg(int type, const string &data);
};


class RtspSession
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

        typedef std::map<uint32_t, uint64_t> CSec2AudioIdMap;

        CSec2AudioIdMap         cseq2id_map;

        RtspClient              *agent;
        int                     md;                 /** media server descriptor */
        int                     reconnect_interval;
        int                     slot;
        int                     cseq;
        int                     fd;

        uint64_t                last_activity;
        sockaddr_storage        l_saddr;
        sockaddr_storage        saddr;

        state_t                 state;
        string                  session_id;
        string                  buffer;

        RtspSession() {}

        void    close();
        void    connect();
        void    init_connection();
        bool    epoll_link(int op, uint32_t events);
        void    in_event();

        size_t  parse_server_response();
        size_t  parse_server_request();

        void    process_response(RtspMsg &msg);
        void    process_server_request(RtspMsg &req);

    public:

        RtspSession(RtspClient *_dispatcher,const sockaddr_storage &_saddr, int _slot);
        RtspSession(RtspSession&&) = default;
        RtspSession& operator=(RtspSession&&) = default;
        ~RtspSession();

        state_t get_state() { return state; }
        void    rtspSendMsg(const RtspMsg &msg);
        void    on_timer(uint64_t timer_val);
        void    handler(uint32_t ev);
};
}
