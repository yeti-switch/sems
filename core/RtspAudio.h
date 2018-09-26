#pragma once

#include "AmSession.h"
#include "RtspConnection.h"

using namespace Rtsp;

class RtspClient;

using Rtsp::RtspMsg;
using Rtsp::RtspSession;

class RtspAudio  :   public AmRtpAudio
{
    typedef enum {
        Ready = 0,
        Progress,
        Playing
    } State;

        uint64_t            id;             /** unique RtspAudio ID */
        RtspClient          *agent;
        AmSession           *session;       /** Session owning this stream */

        int                 md;             /** media server descriptor */
        int                 streamid;       /** streamid from media server RTP-Info header */
        int                 last_sent_cseq; /** cseq of the last sent request */

        State               state;
        string              uri;
        AmSdp               offer, answer;
        // RtspMsg             req;

    private:
        void    initRtpAudio(unsigned short int r_rtp_port);
        int     initRtpAudio_by_sdp(const char *sdp_msg);
        void    describe();
        void    teardown();
        void    setup(int l_port);
        void    play();
        void    rtsp_play(const RtspMsg &msg);
        void    onRtpTimeout();

    public:
        RtspAudio(AmSession* _s, const string &uri);
        ~RtspAudio();

        int     getStreamID() { return streamid; }
        bool    isPlaying()    { return state == Playing; }

        void    close();
        void    open(const string& uri);
        void    onRtspMessage(const RtspMsg &msg);
        void    onRtspPlayNotify(const RtspMsg &msg);

};
