/*
 * Copyright (C) 2002-2003 Fhg Fokus
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/** @file AmRtpStream.h */
#pragma once

#include "AmSdp.h"
#include "AmThread.h"
#include "SampleArray.h"
#include "AmRtpPacket.h"
#include "rtcp/RtcpStat.h"
#include "AmEvent.h"
#include "AmDtmfSender.h"
#include "sip/msg_sensor.h"
#include "sip/ssl_settings.h"
#include "AmMediaTransport.h"
#include "AmZrtpConnection.h"

#include <netinet/in.h>

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <memory>
#include <atomic>

using std::string;
using std::vector;
using std::auto_ptr;
using std::pair;

// return values of AmRtpStream::receive
#define RTP_EMPTY        0 // no rtp packet available
#define RTP_ERROR       -1 // generic error
#define RTP_PARSE_ERROR -2 // error while parsing rtp packet
#define RTP_TIMEOUT     -3 // last received packet is too old
#define RTP_DTMF        -4 // dtmf packet has been received
#define RTP_BUFFER_SIZE -5 // buffer overrun
#define RTP_UNKNOWN_PL  -6 // unknown payload

#define RTP_STREAM_BUF_PACKETS_COUNT 32

/**
 * Forward declarations
 */
class  AmAudio;
class msg_logger;
struct SdpPayload;
struct amci_payload_t;

/**
 * This provides the memory for the receive buffer.
 */
template <int packets_count>
class PacketMem {
#define PacketMemUsedClearMask (~(ULONG_MAX>>(BITS_PER_LONG - packets_count)))
    AmRtpPacket packets[packets_count];
    unsigned long used; //used packets bitmask
  public:
    PacketMem()
      : used(PacketMemUsedClearMask)
    {}
    AmRtpPacket* newPacket()
    {
        if (!(~(used)))
            return nullptr;

        for(int i = 0; i < packets_count; i++) {
            if(!test_and_set_bit(i, &used)) {
                return &packets[i];
            }
        }

        return nullptr;
    }
    void freePacket(AmRtpPacket* p)
    {
        if (!p)  return;

        int idx = p-packets;

        assert(idx >= 0);
        assert(idx < packets_count);

        clear_bit(idx, &used);
        __sync_synchronize();
    }
    void clear()
    {
        used = PacketMemUsedClearMask;
        __sync_synchronize();
    }
    void debug()
    {
        DBG("used: 0x%lx",used);
    }
};

/** \brief event fired on RTP timeout */
class AmRtpTimeoutEvent
  : public AmEvent
{
  public:
    AmRtpTimeoutEvent()
      : AmEvent(0) { }
    ~AmRtpTimeoutEvent() { }
};

/** helper class for assigning boolean floag to a payload ID
 * it is used to check if the payload should be relayed or not */
class PayloadMask
{
  private:
    unsigned char bits[16];

  public:
    // clear flag for all payloads
    void clear();

    void set(unsigned char payload_id) { if (payload_id < 128) bits[payload_id / 8] |= 1 << (payload_id % 8); }

    // set all flags to 'true'
    void set_all();

    // invert all flags
    void invert();

    // get given flag
    bool get(unsigned char payload_id) { if (payload_id > 127) { ERROR("BUG: payload_id out of range\n"); return false; } return (bits[payload_id / 8] & (1 << (payload_id % 8))); }
    
    PayloadMask() { clear(); }
    PayloadMask(bool _set_all) { if (_set_all) set_all(); else clear(); }
    PayloadMask(const PayloadMask &src);
};

class PayloadRelayMap
{
  private:
    unsigned char map[128];

  public:
    void clear();

    // set given flag (TODO: once it shows to be working, change / and % to >> and &)
    void set(unsigned char payload_id, unsigned char mapped_payload_id) { map[payload_id] = mapped_payload_id; }

    // get given flag
    unsigned char get(unsigned char payload_id) { if(map[payload_id] == 0) { return payload_id; } return map[payload_id]; }

    PayloadRelayMap() { clear(); }
    PayloadRelayMap(const PayloadRelayMap &src);
};

/**
 * \brief represents one admissible payload type
 *
 *
 */
struct Payload {
    unsigned char pt;
    string        name;
    unsigned int  clock_rate;
    unsigned int  advertised_clock_rate; // differs for G722
    int           codec_id;
};

/**
 * \brief RTP implementation
 *
 * Rtp stream high level interface.
 */
class AmRtpStream
  : public AmObject
#ifdef WITH_ZRTP
  , public ZrtpContextSubscriber
#endif/*WITH_ZRTP*/
{
  protected:

    // payload collection
    typedef std::vector<Payload> PayloadCollection;

    // list of locally supported payloads
    PayloadCollection payloads;

    // current payload (index into @payloads)
    int payload;

    unsigned long long tx_user_ts;

    RtcpBidirectionalStat rtp_stats;
    struct timeval start_time;
    unsigned long long last_send_rtcp_report_ts;
    unsigned long long dropped_packets_count;

    std::vector<int> incoming_payloads;
    std::vector<int> incoming_relayed_payloads;
    std::vector<int> outgoing_payloads;
    std::vector<int> outgoing_relayed_payloads;
    unsigned long incoming_bytes;
    unsigned long outgoing_bytes;
    unsigned long decode_errors;
    unsigned long rtp_parse_errors;
    unsigned long out_of_buffer_errors;

    bool not_supported_rx_payload_local_reported;
    bool not_supported_rx_payload_remote_reported;
    bool not_supported_tx_payload_reported;
    unsigned long wrong_payload_errors;

    unsigned int dead_rtp_time;

    long int relay_ts_shift;

    struct PayloadMapping {
        int8_t remote_pt; // remote payload type
        uint8_t    index; // index in payloads vector
    };

    typedef std::map<unsigned int, AmRtpPacket*, ts_less> ReceiveBuffer;
    typedef std::queue<AmRtpPacket*>                      RtpEventQueue;
    typedef std::map<unsigned char, PayloadMapping>       PayloadMappingTable;

    unsigned char recv_ctl_buf[RTP_PACKET_TIMESTAMP_DATASIZE];

    // mapping from local payload type to PayloadMapping
    PayloadMappingTable pl_map;

    /** SDP media slot number (n-th media line) */
    int sdp_media_index;

    /** RTP sequence number */
    unsigned int sequence;

    /**
     Payload of last received packet.
     Usefull to detect talk spurt, looking
     for comfort noise packets.
    */
    int         last_payload;

    /**
    * Local interface used for this stream
    * (index into @AmLcConfig::Ifs)
    */
    int l_if;

    /** Timestamp of the last received RTP packet */
    struct timeval last_recv_time;

    /** Local and remote SSRC information */
    unsigned int   l_ssrc;
    unsigned int   r_ssrc;
    bool           r_ssrc_i;

    TransProt transport;
    bool is_ice_stream;
    string ice_pwd;
    string ice_ufrag;

    vector<AmMediaTransport*> ip4_transports;
    vector<AmMediaTransport*> ip6_transports;
    AmMediaTransport* cur_rtp_trans;
    AmMediaTransport* cur_rtcp_trans;
    AmMediaTransport* cur_udptl_trans;

    /** mute && port == 0 */
    bool           hold;

    /** marker flag */
    bool           begin_talk;

    /** do check rtp timeout */
    bool           monitor_rtp_timeout;

    /** Payload type for telephone event */
    unique_ptr<const SdpPayload> remote_telephone_event_pt;
    unique_ptr<const SdpPayload> local_telephone_event_pt;
    DECLARE_BITMAP_ALIGNED(local_telephone_event_payloads, 128 /* payload type is 7th bit field */);

    /** DTMF sender */
    AmDtmfSender   dtmf_sender;

    /**
    * Receive buffer, queue and mutex
    */
    PacketMem<RTP_STREAM_BUF_PACKETS_COUNT> mem;
    ReceiveBuffer   receive_buf;
    RtpEventQueue   rtp_ev_qu;
    AmMutex         receive_mut;

    /** should we receive packets? if not -> drop */
    bool receiving;

    /** if relay_stream is initialized, received RTP is relayed there */
    bool            relay_enabled;
    /** if true, packets are note parsed or checked */
    bool            relay_raw;
    /** pointer to relay stream.
      NOTE: This may only be accessed in initialization
      or by the AmRtpReceiver thread while relaying!  */
    AmRtpStream*    relay_stream;
    /** control transparency for RTP seqno in RTP relay mode */
    bool            relay_transparent_seqno;
    /** control transparency for RTP ssrc in RTP relay mode */
    bool            relay_transparent_ssrc;
    /** filter RTP DTMF (2833 / 4733) in relaying */
    bool            relay_filter_dtmf;
    /** Realy RTP DTMF
    bool filter (2833 / 4733) in active even in active state */

    bool            force_relay_dtmf;
    bool            relay_timestamp_aligning;

    /** relay CN payload type  */
    bool            force_relay_cn;

    /** endless symmetric rtp switching */
    bool            symmetric_rtp_endless;
    /** send initial rtp packet */
    bool            rtp_ping;

    /** force packet buffering after relay */
    bool            force_buffering;

    /** Session owning this stream */
    AmSession*         session;

    /** Payload provider */
    AmPayloadProvider* payload_provider;

    /** insert packet in DTMF queue if correct payload */
    void recvDtmfPacket(AmRtpPacket* p);

    /** Clear RTP timeout at time recv_time */
    void clearRTPTimeout(struct timeval* recv_time);

    void relay(AmRtpPacket* p);

    /** Sets generic parameters on SDP media */
    void getSdp(SdpMedia& m);


    PayloadMask relay_payloads;
    PayloadRelayMap relay_map;
    bool offer_answer_used;

    /** set to true if any data received */
    bool active;

    /* RTP and RTCP multiplexing mode*/
    bool multiplexing;

    /* reusing media transport for udptl packets(fax stream) */
    bool reuse_media_trans;
#ifdef WITH_ZRTP
    zrtpContext zrtp_context;
#endif/*WITH_ZRTP*/
    RtcpReportsPreparedData rtcp_reports;

    /**
    * Select a compatible default payload
    * @return -1 if none available.
    */
    int getDefaultPT();

    void payloads_id2str(const vector<int> i, vector<string> &s);

    void calcRtpPorts(AmMediaTransport* tr_rtp, AmMediaTransport* tr_rtcp);

    virtual void initIP4Transport();
    virtual void initIP6Transport();
  public:

    /** Mute */
    bool mute;

    /** should we receive RFC-2833-style DTMF even when receiving is disabled? */
    bool force_receive_dtmf;

  private:
    void fill_sender_report(RtcpSenderReportHeader &s, struct timeval &now, unsigned int user_ts);

    void init_receiver_info(const AmRtpPacket &p);
    void update_receiver_stats(const AmRtpPacket &p);
    void fill_receiver_report(RtcpReceiverReportHeader &r, struct timeval &now);

    void rtcp_send_report(unsigned int user_ts);
  public:
    /**
    * Set whether RTP stream will receive RTP packets internally (received packets will be dropped or not).
    */
    void setReceiving(bool r);

    /**
    * Stops RTP stream receiving RTP packets internally (received packets will be dropped).
    */
    void pause();

    /**
    * Resume a paused RTP stream internally (received packets will be ed).
    */
    void resume();

    /** Allocates resources for future use of RTP. */
    AmRtpStream(AmSession* _s, int _if);

    /** Stops the stream and frees all resources. */
    virtual ~AmRtpStream();

    void onErrorRtpTransport(const string& error, AmMediaTransport* transport);
    void onRtpPacket(AmRtpPacket* packet, AmMediaTransport* transport);
    void onRtcpPacket(AmRtpPacket* packet, AmMediaTransport* transport);
    void onUdptlPacket(AmRtpPacket* packet, AmMediaTransport* transport);
    void onRawPacket(AmRtpPacket* packet, AmMediaTransport* transport);
    void allowStunConnection(AmMediaTransport* transport, int priority);
    void dtlsSessionActivated(AmMediaTransport* transport, uint16_t srtp_profile,
                              const vector<uint8_t>& local_key, const vector<uint8_t>& remote_key);
    void update_sender_stats(const AmRtpPacket &p);
    void inc_drop_pack(){ dropped_packets_count++; }

    bool process_dtmf_queue(unsigned int ts);

    unsigned int get_adjusted_ts(unsigned int user_ts);

    int send_udptl( unsigned int ts,
        unsigned char* buffer,
        unsigned int   size );

    int send( unsigned int ts,
        unsigned char* buffer,
        unsigned int   size );

    int compile_and_send( const int payload, bool marker,
                unsigned int ts, unsigned char* buffer,
                unsigned int size );

    int receive( unsigned char* buffer, unsigned int size,
           unsigned int& ts, int& payload, bool &relayed);

    /** create and free an RTP packet*/
    AmRtpPacket* createRtpPacket();
    void freeRtpPacket(AmRtpPacket* packet);
    /** Insert an RTP packet to the buffer queue */
    void bufferPacket(AmRtpPacket* p);
    /* Get next packet from the buffer queue */
    int nextPacket(AmRtpPacket*& p);
    /** Try to reuse oldest buffered packet for newly coming packet */
    AmRtpPacket *reuseBufferedPacket();

#ifdef WITH_ZRTP
    zrtpContext* getZrtpContext() { return &zrtp_context; }
    void zrtpSessionActivated(const bzrtpSrtpSecrets_t *srtpSecrets);
    int send_zrtp(unsigned char* buffer, unsigned int size);
#endif/*WITH_ZRTP*/

    void processRtcpTimers(unsigned long long system_ts, unsigned int user_ts);

    /** ping the remote side, to open NATs and enable symmetric RTP */
    virtual int ping(unsigned long long ts) { return 0; }

    /**
    * This function must be called before setLocalPort, because
    * setLocalPort will bind the socket and it will be not
    * possible to change the IP later
    */
    virtual void setLocalIP(const string& host);

    /**
    * Initializes with a new random local port if 'p' is 0,
    * else binds the given port, and sets own attributes properly.
    */
    virtual int getLocalPort();
    virtual int getLocalRtcpPort();

    /**
    * Gets remote RTP port.
    * @return remote RTP port.
    */
    virtual int getRPort(int type);

    /**
    * Gets remote host IP.
    * @return remote host IP.
    */
    virtual string getRHost(int type);

    /**
    * Set remote IP & port.
    */
    void setRAddr(const string& addr, unsigned short port);

    /** Symmetric RTP & RTCP: passive mode ? */
    void setPassiveMode(bool p);
    bool getPassiveMode() { return cur_rtp_trans ? cur_rtp_trans->getPassiveMode() : false; }

    /** Set using transport */
    void setTransport(TransProt trans);

    /** Set using ice protocol */
    void useIce();

    /** Set using multiplexing for rtcp */
    virtual void setMultiplexing(bool multiplex);

    void setReuseMediaPort(bool reuse_media);
    void addAdditionTransport();

    unsigned int get_ssrc() { return l_ssrc; }
    unsigned int get_rsrc() { return r_ssrc; }

    int getLocalTelephoneEventPT();
    int getLocalTelephoneEventRate();
    bool isLocalTelephoneEventPayload(unsigned char payload);
    void setPayloadProvider(AmPayloadProvider* pl_prov);

    int getSdpMediaIndex() { return sdp_media_index; }
    void forceSdpMediaIndex(int idx) { sdp_media_index = idx; offer_answer_used = false; }
    int getPayloadType() { return payload; }
    int getLastPayload() { return last_payload; }
    string getPayloadName(int payload_type);

    void replaceAudioMediaParameters(SdpMedia &m, unsigned int idx, const string& relay_address);

    struct MediaStats {

        struct timeval time_start;
        struct timeval time_end;
        MathStat<uint32_t> rtt;
        uint32_t dropped;

        struct rtp_common {
            unsigned int ssrc;
            struct sockaddr_storage addr;
            uint32_t pkt;
            uint32_t bytes;
            uint32_t total_lost;
            std::vector<string> payloads_transcoded;
            std::vector<string> payloads_relayed;
        };

        struct rx_stat: public rtp_common {
            unsigned long decode_errors;
            unsigned long rtp_parse_errors;
            unsigned long out_of_buffer_errors;

            MathStat<long> delta;
            MathStat<double> jitter;
            MathStat<uint32_t> rtcp_jitter;
        } rx;

        struct tx_stat: public rtp_common {
            MathStat<uint32_t> jitter;
        } tx;

        MediaStats()
        {
            bzero(this, sizeof(struct MediaStats));
        }
    };
    void getMediaStats(struct MediaStats &s);

    unsigned long getRcvdBytes() { return incoming_bytes; }
    unsigned long getSentBytes() { return outgoing_bytes; }
    void updateRcvdBytes(unsigned long bytes) { incoming_bytes += bytes; }

    /**
    * Generate an SDP offer based on the stream capabilities.
    * @param index index of the SDP media within the SDP.
    * @param offer the local offer to be filled/completed.
    */
    virtual void getSdpOffer(unsigned int index, SdpMedia& offer);

    /**
    * Generate an answer for the given SDP media based on the stream capabilities.
    * @param index index of the SDP media within the SDP.
    * @param offer the remote offer.
    * @param answer the local answer to be filled/completed.
    */
    virtual void getSdpAnswer(unsigned int index, const SdpMedia& offer, SdpMedia& answer);

    /**
    * Enables RTP stream.
    * @param local the SDP message generated by the local UA.
    * @param remote the SDP message generated by the remote UA.
    * @warning It is necessary to call getSdpOffer/getSdpAnswer prior to init(...)
    * @warning so that the internal SDP media line index is set properly.
    */
    virtual int init(const AmSdp& local, const AmSdp& remote, bool force_passive_mode = false);

    void updateTransports();
    void applyIceParams(SdpMedia& sdp);

    /** set the RTP stream on hold */
    void setOnHold(bool on_hold);

    /** get whether RTP stream is on hold  */
    bool getOnHold();

    /** setter for monitor_rtp_timeout */
    void setMonitorRTPTimeout(bool m) { monitor_rtp_timeout = m; }
    /** getter for monitor_rtp_timeout */
    bool getMonitorRTPTimeout() { return monitor_rtp_timeout; }

    /*
    * clear RTP timeout to current time
    */
    void clearRTPTimeout();

    /** set relay stream for  RTP relaying */
    void setRelayStream(AmRtpStream* stream);

    /** set relay payloads for  RTP relaying */
    void setRelayPayloads(const PayloadMask &_relay_payloads);
    void setRelayPayloadMap(const PayloadRelayMap & relay_map);

    /** ensable RTP relaying through relay stream */
    void enableRtpRelay();

    /** disable RTP relaying through relay stream */
    void disableRtpRelay();

    /** enable or diable raw UDP relaying through relay stream */
    void setRawRelay(bool enable);

    /** is enable raw UDP relaying through relay stream */
    bool isRawRelay();

    /** enable or disable transparent RTP seqno for relay */
    void setRtpRelayTransparentSeqno(bool transparent);

    /** enable or disable transparent SSRC seqno for relay */
    void setRtpRelayTransparentSSRC(bool transparent);

    /** enable or disable filtering of RTP DTMF for relay */
    void setRtpRelayFilterRtpDtmf(bool filter);

    /** enable or disable timestamp aligning for relay */
    void setRtpRelayTimestampAligning(bool enable_aligning);

    /** enable or disable relay of RTP DTMF in active state */
    void setRtpForceRelayDtmf(bool relay);

    /** enable or disable relay of CN payload */
    void setRtpForceRelayCN(bool relay);

    /** enable or disable endless symmetric rtp switching */
    void setSymmetricRtpEndless(bool endless);
    bool isSymmetricRtpEndless();

    bool isZrtpEnabled();

    /** enable or disable initial rtp ping on stream initialization.
      also it will set mark for all packets to zero */
    void setRtpPing(bool enable);

    /** set dead rtp time for stream */
    void setRtpTimeout(unsigned int timeout);

    /** get dead rtp time */
    unsigned int getRtpTimeout();

    /** remove from RTP receiver */
    void stopReceiving();

    /** (re-)insert into RTP receiver */
    void resumeReceiving();

    /** Quick hack to assign existing stream to another session. The stream should
    * not be reinitialised implicitly (it might be used for media traffic
    * already). */
    void changeSession(AmSession *_s) { session = _s; }

    /** set destination for logging all received/sent RTP and RTCP packets */
    void setLogger(msg_logger *_logger);
    void setSensor(msg_sensor *_sensor);

    void setForceBuffering(bool buffering) { force_buffering = buffering; }

    void getMediaAcl(trsp_acl& acl);

    void debug();
    virtual void getInfo(AmArg &ret);
};

// Local Variables:
// mode:C++
// End:
