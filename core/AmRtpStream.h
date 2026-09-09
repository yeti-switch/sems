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
#include "AmMediaEvents.h"
#include "AmDtmfSender.h"
#include "AmComfortNoiseSender.h"
#include "sip/msg_sensor.h"
#include "sip/ssl_settings.h"
#include "media/AmMediaTransport.h"
#include "media/AmMediaEndpoint.h"
#include "ObjectsCounter.h"

#include <netinet/in.h>

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <memory>
#include <atomic>
#include <chrono>

using std::pair;
using std::string;
using std::vector;

// return values of AmRtpStream::receive
#define RTP_EMPTY       0  // no rtp packet available
#define RTP_ERROR       -1 // generic error
#define RTP_PARSE_ERROR -2 // error while parsing rtp packet
#define RTP_TIMEOUT     -3 // last received packet is too old
#define RTP_DTMF        -4 // dtmf packet has been received
#define RTP_BUFFER_SIZE -5 // buffer overrun
#define RTP_UNKNOWN_PL  -6 // unknown payload

/**
 * Forward declarations
 */
class AmAudio;
class msg_logger;
class AmMediaEndpoint;
struct SdpPayload;
struct amci_payload_t;

/** helper class for assigning boolean flag to a payload ID
 * it is used to check if the payload should be relayed or not */
class PayloadMask {
  private:
    unsigned char bits[16];

  public:
    // clear flag for all payloads
    void clear();

    void set(unsigned char payload_id)
    {
        if (payload_id < 128)
            bits[payload_id / 8] |= 1 << (payload_id % 8);
    }

    // set all flags to 'true'
    void set_all();

    // invert all flags
    void invert();

    // get given flag
    bool get(unsigned char payload_id)
    {
        if (payload_id > 127) {
            ERROR("BUG: payload_id out of range");
            return false;
        }
        return (bits[payload_id / 8] & (1 << (payload_id % 8)));
    }

    PayloadMask() { clear(); }
    PayloadMask(bool _set_all)
    {
        if (_set_all)
            set_all();
        else
            clear();
    }
    PayloadMask(const PayloadMask &src);
};

class PayloadRelayMap {
  private:
    unsigned char map[128];

  public:
    void clear();

    // set given flag (TODO: once it shows to be working, change / and % to >> and &)
    void set(unsigned char payload_id, unsigned char mapped_payload_id) { map[payload_id] = mapped_payload_id; }

    // get given flag
    unsigned char get(unsigned char payload_id)
    {
        if (map[payload_id] == 0) {
            return payload_id;
        }
        return map[payload_id];
    }

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
class AmRtpStream : public AmObject
#ifdef OBJECTS_COUNTER
    ,
                    ObjCounter(AmRtpStream)
#endif
{
    friend class AmMediaEndpoint;

  protected:
    /** transport endpoint: owns transports + ICE/DTLS/ZRTP contexts + inbound receive/demux.
     *  Lazily created on first getEndpoint() via the virtual createEndpoint() factory, so subclasses
     *  (e.g. RtspAudio) supply their own endpoint type regardless of where the stream is constructed.
     *  Non-owning: ownership is handed to the session pool on creation (a session-less mock owns its own). */
    mutable AmMediaEndpoint *endpoint;

    /** non-owning view of the endpoint staged by an in-flight media transaction (new port);
     *  while set, SDP is built from it while @endpoint keeps serving media until commit. */
    AmMediaEndpoint *pending_endpoint;

    virtual AmMediaEndpoint *createEndpoint() const
    {
        return new AmMediaEndpoint(const_cast<AmRtpStream *>(this), session, l_if);
    }

    // payload collection
    typedef std::vector<Payload> PayloadCollection;

    // list of locally supported payloads
    PayloadCollection payloads;

    // current payload (index into @payloads)
    int payload;

    unsigned long long tx_user_ts;

    RtcpBidirectionalStat rtp_stats;
    unsigned long long    last_send_rtcp_report_ts;

    std::map<uint32_t, std::vector<int>> incoming_payloads;
    std::map<uint32_t, std::vector<int>> incoming_relayed_payloads;
    std::vector<int>                     outgoing_payloads;
    std::vector<int>                     outgoing_relayed_payloads;
    unsigned long                        outgoing_bytes;

    int           last_not_supported_rx_payload;
    int           last_not_supported_tx_payload;
    unsigned long wrong_payload_errors;

    unsigned int dead_rtp_time;

    long int relay_ts_shift;

    struct PayloadMapping {
        int8_t  remote_pt; // remote payload type
        uint8_t index;     // index in payloads vector
    };

    typedef std::map<unsigned int, AmRtpPacket *, ts_less> ReceiveBuffer;
    typedef std::queue<AmRtpPacket *>                      RtpEventQueue;
    typedef std::map<unsigned char, PayloadMapping>        PayloadMappingTable;

    unsigned char recv_ctl_buf[RTP_PACKET_TIMESTAMP_DATASIZE];

    // mapping from local payload type to PayloadMapping
    PayloadMappingTable pl_map;

    /** SDP media slot number (n-th media line) */
    int sdp_media_index;

    /** RFC 3264: m= line disabled by setting its port to zero (kept as a placeholder, no media) */
    bool disabled;

    /** negotiated m= transport, cached (set by setTransport) so it can be reported without touching
     *  the endpoint (e.g. for a disabled stream's port-0 m= line); type is derived from it */
    TransProt transport;

    /** RTP sequence number */
    unsigned int sequence;

    /**
     Payload of last not-relayed received packet.
     Usefull to detect talk spurt, looking
     for comfort noise packets.
    */
    int last_payload;

    int                last_recv_payload;
    bool               last_recv_relayed;
    unsigned long long last_recv_ts;

    /** VAD signal: CN observed since last receive().*/
    bool recent_cn_observed;

    /**
     * Local interface used for this stream
     * (index into @AmLcConfig::Ifs)
     */
    int l_if;

    /** Timestamp of the last received RTP packet */
    struct timeval last_recv_time;

    /** Local and remote SSRC information */
    unsigned int l_ssrc;
    unsigned int r_ssrc;
    bool         r_ssrc_i;

    /** media bundling (RFC 9143) enabled for this stream*/
    bool bundle_enabled;
    /** negotiated mid of this stream and the MID RTP header extension id (0 = not negotiated);
     *  used to stamp the MID extension on outgoing RTP while bundling */
    string bundle_mid;
    int    bundle_mid_ext_id;

    /** marker flag */
    bool begin_talk;

    /** do check rtp timeout */
    bool monitor_rtp_timeout;

    /** Payload type for telephone event */
    unique_ptr<const SdpPayload> remote_telephone_event_pt;
    unique_ptr<const SdpPayload> local_telephone_event_pt;
    DECLARE_BITMAP_ALIGNED(local_telephone_event_payloads, 128 /* payload type is 7th bit field */);

    /** DTMF sender */
    AmDtmfSender dtmf_sender;

    /** Comfort Noise (RFC 3389) */
    unique_ptr<const SdpPayload> remote_comfort_noise_pt;
    AmComfortNoiseSender         cn_sender;

    /**
     * Receive buffer, queue and mutex
     */
    ReceiveBuffer receive_buf;
    RtpEventQueue rtp_ev_qu;
    AmMutex       receive_mut;

    /** precomputed or forced stream mute state */
    bool mute;
    /** should we send packets? affects SDP media send indication */
    bool sending;
    /** should we receive packets? if not -> drop. affect SDP media recv indication */
    bool receiving;

    /** if relay_stream is initialized, received RTP is relayed there */
    bool relay_enabled;
    /** if true, packets are note parsed or checked */
    bool relay_raw;
    /** pointer to relay stream.
      NOTE: This may only be accessed in initialization
      or by the AmRtpReceiver thread while relaying!  */
    AmRtpStream *relay_stream;
    /** control transparency for RTP seqno in RTP relay mode */
    bool relay_transparent_seqno;
    /** control transparency for RTP ssrc in RTP relay mode */
    bool relay_transparent_ssrc;
    /** filter RTP DTMF (2833 / 4733) in relaying */
    bool relay_filter_dtmf;
    /** Realy RTP DTMF
    bool filter (2833 / 4733) in active even in active state */

    bool force_relay_dtmf;
    bool relay_timestamp_aligning;

    /** relay CN payload type  */
    bool force_relay_cn;

    /** send initial rtp packet */
    bool rtp_ping;

    /** force packet buffering after relay */
    bool force_buffering;

    /** Session owning this stream */
    AmSession *session;

    /** Payload provider */
    AmPayloadProvider *payload_provider;

    /** insert packet in DTMF queue if correct payload */
    void recvDtmfPacket(AmRtpPacket * p);

    /** Clear RTP timeout at time recv_time */
    void clearRTPTimeout(struct timeval * recv_time);

    void relay(AmRtpPacket * p);

    /** Sets generic parameters on SDP media */
    void getSdp(SdpMedia & m);


    PayloadMask     relay_payloads;
    PayloadRelayMap relay_map;

    /** set to true if any data received */
    bool active;

    RtcpReportsPreparedData rtcp_reports;

    /**
     * Select a compatible default payload
     * @return -1 if none available.
     */
    int getDefaultPT();

    void payloads_id2str(const vector<int> i, vector<string> &s);

  public:
    /** should we receive RFC-2833-style DTMF even when receiving is disabled? */
    bool force_receive_dtmf;

    /** the string representation of the rtp stream initialization error */
    string init_error;

  private:
    void fill_sender_report(RtcpSenderReportHeader & s, struct timeval & now, unsigned int user_ts);

    void init_receiver_info(const AmRtpPacket &p);
    void update_receiver_stats(const AmRtpPacket &p);
    void fill_receiver_report(RtcpReceiverReportHeader & r, struct timeval & now);

    void rtcp_send_report(unsigned int user_ts);

  public:
    // --- transport endpoint (1:1; owned by the session pool) ---
    // getEndpoint: the active endpoint, lazily created on first access (single creation point for every
    //   stream/subclass) and handed to the session pool on creation.
    // sdpEndpoint: the endpoint SDP is built from - the one staged
    //   by an in-flight transaction, else the active one.
    // createDetachedEndpoint/setPendingEndpoint/clearPendingEndpoint: stage a reconfig
    //   for AmMediaTransaction (the staged endpoint is owned by the transaction until commit adopts it);
    // setEndpoint: re-points to a new endpoint on commit (does not free the old - the pool keeps it).
    // releaseEndpoint: hands off the live endpoint (it stays in the pool).
    AmMediaEndpoint *getEndpoint() const;
    AmMediaEndpoint *sdpEndpoint() const
    {
        return pending_endpoint ? pending_endpoint : getEndpoint();
    }
    AmMediaEndpoint *createDetachedEndpoint() const
    {
        return createEndpoint();
    }
    void setPendingEndpoint(AmMediaEndpoint * ep)
    {
        pending_endpoint = ep;
    }
    void clearPendingEndpoint()
    {
        pending_endpoint = nullptr;
    }
    void             setEndpoint(AmMediaEndpoint * ep);
    AmMediaEndpoint *releaseEndpoint();

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
    AmRtpStream(AmSession * _s, int _if, int media_index);

    /** Stops the stream and frees all resources. */
    virtual ~AmRtpStream();

    void update_sender_stats(const AmRtpPacket &p);

    bool process_dtmf_queue(unsigned int ts);

    void enableComfortNoise(unsigned int level, unsigned int interval_ms);

    unsigned int get_adjusted_ts(unsigned int user_ts);

    int send_udptl(unsigned int ts, unsigned char *buffer, unsigned int size);

    int send(unsigned int ts, unsigned char *buffer, unsigned int size);

    int compile_and_send(const int payload, bool marker, unsigned int ts, unsigned char *buffer, unsigned int size);

    int receive(unsigned char *buffer, unsigned int size);

    /** Insert an RTP packet to the buffer queue */
    void bufferPacket(AmRtpPacket * p);
    /* Get next packet from the buffer queue */
    int nextPacket(AmRtpPacket * &p);
    /** Try to reuse oldest buffered packet for newly coming packet */
    AmRtpPacket *reuseBufferedPacket();
    /** free buffered/queued packets via @owner's pool (the endpoint that received them) */
    void flushReceiveBuffer();

    void processRtcpTimers(unsigned long long system_ts, unsigned int user_ts);

    /** ping the remote side, to open NATs and enable symmetric RTP */
    virtual int ping(unsigned long long ts)
    {
        return 0;
    }

    // act on an existing endpoint only (no lazy creation): called on teardown, stream replacement,
    // disabled/port-0 m-lines and plain reporting, where materializing a transport would be wrong;
    // a no-op (or default) without an endpoint.
    void           stopReceiving();   // -> endpoint (remove from RTP receiver)
    void           resumeReceiving(); // -> endpoint (re-insert into RTP receiver)
    void           setLogger(msg_logger * _logger);
    void           setSensor(msg_sensor * _sensor);
    virtual int    getRPort(int type);
    virtual string getRHost(int type);
    void           setRAddr(const string &addr, unsigned short port);

    unsigned int get_ssrc()
    {
        return l_ssrc;
    }
    unsigned int get_rsrc()
    {
        return r_ssrc;
    }

    int  getLocalTelephoneEventPT();
    int  getLocalTelephoneEventRate();
    bool isLocalTelephoneEventPayload(unsigned char payload);
    void setPayloadProvider(AmPayloadProvider * pl_prov);

    int getSdpMediaIndex()
    {
        return sdp_media_index;
    }

    // RFC 3264: a disabled m= line keeps its slot at port 0 and carries no media
    void setDisabled(bool d)
    {
        disabled = d;
    }
    bool isDisabled() const
    {
        return disabled;
    }

    /** Set using transport */
    void      setTransport(TransProt trans);
    TransProt getTransport() const
    {
        return transport;
    }
    MediaType getMediaType() const
    {
        return (transport == TP_UDPTL || transport == TP_UDPTLSUDPTL) ? MT_IMAGE : MT_AUDIO;
    }

    int getPayloadType()
    {
        return payload;
    }
    int getLastPayload()
    {
        return last_payload;
    }
    string getPayloadName(int payload_type);
    bool   isPayloadCN(int payload_type) const;

    void replaceAudioMediaParameters(SdpMedia & m, unsigned int idx, AddressType addr_type);

    struct MediaStats {

        struct timeval     time_start;
        struct timeval     time_end;
        MathStat<uint32_t> rtt;
        uint32_t           dropped;
        uint32_t           out_of_buffer_errors;
        uint32_t           rtp_parse_errors;
        uint32_t           srtp_decript_errors;

        uint32_t rtcp_rr_sent, rtcp_rr_recv;
        uint32_t rtcp_sr_sent, rtcp_sr_recv;

        struct rtp_common {
            unsigned int            ssrc;
            struct sockaddr_storage addr;
            uint32_t                pkt;
            uint32_t                bytes;
            uint32_t                total_lost;
            vector<string>          payloads_transcoded;
            vector<string>          payloads_relayed;

            rtp_common();
        };

        struct rx_stat : public rtp_common {
            uint32_t           decode_errors;
            MathStat<long>     delta;
            MathStat<double>   jitter;
            MathStat<uint32_t> rtcp_jitter;

            rx_stat();
        };


        struct tx_stat : public rtp_common {
            MathStat<uint32_t> jitter;
        } tx;

        vector<struct rx_stat> rx;

        vector<IceContextStat>    ice;
        vector<DtlsHandshakeStat> dtls;

        MediaStats();
    };
    void getMediaStats(struct MediaStats & s);

    unsigned long getSentBytes()
    {
        return outgoing_bytes;
    }

    /**
     * Generate an SDP offer based on the stream capabilities.
     * @param offer the local offer to be filled/completed.
     */
    virtual void getSdpOffer(SdpMedia & offer);

    /**
     * Generate an answer for the given SDP media based on the stream capabilities.
     * @param offer the remote offer.
     * @param answer the local answer to be filled/completed.
     */
    virtual void getSdpAnswer(const SdpMedia &offer, SdpMedia &answer);

    enum class InitResult {
        Ok,
        NoStream,       // B2B slot without a stream attached (StreamData), nothing was initialized
        CodecError,     // payload negotiation failed; transport untouched, relay may still work
        TransportError, // no usable transport/connection to the remote media address
    };

    /**
     * Enables RTP stream.
     * @param local the SDP message generated by the local UA.
     * @param remote the SDP message generated by the remote UA.
     * @return InitResult; on error the reason is in init_error
     * @warning It is necessary to call getSdpOffer/getSdpAnswer prior to init(...)
     * @warning so that the internal SDP media line index is set properly.
     */
    virtual InitResult init(const AmSdp &local, const AmSdp &remote, bool sdp_offer_owner, bool force_passive_mode);

    /** set the RTP stream on hold */
    void setOnHold(bool on_hold);

    /** get whether RTP stream is on hold  */
    bool getOnHold();

    /** force stream mute flag */
    void setMute(bool mute)
    {
        this->mute = mute;
    }

    /** setter for monitor_rtp_timeout */
    void setMonitorRTPTimeout(bool m);
    /** getter for monitor_rtp_timeout */
    bool getMonitorRTPTimeout()
    {
        return monitor_rtp_timeout;
    }

    /*
     * clear RTP timeout to current time
     */
    void clearRTPTimeout();

    /** set relay stream for  RTP relaying */
    void setRelayStream(AmRtpStream * stream);

    /** set relay payloads for  RTP relaying */
    void setRelayPayloads(const PayloadMask &_relay_payloads);
    void setRelayPayloadMap(const PayloadRelayMap &relay_map);

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

    /** enable or disable initial rtp ping on stream initialization.
      also it will set mark for all packets to zero */
    void setRtpPing(bool enable);

    /** set dead rtp time for stream */
    void setRtpTimeout(unsigned int timeout);

    /** get dead rtp time */
    unsigned int getRtpTimeout();

    /** Quick hack to assign existing stream to another session. The stream should
     * not be reinitialised implicitly (it might be used for media traffic
     * already). */
    void changeSession(AmSession * _s)
    {
        session = _s;
    }

    void setForceBuffering(bool buffering)
    {
        force_buffering = buffering;
    }

    void         debug();
    virtual void getInfo(AmArg & ret);
};

// Local Variables:
// mode:C++
// End:
