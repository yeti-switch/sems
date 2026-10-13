/*
 * Media transport endpoint: owns the media transport(s) + ICE/DTLS/ZRTP contexts +
 * the inbound receive/demux path for a media connection. Serves one stream (1:1,
 * non-bundle) or several (1:N, RFC 9143 BUNDLE). It is the object AmMediaTransport
 * talks back to (the receive sink).
 */
#pragma once

#include "AmMediaTransport.h"
#include "AmRtpPacket.h"
#include "sip/ssl_settings.h"

#include <netinet/in.h>
#include <chrono>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include <list>

class AmRtpStream;
class AmSession;
struct SdpMedia;

class AmMediaEndpoint
#ifdef WITH_ZRTP
    : public ZrtpContextSubscriber
#endif
{
  protected:
    // --- served streams ---
    std::list<AmRtpStream *> streams;
    AmSession               *session;

    // --- transport parameters ---
    int       l_if;
    TransProt transport;
    bool      multiplexing; // rtcp-mux; seeded from session at creation, then owned here

    // set by init() (transport state)
    bool connection_is_muted;
    bool relay_is_muted;

    // symmetric RTP (transport-level): enable set on entering passive mode; endless seeded from session
    bool symmetric_rtp_enable;
    bool symmetric_rtp_endless;

    // endpoint-level (transport aggregate) stats
    unsigned long long dropped_packets_count;
    unsigned long      incoming_bytes;
    unsigned long      rtp_parse_errors;
    unsigned long      out_of_buffer_errors;
    unsigned long      srtp_unprotect_errors;

    // --- ICE state + security contexts (one set per endpoint/transport) ---
    bool        is_ice_stream;
    bool        ice_controlled;
    uint64_t    ice_tiebreaker;
    std::string ice_pwd, ice_ufrag, ice_remote_pwd, ice_remote_ufrag;

    std::unique_ptr<IceContext>  ice_context[MAX_TRANSPORT_TYPE];
    std::unique_ptr<DtlsContext> dtls_context[MAX_TRANSPORT_TYPE];
    SSLKeyLogger                *ssl_key_log_file;
#ifdef WITH_ZRTP
    zrtpContext zrtp_context;
#endif

    // --- transport set (primary = cur_rtp_trans; for a fax endpoint it is FAX_TRANSPORT) ---
    std::vector<AmMediaTransport *> ip4_transports, ip6_transports;
    AmMediaTransport               *cur_rtp_trans;
    AmMediaTransport               *cur_rtcp_trans;

    sockaddr_storage learned_rtp_addr;
    /** MediaEstablishedEvent already posted; re-armed by clearEstablished() on ICE restart */
    bool media_established_fired;
    /** raw-relay mode: endpoint carries a single non-RTP stream (UDPTL/fax); mutually exclusive with bundle */
    bool raw_mode;
    /** wall-clock anchor for measuring media setup latency reported with MediaEstablishedEvent */
    std::chrono::steady_clock::time_point media_setup_start;

    // --- inbound packet pool ---
    PacketMem<RTP_STREAM_BUF_PACKETS_COUNT> mem;

    void         calcRtpPorts(AmMediaTransport *tr_rtp, AmMediaTransport *tr_rtcp);
    virtual void initIP4Transport();
    virtual void initIP6Transport();
    void         setCurrentTransport(AmMediaTransport *transport);
    void         initIce();

  public:
    AmMediaEndpoint(AmRtpStream *s, AmSession *sess, int iface);
    virtual ~AmMediaEndpoint();

    AmRtpStream *getStream(const AmRtpPacket *p = nullptr) const;
    void         addMember(AmRtpStream *s);    // attach (1:1 first, or BUNDLE join);
    void         removeMember(AmRtpStream *s); // detach (releaseEndpoint or BUNDLE leave)
    size_t       memberCount() const { return streams.size(); }
    AmSession   *getSession() const { return session; }

    AmMediaTransport *getCurRtpTrans() const { return cur_rtp_trans; }
    AmMediaTransport *getCurRtcpTrans() const { return cur_rtcp_trans; }

    void iterateTransports(std::function<void(AmMediaTransport *)> it);

    // --- transport / addresses / ports ---
    void      setTransport(TransProt tr) { transport = tr; }
    TransProt getTransport() const { return transport; }
    void      setLocalIP(AddressType addrtype = AT_NONE);
    string    getLocalIP();
    string    getLocalAddress();
    int       getLocalPort();
    int       getLocalRtcpPort();
    int       getRPort(int type);
    string    getRHost(int type);

    // transport-mediated operations (transport-readiness checked inside).
    void fillSdpOffer(SdpMedia &m);
    void fillSdpAnswer(const SdpMedia &offer, SdpMedia &answer);
    int  sendRtp(AmRtpPacket *p, AmStreamConnection::ConnectionType type);
    int  sendRtcp(AmRtpPacket *p);
    int  sendUdptl(AmRtpPacket *p);
    void setRawMode();
    void stopReceiving();
    void resumeReceiving();
    void setLogger(msg_logger *l);
    void setSensor(msg_sensor *s);
    void fillIceStats(std::vector<IceContextStat> &out);
    void fillDtlsStats(std::vector<DtlsHandshakeStat> &out);
    void fillTransportsInfo(AmArg &transports);
    void getInfo(AmArg &ret);
    void update_sender_stats(const AmRtpPacket &p);

    // drop/received-byte counters are endpoint-level (transport aggregate), not per-stream
    void               inc_drop_pack() { dropped_packets_count++; }
    void               updateRcvdBytes(unsigned long bytes) { incoming_bytes += bytes; }
    unsigned long long getDroppedPackets() const { return dropped_packets_count; }
    unsigned long      getRcvdBytes() const { return incoming_bytes; }
    unsigned long      getRtpParseErrors() const { return rtp_parse_errors; }
    unsigned long      getOutOfBufferErrors() const { return out_of_buffer_errors; }
    unsigned long      getSrtpUnprotectErrors() const { return srtp_unprotect_errors; }

    // symmetric RTP / passive are transport-level (independent of bundle), owned here
    bool isSymmetricRtpEnable() const { return symmetric_rtp_enable; }
    bool isSymmetricRtpEndless() const { return symmetric_rtp_endless; }
    void setSymmetricRtpEndless(bool endless) { symmetric_rtp_endless = endless; }
    // mute: 1:1 now; in bundle must mute all streams attached to the endpoint
    void setMute(bool mute);
    bool getLocalAddr(sockaddr_storage *a);
    void getRAddr(sockaddr_storage *a);
    void getRAddr(int type, sockaddr_storage *a);
    void setRAddr(const string &addr, unsigned short port);
    void setPassiveMode(bool p);
    bool getPassiveMode() const { return cur_rtp_trans ? cur_rtp_trans->getPassiveMode() : false; }
    void setMultiplexing(bool m) { multiplexing = m; }
    bool isMultiplexing() const { return multiplexing; }

    virtual bool isZrtpEnabled() const;

    // transport-level init;
    // re-appliable / soft-idempotent (re-INVITE via change detection);
    // early-returns for a=bundle-only / port-0 member
    // mute flags computed by init() (transport-level)
    // Returns 0 on success, -1 on error.
    int  init(const AmSdp &local, const AmSdp &remote, int media_index, bool sdp_offer_owner, bool force_passive_mode,
              string &init_error);
    bool isConnectionMuted() const { return connection_is_muted; }
    bool isRelayMuted() const { return relay_is_muted; }

    // --- ICE / DTLS / ZRTP contexts ---
    void          useIce() { is_ice_stream = true; }
    bool          isIceStream() const { return is_ice_stream; }
    void          setIceStream(bool v) { is_ice_stream = v; }
    bool          isIceControlled();
    uint64_t      getIceTieBreaker();
    void          onIceRoleConflict();
    IceContext   *getIceContext(uint8_t tt);
    DtlsContext  *getDtlsContext(uint8_t tt);
    void          initDtls(uint8_t tt, bool client);
    void          applyIceParams(SdpMedia &m);
    void          onSrtpKeysAvailable(int tt, uint16_t profile, const string &lk, const string &rk);
    void          allowStunConnection(AmMediaTransport *t, sockaddr_storage *ra, int prio);
    void          allowStunPair(AmMediaTransport *t, sockaddr_storage *ra);
    void          dtlsSessionActivated(AmMediaTransport *t, uint16_t profile, const std::vector<uint8_t> &lk,
                                       const std::vector<uint8_t> &rk);
    void          onCloseDtlsSession(uint8_t tt);
    SSLKeyLogger *getSklfile() const { return ssl_key_log_file; }
    void          setSklfile(SSLKeyLogger *l);
#ifdef WITH_ZRTP
    zrtpContext *getZrtpContext() { return &zrtp_context; }
    void         initZrtp();
    void         startZrtp();
    void         zrtpSessionActivated(srtp_profile_t profile, const std::vector<uint8_t> &lk,
                                      const std::vector<uint8_t> &rk) override;
    int          send_zrtp(unsigned char *buffer, unsigned int size) override;
#endif

    // --- inbound (sink) — called by AmMediaTransport ---
    AmRtpPacket *createRtpPacket();
    AmRtpPacket *reuseBufferedPacket();
    void         clearRTPTimeout(struct timeval *recv_time);
    void         onErrorRtpTransport(AmStreamConnection::ConnectionError err_id, const string_view &err_str,
                                     AmMediaTransport *t, int err_code = 0);
    void         onRtpPacket(AmRtpPacket *p, AmMediaTransport *t);
    void         onRtcpPacket(AmRtpPacket *p, AmMediaTransport *t);
    void         onUdptlPacket(AmRtpPacket *p, AmMediaTransport *t);
    void         onRawPacket(AmRtpPacket *p, AmMediaTransport *t);
    void         onLeavePassiveMode();
    void         onRtpEndpointLearned();
    void         learnRtpEndpoint(const sockaddr_storage *raddr);
    virtual void onTransportEstablished();
    void         clearEstablished();
    void         resetMediaSetupTimer();
};
