#ifndef __B2BMEDIA_H
#define __B2BMEDIA_H

#include "AmAudio.h"
#include "AmRtpStream.h"
#include "AmRtpAudio.h"
#include "AmMediaProcessor.h"
#include "AmDtmfDetector.h"

#include <functional>
#include <map>
#include <type_traits>

class AmB2BSession;
class AmMediaTransaction;

class B2BMediaStatistics {
  private:
    std::map<string, int> codec_write_usage;
    std::map<string, int> codec_read_usage;
    AmMutex               mutex;

  public:
    void reportCodecWriteUsage(string &dst);
    void reportCodecReadUsage(string &dst);
    void getReport(const AmArg &args, AmArg &ret);

    static B2BMediaStatistics *instance();
    void                       incCodecWriteUsage(const string &codec_name);
    void                       decCodecWriteUsage(const string &codec_name);
    void                       incCodecReadUsage(const string &codec_name);
    void                       decCodecReadUsage(const string &codec_name);
};

/** \brief Class for computing mask of payloads to relay
 *
 * */
class RelayController {
  public:
    virtual void computeRelayMask(const SdpMedia &m, bool &enable, PayloadMask &mask, PayloadRelayMap &map) = 0;
    virtual ~RelayController() {}
};

class StreamData {
  public:
    /** state as of the last SDP round. Held per-leg on StreamData; the two legs of
     *  a StreamPair are always kept in sync.
     *  Empty:       placeholder session slot (never was B2B-managed);
     *  ActiveAudio: audio m=, full playout/transcoding/DTMF/relay;
     *  ActiveRelay: non-audio canRelay m=, relay-only;
     *  Inactive:    was Active*, dropped out this round — warm slot kept, wiring torn down. */
    enum State { Empty, ActiveAudio, ActiveRelay, Inactive };

  private:
    /** owning session-leg; nullptr for a not-yet-attached leg (distributed B2B).
     * StreamData holds only per-pair-per-leg B2B meta. */
    AmB2BSession *leg;
    /** slot position, fixed at construction to the m= index. */
    int media_idx;
    /** current pair state (see enum State) */
    State state;
    /** media kind + transport from the m= line, kept for retro-materialising the
     *  session slot in setLeg() when the leg attaches after pair creation. */
    MediaType type;
    TransProt transport;
    /** Flag set when streams in A/B leg are correctly initialized (for
     * transcoding purposes). */
    bool initialized;
    //----------------------------------------------
    //      audio stream data parameters
    /** Non-stream input (required for music on hold for example). */
    AmAudio *in;
    /** Non-stream output */
    AmAudio *out;

    /** remembered value of the option from AmB2BSession */
    bool force_symmetric_rtp;
    /** Enables inband dtmf detection */
    bool enable_dtmf_transcoding;
    /** filter out samples with inbound dtmf */
    bool enable_inbound_dtmf_filtering;
    /** Low fidelity payloads for which inband DTMF transcoding should be used */
    vector<SdpPayload> lowfi_payloads;
    /** DTMF detector used by dtmf_queue */
    AmDtmfDetector *dtmf_detector;
    /** Queue for handling raw DTMF events.
     *
     * It is rather quick hack to make B2B media working with current code.
     * Each stream can use different sampling rate and thus DTMF detection need
     * to be done independently for each stream. */
    AmDtmfEventQueue *dtmf_queue;

    /** RTP relay (temporarily) paused?
     * relay stream may still be set up and updated */
    bool            relay_paused;
    bool            relay_enabled;
    std::string     relay_address;
    int             relay_port;
    PayloadMask     relay_mask;
    PayloadRelayMap relay_map;

    bool muted;
    // for performance monitoring
    int    outgoing_payload;
    int    incoming_payload;
    string outgoing_payload_name;
    string incoming_payload_name;

    bool sdp_offer_owner;

  public:
    StreamData()                    = delete;
    StreamData(StreamData const &)  = delete;
    StreamData(StreamData const &&) = delete;
    StreamData(AmB2BSession *leg, int media_idx, State initial, MediaType type, TransProt transport,
               AmMediaTransaction *tx = nullptr);
    ~StreamData();

    State getState() const { return state; }

    void clear();
    /** initialise per-pair-per-leg meta */
    void initialize(bool audio);
    /** attach/detach a leg. In tx mode `tx` receives the new stream (staged). */
    void setLeg(AmB2BSession *l, bool audio, AmMediaTransaction *tx = nullptr);
    /** move this leg to `desired` (empty→active promotes the session slot,
     *  active*→inactive tears down relay wiring). Updates state on completion. */
    void transition(State desired);
    void debug();
    void getInfo(AmArg &ret);
    void mute(bool set_mute);

    /** live RTP stream from the session pool; nullptr for an empty/detached leg */
    AmRtpAudio *getStream() const;
    bool        isInitialized() { return initialized; }
    void        setLogger(msg_logger *logger)
    {
        if (auto *s = getStream())
            s->setLogger(logger);
    }
    void setSklLogger(SSLKeyLogger *logger)
    {
        if (auto *s = getStream())
            s->getEndpoint()->setSklfile(logger);
    }
    void setSensor(msg_sensor *sensor)
    {
        if (auto *s = getStream())
            s->setSensor(sensor);
    }
    void setRtpTimeout(unsigned int timeout)
    {
        if (auto *s = getStream())
            s->setRtpTimeout(timeout);
    }
    void setMonitorRtpTimeout(bool enable)
    {
        if (auto *s = getStream())
            s->setMonitorRTPTimeout(enable);
    }
    void stopStreamProcessing()
    {
        if (auto *s = getStream())
            s->stopReceiving();
    }
    void resumeStreamProcessing()
    {
        if (auto *s = getStream())
            s->resumeReceiving();
    }
    void clearRTPTimeout()
    {
        if (auto *s = getStream())
            s->clearRTPTimeout();
    }
    void setReceiving(bool r)
    {
        if (auto *s = getStream())
            s->setReceiving(r);
    }
    void setLocalIP(AddressType type)
    {
        if (auto *s = getStream())
            s->getEndpoint()->setLocalIP(type);
    }
    void getSdpOffer(SdpMedia &m)
    {
        if (auto *s = getStream())
            s->getSdpOffer(m);
    }
    void getSdpAnswer(const SdpMedia &offer, SdpMedia &answer)
    {
        if (auto *s = getStream())
            s->getSdpAnswer(offer, answer);
    }
    void replaceAudioMediaParameters(SdpMedia &m, unsigned int idx, AddressType type)
    {
        if (auto *s = getStream())
            s->replaceAudioMediaParameters(m, idx, type);
    }
    void setSdpOfferOwner(bool owner) { sdp_offer_owner = owner; }

    /** initialize given stream for transcoding & regular audio processing*/
    AmRtpStream::InitResult initStream(PlayoutType playout_type, AmSdp &local_sdp, AmSdp &remote_sdp);

    void     setInput(AmAudio *_in) { in = _in; }
    void     setOutput(AmAudio *_in) { out = _in; }
    AmAudio *getInput() { return in; }
    AmAudio *getOutput() { return out; }

    void updateSendStats();
    void updateRecvStats(AmRtpStream *s);
    void resetStats();

    void clearDtmfSink();

    /** Set relay stream and payload IDs to be relayed.
     *
     * Removes the stream from AmRtpReceiver before updating and returns it back
     * once done. */
    void setRelayStream(AmRtpAudio *other);

    /** computes and stores payloads that can be relayed based on the
     * corresponding 'peer session' remote media line (i.e. what accepts the
     * other remote end directly) */
    void setRelayPayloads(const SdpMedia &m, RelayController *ctrl);

    void setRelayDestination(const string &connection_address, int port);

    /** set relay temporarily to paused (stream relation may still be up) */
    void setRelayPaused(bool paused);

    /** release old and store new DTMF sink */
    void setDtmfSink(AmDtmfSink *dtmf_sink);

    /** Processes raw DTMF events in own queue. */
    void processDtmfEvents()
    {
        if (dtmf_queue)
            dtmf_queue->processEvents();
    }

    /** Sends DTMF */
    void sendDtmf(int event, unsigned int duration_ms, int volume);

    /** Writes data to won stream. Data are read either from local alternative
     * input (in) or from stream given by src parameter.
     *
     * Buffer is just space used to read data before writing them,
     * AmMediaProcessor buffer should be propagated here (see AmMediaSession) */
    int writeStream(unsigned long long ts, unsigned char *buffer, StreamData &src);
};

/** \brief Class for control over media relaying and transcoding in a B2B session.
 *
 * This class manages RTP streams of both call legs, configures AmRtpStream
 * relaying functionality and in case media needs to be transcoded its
 * AmMediaSession interface implementation reads data from RTP streams in one
 * leg and writes them to appropriate RTP streams of the other leg.
 *
 * The signaling parts of the session (AmB2BSession instances for both call
 * legs) drive updates via createUpdateStreams() and rewrite outgoing SDP through
 * replaceConnectionAddress().
 *
 * B2B SDP is not built from AmSession's offer/answer machinery — we relay the
 * remote SDP with light edits (filter/inject payloads), so no local↔remote
 * payload-ID mapping is kept. Payload IDs come from the remote party unchanged.
 *
 * TODO:
 *  - hold-state should be driven by signaling (AmB2BSession): stop sending
 *    audio, or send hold music. Right now setOnHold()/setReceiving() are
 *    disabled in initStream() (see the commented-out lines) because they
 *    override SDP-negotiated state.
 *
 *  - correct sampling periods when relaying/transcoding according to values
 *    advertised in the relayed local SDP.
 *
 *  - SSRC / seq. no. for mixed transcode+relay streams: transparent SSRC/seq.
 *    for relayed payloads together with our own for transcoded payloads looks
 *    inconsistent to wireshark and possibly clients. Options: disable
 *    transparent SSRC/seq. when any payload is being transcoded, and if we
 *    take over the seq. numbers, still propagate observed losses (offset by
 *    the difference between received and sent seq. numbers).
 *    Caveat: forcing our own SSRC breaks sources that themselves mix audio
 *    from several inputs — there we must keep transparent SSRC.
 *
 *  - in-band DTMF detection inside the relay-only path (where packets are
 *    not decoded) is not supported. Do we need it?
 */

class AmB2BMedia : public AmMediaSession
#ifdef OBJECTS_COUNTER
    ,
                   ObjCounter(AmB2BMedia)
#endif
{
  private:
    /* remembered both legs of the B2B call
     * currently required for DTMF processing and used for reading RTP relay
     * parameters (rtp_relay_transparent_seqno, rtp_relay_transparent_ssrc,
     * rtp_interface) */
    AmB2BSession *a, *b;

    class StreamPair {
      public:
        // pair state lives per-leg on StreamData (a and b are always kept in sync).
        using State = StreamData::State;

        StreamData a, b;
        int        media_idx;

      public:
        StreamPair()                    = delete;
        StreamPair(StreamPair const &)  = delete;
        StreamPair(StreamPair const &&) = delete;
        StreamPair(AmB2BSession *_a, AmB2BSession *_b, int _media_idx, State _state, MediaType _type,
                   TransProt _transport, AmMediaTransaction *tx_a = nullptr, AmMediaTransaction *tx_b = nullptr)
            : a(_a, _media_idx, _state, _type, _transport, tx_a)
            , b(_b, _media_idx, _state, _type, _transport, tx_b)
            , media_idx(_media_idx)
        {
        }

        ~StreamPair() {}

        bool audio() const { return a.getState() == StreamData::ActiveAudio; }
        bool active() const
        {
            return a.getState() == StreamData::ActiveAudio || a.getState() == StreamData::ActiveRelay;
        }
        bool empty() const { return a.getState() == StreamData::Empty; }

        bool requiresProcessing()
        {
            if (audio())
                return a.getInput() || b.getInput();
            return false;
        }
        void setLogger(msg_logger *logger)
        {
            a.setLogger(logger);
            b.setLogger(logger);
        }
        void setSklLogger(SSLKeyLogger *logger)
        {
            a.setSklLogger(logger);
            b.setSklLogger(logger);
        }
        void setASensor(msg_sensor *sensor) { a.setSensor(sensor); }
        void setBSensor(msg_sensor *sensor) { b.setSensor(sensor); }
        void setRtpTimeout(bool a_leg, unsigned int timeout)
        {
            if (a_leg)
                a.setRtpTimeout(timeout);
            else
                b.setRtpTimeout(timeout);
        }
        void setRtpTimeout(unsigned int timeout)
        {
            a.setRtpTimeout(timeout);
            b.setRtpTimeout(timeout);
        }
        void setMonitorRtpTimeout(bool enable)
        {
            a.setMonitorRtpTimeout(enable);
            b.setMonitorRtpTimeout(enable);
        }
    };

    /** Callgroup reqired by AmMediaProcessor to distinguish
     * AmMediaProcessorThread which should take care about media session.
     *
     * It might be handy to use own generated callgroup independent on caller's
     * and callee's one. (FIXME: not sure if it is worth consumed additional
     * resources). */
    string callgroup;

    // needed for updating relayed payloads
    AmSdp a_leg_local_sdp, a_leg_remote_sdp;
    AmSdp b_leg_local_sdp, b_leg_remote_sdp;
    bool  have_a_leg_local_sdp, have_a_leg_remote_sdp;
    bool  have_b_leg_local_sdp, have_b_leg_remote_sdp;

    AmMutex mutex;
    int     ref_cnt;

    /** Playout type describes what kind of buffering will be used for audio
     * streams. Please note that ADAPTIVE_PLAYOUT requires some kind of
     * detection if there is really data to read from the buffer because the get
     * function always return something regardless if something was written into
     * or not.
     */
    PlayoutType playout_type;

    std::list<StreamPair> streams;
    std::list<StreamPair> pending_streams;
    bool                  in_transaction_mode = false;
    // per-leg OA-completion flags accumulated during a tx; commit fires when both are true
    bool a_leg_oa_completed = false;
    bool b_leg_oa_completed = false;
    // per-leg "next OA is yeti's own local reply" flag; consumed & cleared by notifyOACompleted
    bool a_leg_local_oa = false;
    bool b_leg_local_oa = false;
    // snapshots of local/remote SDPs taken at beginTransactionMode; restored on rollback
    AmSdp prev_a_leg_local_sdp, prev_a_leg_remote_sdp;
    AmSdp prev_b_leg_local_sdp, prev_b_leg_remote_sdp;

    bool a_leg_muted, b_leg_muted;
    // bool a_leg_receiving, b_leg_receiving;

    bool relay_paused;

    /** post-SDP applier: state transitions + per-pair relay setup + audio init/wiring in one walk.
     *  updateAudioPair inits/syncs an audio pair; updateRelayPair wires a non-audio relay pair. */
    bool updateStreamsUnsafe(bool a_leg, RelayController *ctrl, bool sdp_offer_owner, string &error);
    void updateAudioPair(StreamPair & pair, bool a_leg, RelayController *ctrl, const string &connection_address,
                         const SdpMedia &m, bool &needs_processing);
    void updateRelayPair(StreamPair & pair, bool a_leg, const string &connection_address, const SdpMedia &m);

    /** first-seen pair creation from SDP; idempotent.
     *  local=true skips creation for m-lines beyond current pair count (local in-dialog processing
     *  with extra m-lines that are disabled in the SIP reply but must not pollute pair/slot state). */
    void createStreams(const AmSdp &sdp, bool a_leg);

    // callback returning bool: true stops iteration early; void callbacks always iterate to the end
    template <typename F> void forEachPair(F && fn, bool include_pending = true)
    {
        auto visit = [&](StreamPair &p) {
            if constexpr (std::is_same_v<std::invoke_result_t<F, StreamPair &>, bool>)
                return fn(p);
            else {
                fn(p);
                return false;
            }
        };
        for (auto &p : streams)
            if (visit(p))
                return;
        if (include_pending)
            for (auto &p : pending_streams)
                if (visit(p))
                    return;
    }

    /** finalise pair states once both legs have SDP collected */
    void applyStateTransitions();

    /** initialises pair streams; throws string on a transport-level failure */
    void initPairStream(StreamPair & pair);
    /** syncs pair cross-leg wiring (DTMF sink, relay stream, stereo recorders) */
    void syncPairWiring(StreamPair & pair);

    void setMuteFlag(bool a_leg, bool set);
    void changeSessionUnsafe(bool a_leg, AmB2BSession *new_session);
    void clearAudioUnsafe(bool a_leg);

    msg_logger   *logger;  // log RTP traffic
    SSLKeyLogger *sklfile; // log secure keys
    msg_sensor   *asensor; // RTP traffic mirroring
    msg_sensor   *bsensor;

    bool ignore_relay_streams; // skip relay streams create/update

    /** pending in/out per media_idx, applied when the pair is created. */
    std::map<unsigned, AmAudio *> pending_a_in, pending_a_out;
    std::map<unsigned, AmAudio *> pending_b_in, pending_b_out;

  protected:
    virtual ~AmB2BMedia();

  public:
    AmB2BMedia(AmB2BSession * _a, AmB2BSession * _b);

    /**
     * To add a AmB2BMedia session to the media processor, *this method
     * MUST be used* as it increases the refcnt.
     */
    void addToMediaProcessor();
    /**
     * unsafe version (no locking of mutex)
     *
     * To add a AmB2BMedia session to the media processor, *this method
     * MUST be used* as it increases the refcnt.
     */
    void addToMediaProcessorUnsafe();

    void changeSession(bool a_leg, AmB2BSession *new_session);

    // void updateRelayPayloads(bool a_leg, const AmSdp &local_sdp, const AmSdp &remote_sdp);

    /**
     * Adds a reference.
     *
     * Both AmB2BSessions and AmMediaProcessor uses refcnt to this class; B2BSession
     * in case of RTP relay, AmMediaProcessor in case of local media processing.
     *
     * Instance of this object is created with reference counter set to zero.
     * Thus if somebody wants to hold a reference it must call addReference()
     * explicitly after construction!
     */
    void addReference();

    /** Releases reference.
     *
     * Returns true if this was the last reference, in that case the pointer
     * to that object is now *invalid*
     * Must be last operation in member method!
     */
    bool releaseReference();

    // ----------------- SDP manipulation & updates -------------------

    static bool canRelay(const SdpMedia &m);

    /** Replace connection address and ports within SDP.
     *
     * Throws an exception (string) in case of error. (FIXME?) */
    void replaceConnectionAddress(AmSdp & parser_sdp, bool a_leg, AddressType addr_type);

    /** replace offer inside given SDP with locally generated one (media streams
     * etc must be initialised like in case replaceConnectionAddress) */
    bool replaceOffer(AmSdp & sdp, bool a_leg);

    bool         haveLocalSdp(bool a_leg);
    bool         haveRemoteSdp(bool a_leg);
    const AmSdp &getLocalSdp(bool a_leg);
    const AmSdp &getRemoteSdp(bool a_leg);

    /** Update media session with local & remote SDP.
     *  Returns false with the reason in error when a stream is left without usable media
     *  (transport init or relay destination failure); the caller owns the call teardown. */
    bool createUpdateStreams(bool a_leg, const AmSdp &local_sdp, const AmSdp &remote_sdp, RelayController *ctrl,
                             bool sdp_offer_owner, string &error);
    bool updateStreams(bool a_leg, RelayController *ctrl, bool sdp_offer_owner, string &error);

    /** Detach the session from every leg it occupies (role-independent) and stop
     * processing if both legs are gone.
     *
     * Releases all RTP streams and removes itself from media processor if still
     * there. */
    void stop(AmB2BSession * s);

    // ---- AmMediaSession interface for processing audio in a standard way ----

    /** Should read from all streams before writing to the other streams.
     *
     * Because processing is driven by destination stream (i.e. we don't read
     * anything unless the destination stream is ready to send something - see
     * sendIntReached()) all processing is done in writeStreams */
    virtual int readStreams(unsigned long long ts, unsigned char *buffer) override
    {
        return 0;
    }

    /** Read and write all RTP streams if data are to be written (see
     * readStreams()). */
    virtual int writeStreams(unsigned long long ts, unsigned char *buffer) override;

    virtual void ping(unsigned long long ts) override;

    /** Calls processDtmfEvent on both AmB2BSessions for which this AmB2BMedia
     * instance manages media. */
    virtual void processDtmfEvents() override;

    /** Sends DTMF using the given call leg */
    void sendDtmf(bool a_leg, int event, unsigned int duration_ms, int volume = -1);

    /** Release all RTP streams of both legs and both AmB2BSessions as well.
     *
     * Though readStreams(), writeStreams() or processDtmfEvents() can be called
     * after call to clearAudio, they will do nothing because all relevant
     * information will be rlready eleased. */
    virtual void clearAudio() override;

    /** release RTP streams of every leg the session occupies */
    void clearAudio(AmB2BSession * s);

    /** Clear RTP timeout of all streams in both call legs. */
    virtual void clearRTPTimeout() override;

    virtual void onMediaSessionExists() override;

    /** Callback function called once media processor releases this instance
     * from processing loop.
     *
     * Deletes itself if there are no other references! FIXME: might be
     * returning something like "release me" and calling delete from media
     * processor would be better? */
    virtual void onMediaProcessingTerminated() override;

    void mute(bool a_leg)
    {
        setMuteFlag(a_leg, true);
    }
    void unmute(bool a_leg)
    {
        setMuteFlag(a_leg, false);
    }
    void setRtpTimeout(bool a_leg, unsigned int timeout);
    void setRtpTimeout(unsigned int timeout);
    void setMonitorRtpTimeout(bool enable);
    bool isMuted(bool a_leg)
    {
        if (a_leg)
            return a_leg_muted;
        else
            return b_leg_muted;
    }

    void setStreamInput(bool a_leg, unsigned media_idx, AmAudio *in);
    void setStreamOutput(bool a_leg, unsigned media_idx, AmAudio *out);
    void setFirstStreamInput(bool a_leg, AmAudio *in);
    void setFirstStreamOutput(bool a_leg, AmAudio *out);

    /** stage new pairs/streams during an in-flight OA (reinvite adding m= lines).
     *  Per-leg AmMediaTransaction is created lazily in createStreams and owned
     *  by the session. commit splices staged pairs into streams; rollback drops them. */
    void beginTransactionMode();
    void rollbackTransactionMode();
    // record a leg's successful OA completion; when both legs reported, commit fires
    void notifyOACompleted(bool a_leg);
    // arm the "next OA is local" flag for a leg (yeti's processLocalRequest calls this before dlg->reply)
    void setLocalOa(bool a_leg);

    void createHoldAnswer(bool a_leg, const AmSdp &offer, AmSdp &answer, bool use_zero_con);

    void setRtpLogger(msg_logger * _logger);
    void setSklLogger(SSLKeyLogger * logger);
    void setRtpASensor(msg_sensor * _sensor);
    void setRtpBSensor(msg_sensor * _sensor);

    /** enable or disable DTMF receiving on relay streams */
    void setRelayDTMFReceiving(bool enabled);

    /** pause relaying on streams */
    void pauseRelay();

    /** restart relaying on streams */
    void restartRelay();

    /** set 'receving' property of RTP/relay streams (not receiving=drop incoming packets) */
    void setReceiving(bool receiving_a, bool receiving_b);

    void setIgnoreRelayStreams(bool ignore);

    // print debug info
    void debug();

    virtual void getInfo(AmArg & ret) override;
};

#endif
