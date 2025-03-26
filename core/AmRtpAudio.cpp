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

#include "AmRtpAudio.h"
#include "AmAudioFileRecorderMono.h"
#include "AmAudioFileRecorderStereoMP3.h"
#include "AmSession.h"
#include "AmPlayoutBuffer.h"
#include "AmUtils.h"
#include <sys/time.h>
#include <assert.h>
#include <sstream>

AmAudioRtpFormat::AmAudioRtpFormat()
  : AmAudioFormat(-1),
    advertized_rate(0)
{}

AmAudioRtpFormat::~AmAudioRtpFormat()
{}

int AmAudioRtpFormat::setCurrentPayload(Payload pl, int frame_size_in)
{
    if (this->codec_id != pl.codec_id) {
        codec_id = pl.codec_id;
        channels = 1;
        rate = pl.clock_rate;
        advertized_rate = pl.advertised_clock_rate;
        frame_time = frame_size_in;
        frame_size = frame_size_in*this->rate/1000;

        DBG("AmAudioRtpFormat::setCurrentPayload: codec_id: %d, rates:%d/%d, frame_time/size: %d/%d, sdp: %s",
            codec_id,
            rate, advertized_rate,
            frame_time, frame_size,
            sdp_format_parameters.c_str());

        if (this->codec != nullptr) {
            destroyCodec();
        }
    }
    return 0;
}

void AmAudioRtpFormat::initCodec()
{
    amci_codec_fmt_info_t fmt_i[4];

    fmt_i[0].id=AMCI_FMT_FRAME_LENGTH;
    fmt_i[0].value=frame_size*1000/getRate();
    fmt_i[1].id=AMCI_FMT_FRAME_SIZE;
    fmt_i[1].value=frame_size;
    fmt_i[2].id = 0;

    if( codec && codec->init ) {
        if ((h_codec = (*codec->init)(sdp_format_parameters.c_str(), fmt_i)) == -1) {
            ERROR("could not initialize codec %i",codec->id);
        } else {
            string s;
            int i=0;
            while (fmt_i[i].id) {
                switch (fmt_i[i].id) {
                case AMCI_FMT_FRAME_LENGTH : {
                    //frame_length=fmt_i[i].value;
                } break;
                case AMCI_FMT_FRAME_SIZE: {
                    frame_size=static_cast<unsigned int>(fmt_i[i].value);
                    frame_time=frame_size*1000/rate;
                } break;
                case AMCI_FMT_ENCODED_FRAME_SIZE: {
                //   frame_encoded_size=fmt_i[i].value;
                } break;
                default: {
                    DBG("Unknown codec format descriptor: %d", fmt_i[i].id);
                } break;
                } //switch (fmt_i[i].id)

                i++;
            }
        }
    }
}

AmRtpAudio::AmRtpAudio(AmSession* _s, int _if)
  : AmRtpStream(_s,_if),
    AmAudio(nullptr),
    m_playout_type(SIMPLE_PLAYOUT),
    playout_buffer(nullptr),
    frame_size(0),
    /*last_ts_i(false),*/ use_default_plc(true),
    last_check(0),last_check_i(false), send_int(false),
    last_send_ts_i(false),
    last_decoded_system_ts(0),
    recv_samples_timeout_threshold(AmConfig.dead_rtp_time),
    recv_samples_timeout(false),
    max_rtp_time(0),
    ignore_recording(false)
{
#ifdef USE_SPANDSP_PLC
    plc_state = plc_init(NULL);
#endif // USE_SPANDSP_PLC
}

AmRtpAudio::~AmRtpAudio()
{
#ifdef USE_SPANDSP_PLC
    plc_release(plc_state);
#endif // USE_SPANDSP_PLC
}

bool AmRtpAudio::checkInterval(unsigned long long ts)
{
    if(!last_check_i) {
        send_int     = true;
        last_check_i = true;
        last_check   = ts;
    } else {
        if(scaleSystemTS(ts - last_check) >= getFrameSize()) {
            send_int = true;
            last_check = ts;
        } else {
            send_int = false;
        }
    }
    return send_int;
}

bool AmRtpAudio::sendIntReached()
{
    return send_int;
}

bool AmRtpAudio::sendIntReached(unsigned long long ts)
{
    if (!last_send_ts_i) return true;
    else return (scaleSystemTS(ts - last_send_ts) >= getFrameSize());
}

unsigned int AmRtpAudio::bytes2samples(unsigned int bytes) const
{
    return AmAudio::bytes2samples(bytes);
}

/* 
   @param system_ts [in]    the current ts in the audio buffer
*/
int AmRtpAudio::receive(unsigned long long system_ts) 
{
    int size;

    if(!fmt.get() || (!playout_buffer.get())) {
        DBG("audio format not initialized");
        return RTP_ERROR;
    }

    unsigned int wallclock_ts = scaleSystemTS(system_ts);

    while(true) {
        size = AmRtpStream::receive(
            static_cast<unsigned char*>(samples),
            static_cast<unsigned int>(AUDIO_BUFFER_SIZE));
        //DBG("AmRtpStream::receive: %d", size);
        if(size <= 0) {

            switch(size){
            case 0: break;
            case RTP_DTMF:
            case RTP_UNKNOWN_PL:
            case RTP_PARSE_ERROR:
                continue;
            case RTP_TIMEOUT:
                //FIXME: postRequest(new SchedRequest(AmMediaProcessor::RemoveSession,s));
                // post to the session (FIXME: is session always set? seems to be...)
                onRtpTimeout();
                return -1;
            case RTP_BUFFER_SIZE:
            default:
                ERROR("AmRtpStream::receive() returned %i",size);
                //FIXME: postRequest(new SchedRequest(AmMediaProcessor::ClearSession,s));
                //       or AmMediaProcessor::instance()->clearSession(session);
                return -1;
            } //switch(size)

            break;
        } //if(size <= 0)

        if(COMFORT_NOISE_PAYLOAD_TYPE == last_recv_payload) {
            playout_buffer->clearLastTs();
            continue;
        } else {
            if(setCurrentPayload(last_recv_payload, static_cast<int>(frame_size)) < 0)
                continue;
        }

        int decoded_size = decode(static_cast<unsigned int>(size));
        if(decoded_size <= 0) {
            if(rtp_stats.current_rx) {
                if(!rtp_stats.current_rx->decode_err) { //print just first decode error for current stream
                    DBG("AmAudio:decode(%d) returned %i. local_ssrc: 0x%x, local_tag: %s",
                        size,decoded_size,
                        l_ssrc,session ? session->getLocalTag().c_str() : "no session");
                }
                rtp_stats.current_rx->decode_err++;
            }
            return (decoded_size < 0) ? -1 : 0;
        }

        last_decoded_system_ts = system_ts;

        // This only works because the possible ratio (Rate/TSRate)
        // is 2. Rate and TSRate are only different in case of g722.
        // For g722, TSRate=8000 and Rate=16000
        //
        AmAudioRtpFormat* rtp_fmt = static_cast<AmAudioRtpFormat*>(fmt.get());
        unsigned long long adjusted_rtp_ts = last_recv_ts;

        if(rtp_fmt->getRate() != rtp_fmt->getTSRate()) {
            adjusted_rtp_ts =
                last_recv_ts *
                static_cast<unsigned long long>(rtp_fmt->getRate())
                / static_cast<unsigned long long>(rtp_fmt->getTSRate());
        }

        playout_buffer->write(
            wallclock_ts,
            static_cast<u_int32_t>(adjusted_rtp_ts),
            reinterpret_cast<ShortSample*>(static_cast<unsigned char*>(samples)),
            /*reinterpret_cast<ShortSample*>(unsigned char *samples()),*/
            PCM16_B2S(static_cast<u_int32_t>(decoded_size)), begin_talk);

        if(!active && !last_recv_relayed) {
            DBG("switching to active-mode\t(ts=%llu;stream=%p)",
                last_recv_ts,static_cast<void *>(this));
            active = true;
        }
    } //while(true)

    return size;
}

void AmRtpAudio::record(
    unsigned long long system_ts, unsigned char* buffer,
    int input_sample_rate, unsigned int size)
{
    if(!size) return;
    if (mute) return;

    if(record_enabled) {
        RecorderPutSamples(recorder_id,buffer,size,input_sample_rate);
    }

    applyPendingStereoRecorders(session);

    if(stereo_record_enabled) {
        stereo_recorders.put(system_ts,buffer,size,input_sample_rate);
    }
}

int AmRtpAudio::get(
    unsigned long long system_ts, unsigned char* buffer,
    int output_sample_rate, unsigned int nb_samples)
{
    if (!(receiving || getPassiveMode())) return 0; // like nothing received

    int ret = receive(system_ts);
    if(ret < 0)
        return ret; // like nothing received?

    if (!active && !last_recv_relayed) return 0;

    unsigned int user_ts = scaleSystemTS(system_ts);

    if(recv_samples_timeout) {
        if(ret > 0) {
            recv_samples_timeout = false;
        }
    } else if(recv_samples_timeout_threshold) {
        unsigned int diff_sec = (system_ts - last_decoded_system_ts)/WALLCLOCK_RATE;
        if(diff_sec > recv_samples_timeout_threshold) {
            recv_samples_timeout = true;
        }
    }

    nb_samples = static_cast<unsigned int>(
        static_cast<float>(nb_samples) * static_cast<float>(getSampleRate())
        / static_cast<float>(output_sample_rate));

    u_int32_t size =
        PCM16_S2B(playout_buffer->read(
            user_ts,
            reinterpret_cast<ShortSample*>(static_cast<unsigned char*>(samples)),
            nb_samples));

    if(max_rtp_time && max_rtp_time <= last_recv_ts && !size) {
       onMaxRtpTimeReached();
       max_rtp_time = 0;
    }

    if(output_sample_rate != getSampleRate()) {
        size = resampleOutput(
            static_cast<unsigned char*>(samples),
            size, getSampleRate(), output_sample_rate);
    }

    memcpy(buffer,static_cast<unsigned char*>(samples),size);

    return static_cast<int>(size);
}

int AmRtpAudio::put(
    unsigned long long system_ts, unsigned char* buffer,
    int input_sample_rate, unsigned int size)
{
    last_send_ts_i = true;
    last_send_ts = system_ts;

    if(!size) return 0;

    if(mute || (!sending)) return 0;

    if(!fmt.get())
      return 0;

    if(!ignore_recording) {
        if(record_enabled) {
            RecorderPutSamples(recorder_id,buffer,size,input_sample_rate);
        }

        if(stereo_record_enabled) {
            stereo_recorders.put(system_ts,buffer,size,input_sample_rate);
        }
    } else {
        ignore_recording = false;
    }

    memcpy(static_cast<unsigned char*>(samples),buffer,size);
    size = resampleInput(
        static_cast<unsigned char*>(samples),
        size, input_sample_rate, getSampleRate());

    int s = encode(size);
    if(s<=0) {
        return s;
    }

    update_user_ts(system_ts);

    return send(tx_user_ts,
                static_cast<unsigned char*>(samples),
                static_cast<unsigned int>(s));
}

void AmRtpAudio::put_on_idle(unsigned long long system_ts)
{
    //DBG("%llu put_on_idle",system_ts);
    last_send_ts_i = true;
    last_send_ts = system_ts;

    if (mute || (!sending))
        return;

    update_user_ts(system_ts);

    process_dtmf_queue(tx_user_ts);
}

void AmRtpAudio::update_user_ts(unsigned long long system_ts)
{
    AmAudioRtpFormat* rtp_fmt = static_cast<AmAudioRtpFormat*>(fmt.get());

    if(!rtp_fmt)
        return;

    // pre-division by 100 is important
    // so that the first multiplication
    // does not overflow the 64bit int
    tx_user_ts =
        system_ts * (static_cast<unsigned long long>(rtp_fmt->getTSRate()) / 100)
        / (WALLCLOCK_RATE/100);
}

void AmRtpAudio::getSdpOffer(unsigned int index, SdpMedia& offer)
{
    AmRtpStream::getSdpOffer(index,offer);
}

void AmRtpAudio::getSdpAnswer(
    unsigned int index,
    const SdpMedia& offer,
    SdpMedia& answer)
{
    AmRtpStream::getSdpAnswer(index,offer,answer);
}

int AmRtpAudio::init(
    const AmSdp& local,
    const AmSdp& remote,
    bool sdp_offer_owner,
    bool force_passive_mode)
{
    DBG("AmRtpAudio::init(...)");
    if(AmRtpStream::init(local,remote,sdp_offer_owner,force_passive_mode)) {
        return -1;
    }

    if(local.media[sdp_media_index].type == MT_AUDIO) {
        PayloadMappingTable::iterator pl_it =
            pl_map.find(static_cast<PayloadMappingTable::key_type>(payload));
        if ((pl_it == pl_map.end()) || (pl_it->second.remote_pt < 0)) {
            DBG("no default payload has been set");
            return -1;
        }

        const SdpMedia& remote_media = remote.media[sdp_media_index];
        if(session && !session->getRtpFrameSize(frame_size)) frame_size = remote_media.frame_size;

        AmAudioRtpFormat* fmt_p = new AmAudioRtpFormat();
        fmt_p->setCurrentPayload(payloads[pl_it->second.index], frame_size);
        fmt.reset(fmt_p);

        amci_codec_t* codec = fmt->getCodec();
        use_default_plc = ((codec==nullptr) || (codec->plc == nullptr));

#ifndef USE_SPANDSP_PLC
        fec.reset(new LowcFE(static_cast<unsigned int>(getSampleRate())));
#endif // USE_SPANDSP_PLC

        if (m_playout_type == SIMPLE_PLAYOUT) {
            playout_buffer.reset(new AmPlayoutBuffer(this,static_cast<unsigned int>(getSampleRate())));
        } else if (m_playout_type == ADAPTIVE_PLAYOUT) {
            playout_buffer.reset(new AmAdaptivePlayout(this,static_cast<unsigned int>(getSampleRate())));
        } else {
            playout_buffer.reset(new AmJbPlayout(this,static_cast<unsigned int>(getSampleRate())));
        }
    }

    if(session) {
        if(session->getRecordAudio()) {
            setRecorder(session->getLocalTag());
        }

        setSymmetricCandidate(session->getRtpSymmetricCandidate());
        setSymmetricRtpEndless(session->getRtpEndlessSymmetricRtp());
    }

    return 0;
}

int AmRtpAudio::ping(unsigned long long ts)
{
    if(!rtp_ping) return 0;

    unsigned char ping_chr[2];

    ping_chr[0] = 0;
    ping_chr[1] = 0;

    update_user_ts(ts);

    return compile_and_send(payload, true, static_cast<unsigned int>(tx_user_ts), ping_chr, 2);
}

unsigned int AmRtpAudio::getFrameSize()
{
    if (!fmt.get())
        return 0;

    return static_cast<AmAudioRtpFormat*>(fmt.get())->getFrameSize();
}

unsigned int AmRtpAudio::getFrameTime()
{
    if (!fmt.get())
        return 0;

    return static_cast<AmAudioRtpFormat*>(fmt.get())->getFrameTime();
}

int AmRtpAudio::setCurrentPayload(int payload, int frame_size)
{
    if(payload != this->payload) {

        if(payload == last_not_supported_rx_payload) {
            //received payload known as not supported. skip processing
            wrong_payload_errors++;
            return -1;
        }

        CLASS_DBG("change payload %d -> %d, local_ssrc: 0x%x, local_tag: %s",
            this->payload, payload,
            l_ssrc,session ? session->getLocalTag().c_str() : "no session");

        PayloadMappingTable::iterator pmt_it =
            pl_map.find(static_cast<PayloadMappingTable::key_type>(payload));
        if(pmt_it == pl_map.end()) {
            CLASS_DBG("received payload %i is not described in local SDP. ignore it. "
                      "local_ssrc: 0x%x, local_tag: %s",
                      payload,
                      l_ssrc,session ? session->getLocalTag().c_str() : "no session");

            last_not_supported_rx_payload = payload;
            wrong_payload_errors++;
            return -1;
        }

        if(pmt_it->second.remote_pt < 0) {
            CLASS_DBG("received payload %i is not described in remote SDP. ignore it. "
                      "local_ssrc: 0x%x, local_tag: %s",
                      payload,
                      l_ssrc,session ? session->getLocalTag().c_str() : "no session");

            last_not_supported_rx_payload = payload;
            wrong_payload_errors++;
            return -1;
        }

        unsigned char index = pmt_it->second.index;
        if(index >= payloads.size()) {
            ERROR("Could not set current payload: payload %i maps to invalid index %i",
                payload, index);
            last_not_supported_rx_payload = payload;
            wrong_payload_errors++;
            return -1;
        }

        if(isLocalTelephoneEventPayload(payload)) {
            CLASS_ERROR("Attempt to set telephone-event payload %d as default audio payload. ignore it",
                        payload);
            last_not_supported_rx_payload = payload;
            wrong_payload_errors++;
            return -1;
        }

        this->payload = payload;

        last_not_supported_rx_payload = -1;

        unsigned int old_rate = fmt->getRate();
        int ret = static_cast<AmAudioRtpFormat*>(fmt.get())
            ->setCurrentPayload(payloads[index], frame_size);
        if(!ret) {
            amci_codec_t* codec = fmt->getCodec();
            use_default_plc = ((codec==nullptr) || (codec->plc == nullptr));
            if(old_rate!=fmt->getRate()) {
#ifndef USE_SPANDSP_PLC
                fec.reset(new LowcFE(fmt->getRate()));
#endif
                playout_buffer->reinit(fmt->getRate());
            }
        }
        return ret;

    } else {
        return 0;
    }
}

unsigned int AmRtpAudio::conceal_loss(unsigned int ts_diff, unsigned char *buffer)
{
    unsigned int s = 0;

    if(!use_default_plc) {
        amci_codec_t* codec = fmt->getCodec();
        assert(codec);
        if(!codec->plc) {
            DBG("attempt to use codec specific PLC "
                "for codec(%d) which does not support it. "
                "failover to default PLC",
                codec->id);
            use_default_plc = true;
            goto _default_plc;
        }
        s = static_cast<unsigned int>((*codec->plc)(
            buffer, PCM16_S2B(ts_diff),
            static_cast<unsigned int>(fmt->channels),
            static_cast<unsigned int>(getSampleRate()),
            fmt->getHCodec()));
        //DBG("codec specific PLC (ts_diff = %i; s = %i)",ts_diff,s);
        return s;
    }

_default_plc:
    s = default_plc(
        buffer, PCM16_S2B(ts_diff),
        static_cast<unsigned int>(fmt->channels),
        static_cast<unsigned int>(getSampleRate()));
    //DBG("default PLC (ts_diff = %i; s = %i)",ts_diff,s);
    return s;
}

unsigned int AmRtpAudio::default_plc(
    unsigned char* out_buf,
    unsigned int   size,
    unsigned int   /*channels*/,
    unsigned int   sample_rate)
{
    short* buf_offset = reinterpret_cast<short*>(out_buf);

#ifdef USE_SPANDSP_PLC
    plc_fillin(plc_state, buf_offset, PCM16_B2S(size));
#else
    for(unsigned int i=0; i<(PCM16_B2S(size)/FRAMESZ); i++) {
        fec->dofe(buf_offset);
        buf_offset += FRAMESZ;
    }

#endif // USE_SPANDSP_PLC

    return static_cast<unsigned int>(PCM16_S2B(buf_offset - reinterpret_cast<short*>(out_buf)));
}

void AmRtpAudio::add_to_history(int16_t *buffer, unsigned int size)
{
    if (!use_default_plc)
        return;

#ifdef USE_SPANDSP_PLC
    plc_rx(plc_state, buffer, PCM16_B2S(size));
#else // USE_SPANDSP_PLC
    int16_t* buf_offset = buffer;

    unsigned int sample_rate = static_cast<unsigned int>(getSampleRate());

    for(unsigned int i=0; i<(PCM16_B2S(size)/FRAMESZ); i++) {
        fec->addtohistory(buf_offset);
        buf_offset += FRAMESZ;
    }
#endif // USE_SPANDSP_PLC
}

void AmRtpAudio::setPlayoutType(PlayoutType type)
{
    if (m_playout_type != type) {
        if (type == ADAPTIVE_PLAYOUT) {
            if(session) session->lockAudio();
            m_playout_type = type;
            if (fmt.get())
                playout_buffer.reset(new AmAdaptivePlayout(this,static_cast<unsigned int>(getSampleRate())));
            if(session) session->unlockAudio();
            DBG("Adaptive playout buffer activated");
        } else if (type == JB_PLAYOUT) {
            if(session) session->lockAudio();
            m_playout_type = type;
            if (fmt.get())
                playout_buffer.reset(new AmJbPlayout(this,static_cast<unsigned int>(getSampleRate())));
            if(session) session->unlockAudio();
            DBG("Adaptive jitter buffer activated");
        } else {
            if(session) session->lockAudio();
            m_playout_type = type;
            if (fmt.get())
                playout_buffer.reset(new AmPlayoutBuffer(this,static_cast<unsigned int>(getSampleRate())));
            if(session) session->unlockAudio();
            DBG("Simple playout buffer activated");
        }
    }
}

void AmRtpAudio::setMaxRtpTime(uint32_t ts)
{
    CLASS_DBG("AmRtpAudio::setLastRtpTime(%u)", ts);
    max_rtp_time = ts;
}

void AmRtpAudio::setRecvSamplesTimeout(uint32_t ts)
{
    CLASS_DBG("AmRtpAudio::setRecvSamplesTimeout(%u)", ts);
    recv_samples_timeout_threshold = ts;
}

void AmRtpAudio::updateStereoRecorders()
{
    if(session) {
        setStereoRecorders(session->getStereoRecorders(), session);
    }
}

void AmRtpAudio::onMaxRtpTimeReached()
{
    if(session) session->postEvent(new AmAudioEvent(AmAudioEvent::noAudio));
}

void AmRtpAudio::onRtpTimeout()
{
    if(session) session->postEvent(new AmRtpTimeoutEvent());
}

void AmRtpAudio::sendDtmf(int event, unsigned int duration_ms, int volume)
{
    CLASS_DBG("AmRtpAudio::sendDtmf(event = %d, duration = %u, volume = %d)",event,duration_ms, volume);
    dtmf_sender.queueEvent(event, duration_ms, volume, getLocalTelephoneEventRate(), frame_size);
}
