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
/** @file AmRtpAudio.h */
#ifndef _AmRtpAudio_h_
#define _AmRtpAudio_h_

#include "AmAudio.h"
#include "AmRtpStream.h"
#include "LowcFE.h"

#ifdef USE_SPANDSP_PLC
#include <math.h>
#include "spandsp/plc.h"
#endif

class AmPlayoutBuffer;

enum PlayoutType {
  ADAPTIVE_PLAYOUT,
  JB_PLAYOUT,
  SIMPLE_PLAYOUT
};



/** 
 * \brief interface for PLC buffer
 */

class AmPLCBuffer {
 public: 

  virtual void add_to_history(int16_t *buffer, unsigned int size) = 0;

  // Conceals packet loss into the out_buffer
  // @return length in bytes of the recivered segment
  virtual unsigned int conceal_loss(unsigned int ts_diff, unsigned char *out_buffer) = 0;
  AmPLCBuffer() { }
  virtual ~AmPLCBuffer() { }
};


/** \brief RTP audio format */
class AmAudioRtpFormat: public AmAudioFormat
{
  /** Sampling rate as advertized in SDP (differs from actual rate for G722) **/
  unsigned int advertized_rate;

protected:
  /** from AmAudioFormat */
  void initCodec();

public:
  AmAudioRtpFormat();
  ~AmAudioRtpFormat();

  /** return the timestamp sampling rate */
  unsigned int getTSRate() { return advertized_rate; }
  unsigned int getFrameSize() { return frame_size; }

  /**
   * changes payload. returns != 0 on error.
   */
  int setCurrentPayload(Payload pl, int frame_size = 20);
};


/** 
 * \brief binds together a \ref AmRtpStream and an \ref AmAudio for a session 
 */
class AmRtpAudio: public AmRtpStream, public AmAudio, public AmPLCBuffer
{
  PlayoutType m_playout_type;
  unique_ptr<AmPlayoutBuffer> playout_buffer;

  unsigned int frame_size;

#ifdef USE_SPANDSP_PLC
    plc_state_t* plc_state;
#else 
    std::unique_ptr<LowcFE>       fec;
#endif

  bool         use_default_plc;

  unsigned long long last_check;
  bool               last_check_i;
  bool               send_int;
  
  unsigned long long last_send_ts;
  bool               last_send_ts_i;

  unsigned long long last_decoded_system_ts;
  unsigned int       recv_samples_timeout_threshold;
  /* indicates that there are
   * no decoded samples for recv_samples_timeout_threshold seconds.
   * used to skip recording on empty input
   */
  bool               recv_samples_timeout;

  /**
   last expected RTP timestamp to receive
   causes onMaxRtpTimeReached() to be called if reached
   */
  unsigned long long max_rtp_time;
  
  /**
   * one-time flag to ignore put samples to record
   * flag is controlled by function ignoreRecording()
   */
  bool ignore_recording;

  //
  // Default packet loss concealment functions
  //
  unsigned int default_plc(unsigned char* out_buf,
			   unsigned int   size,
			   unsigned int   channels,
			   unsigned int   rate);

public:
  AmRtpAudio(AmSession* _s, int _if);
  ~AmRtpAudio();

  unsigned int getFrameSize();
  unsigned int getFrameTime();

  bool checkInterval(unsigned long long ts);
  bool sendIntReached();
  bool sendIntReached(unsigned long long ts);

  int setCurrentPayload(int payload, int frame_size = 20);
  int getCurrentPayload();

  int receive(unsigned long long system_ts);

  void record(
    unsigned long long system_ts, unsigned char* buffer,
    int input_sample_rate, unsigned int size);

  // AmAudio interface
  int get(unsigned long long system_ts, unsigned char* buffer, 
	  int output_sample_rate, unsigned int nb_samples) override;

  int put(unsigned long long system_ts, unsigned char* buffer, 
	  int input_sample_rate, unsigned int size) override;

  void put_on_idle(unsigned long long system_ts);

  void update_user_ts(unsigned long long system_ts);

  unsigned int bytes2samples(unsigned int) const;

  // AmRtpStream interface
  void getSdpOffer(unsigned int index, SdpMedia& offer) override;
  void getSdpAnswer(unsigned int index, const SdpMedia& offer, SdpMedia& answer) override;

  int init(const AmSdp& local,
       const AmSdp& remote,
       bool sdp_offer_owner,
       bool force_passive_mode) override;

  int ping(unsigned long long ts) override;

  void setPlayoutType(PlayoutType type);


  // AmPLCBuffer interface
  void add_to_history(int16_t *buffer, unsigned int size) override;

  // Conceals packet loss into the out_buffer
  // @return length in bytes of the recivered segment
  unsigned int conceal_loss(unsigned int ts_diff, unsigned char *out_buffer) override;

  bool isLastSamplesRelayed() { return last_recv_relayed; }
  
  bool isRecvSamplesTimeout() { return recv_samples_timeout; }

  /**
  * send a DTMF as RTP payload (RFC4733)
  * @param event event ID (e.g. key press), see rfc
  * @param duration_ms duration in milliseconds
  */
  void sendDtmf(int event, unsigned int duration_ms, int volume = -1);

  void setMaxRtpTime(uint32_t ts);
  void setRecvSamplesTimeout(uint32_t ts);
  void ignoreRecording() { ignore_recording = true; }
  void updateStereoRecorders();

protected:
  int read(unsigned int user_ts, unsigned int size) override { return 0; }
  int write(unsigned int user_ts, unsigned int size) override { return 0; }
  void virtual onRtpTimeout();
  void virtual onMaxRtpTimeReached();

};

#endif






