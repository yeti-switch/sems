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

#include "AmRtpStream.h"
#include "AmRtpPacket.h"
#include "AmRtpReceiver.h"
#include "AmLcConfig.h"
#include "AmPlugIn.h"
#include "AmAudio.h"
#include "AmUtils.h"
#include "AmSession.h"

#include "AmDtmfDetector.h"
#include "rtp/telephone_event.h"
#include "amci/codecs.h"
#include "AmJitterBuffer.h"

#include "sip/resolver.h"
#include "sip/ip_util.h"
#include "sip/transport.h"
#include "sip/raw_sender.h"
#include "sip/msg_logger.h"

#include "log.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef WITH_ZRTP
#include "zrtp/zrtp.h"
#endif

#include "rtp/rtp.h"

#include <set>
using std::set;
#include <algorithm>
#include <sstream>

#define ts_unsigned_diff(a,b) ((a)>=(b) ? (a)-(b) : (b)-(a))

#define RTCP_REPORT_SEND_INTERVAL_SECONDS 3

//seconds between 1900-01-01 and 1970-01-01
//(70*365 + 17)*86400
#define NTP_TIME_OFFSET 2208988800ULL

static inline void add_if_no_exist(std::vector<int> &v,int payload){
	if(std::find(v.begin(),v.end(),payload)==v.end())
		v.push_back(payload);
}

void PayloadMask::clear()
{
  memset(bits, 0, sizeof(bits));
}

void PayloadMask::set_all()
{
  memset(bits, 0xFF, sizeof(bits));
}

void PayloadMask::invert()
{
  // assumes that bits[] contains 128 bits
  unsigned long long* ull = (unsigned long long*)bits;
  ull[0] = ~ull[0];
  ull[1] = ~ull[1];
}

PayloadMask::PayloadMask(const PayloadMask &src)
{
  memcpy(bits, src.bits, sizeof(bits));
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 * This function must be called before setLocalPort, because
 * setLocalPort will bind the socket and it will be not
 * possible to change the IP later
 */
void AmRtpStream::setLocalIP(const string& ip)
{
  if (!am_inet_pton(ip.c_str(), &l_saddr)) {
    throw string ("AmRtpStream::setLocalIP: Invalid IP address: ") + ip;
  }
  CLASS_DBG("ip = %s\n",ip.c_str());
}

int AmRtpStream::hasLocalSocket() {
  return l_sd;
}

int AmRtpStream::getLocalSocket()
{
   if (l_sd)
        return l_sd;

    int sd=0, rtcp_sd=0;
    if((sd = socket(l_saddr.ss_family,SOCK_DGRAM,0)) == -1) {
        CLASS_ERROR("%s\n",strerror(errno));
        throw string ("while creating new socket.");
    }

    if((rtcp_sd = socket(l_saddr.ss_family,SOCK_DGRAM,0)) == -1) {
        CLASS_ERROR("%s\n",strerror(errno));
        throw string ("while creating new socket.");
    }

    int true_opt = 1;
    if(ioctl(sd, FIONBIO , &true_opt) == -1) {
        CLASS_ERROR("%s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket non blocking.");
    }

    if(setsockopt(sd,SOL_SOCKET,SO_TIMESTAMP,
                  (void*)&true_opt, sizeof(true_opt)) < 0)
    {
        CLASS_ERROR("%s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket SO_TIMESTAMP opt");
    }

    if(ioctl(rtcp_sd, FIONBIO , &true_opt) == -1) {
        CLASS_ERROR("%s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTCP socket non blocking.");
    }

    if(setsockopt(rtcp_sd,SOL_SOCKET,SO_TIMESTAMP,
                  (void*)&true_opt, sizeof(true_opt)) < 0)
    {
        CLASS_ERROR("%s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTCP socket SO_TIMESTAMP opt");
    }

    l_sd = sd;
    l_rtcp_sd = rtcp_sd;

    return l_sd;
}

void AmRtpStream::setLocalPort(unsigned short p)
{
  if(l_port)
    return;
  
  if(l_if < 0) {
    if (session) l_if = session->getRtpInterface();
    else {
      CLASS_ERROR("BUG: no session when initializing RTP stream, invalid interface can be used\n");
      l_if = 0;
    }
  }
  
  if(laddr_if < 0) {
      if(session) laddr_if = session->getRtpAddr();
      else {
          CLASS_ERROR("BUG: no session when initializing RTP stream, invalid interface addr can be used\n");
        l_if = 0;
      }
  }

  int retry = 10;
  unsigned short port = 0;
  for(;retry; --retry){

    if (!getLocalSocket())
      return;

    if(!p)
      port = AmConfig.media_ifs[l_if].proto_info[laddr_if]->getNextRtpPort();
    else
      port = p;

    am_set_port(&l_saddr,port+1);
    if(bind(l_rtcp_sd,(const struct sockaddr*)&l_saddr,SA_len(&l_saddr))) {
      CLASS_DBG("bind: %s\n",strerror(errno));		
      goto try_another_port;
    }

    am_set_port(&l_saddr,port);
    if(bind(l_sd,(const struct sockaddr*)&l_saddr,SA_len(&l_saddr))) {
      CLASS_DBG("bind: %s\n",strerror(errno));		
      goto try_another_port;
    }

    // both bind() succeeded!
    break;

  try_another_port:
      close(l_sd);
      l_sd = 0;
      close(l_rtcp_sd);
      l_rtcp_sd = 0;
  }

  int true_opt = 1;
  if (!retry){
    CLASS_ERROR("could not find a free RTP port\n");
    throw string("could not find a free RTP port");
  }

  // rco: does that make sense after bind() ????
  if(setsockopt(l_sd, SOL_SOCKET, SO_REUSEADDR,
		(void*)&true_opt, sizeof (true_opt)) == -1) {

    CLASS_ERROR("%s\n",strerror(errno));
    close(l_sd);
    l_sd = 0;
    throw string ("while setting local address reusable.");
  }

  int tos = AmConfig.media_ifs[l_if].proto_info[laddr_if]->tos_byte;
  if(tos &&
     (setsockopt(l_sd, IPPROTO_IP, IP_TOS,  &tos, sizeof(tos)) == -1 ||
      setsockopt(l_rtcp_sd, IPPROTO_IP, IP_TOS,  &tos, sizeof(tos)) == -1))
  {
    CLASS_WARN("failed to set IP_TOS for descriptors %d/%d",l_sd,l_rtcp_sd);
  }

  l_port = port;
  l_rtcp_port = port+1;

  if(!p) {
    l_sd_ctx = AmRtpReceiver::instance()->addStream(l_sd, this,l_sd_ctx);
    l_rtcp_sd_ctx = AmRtpReceiver::instance()->addStream(l_rtcp_sd, this,l_rtcp_sd_ctx);
    if(l_sd_ctx < 0 || l_rtcp_sd_ctx < 0){
        CLASS_ERROR("can't add to RTP receiver (%s:%i/%i)\n",
            get_addr_str((sockaddr_storage*)&l_saddr).c_str(),l_port,l_rtcp_port);
    } else {
        CLASS_DBG("added to RTP receiver (%s:%i/%i)\n",
            get_addr_str((sockaddr_storage*)&l_saddr).c_str(),l_port,l_rtcp_port);
    }
  }

  memcpy(&l_rtcp_saddr, &l_saddr, sizeof(l_saddr));
  am_set_port(&l_rtcp_saddr, l_rtcp_port);
}

int AmRtpStream::ping()
{
  // TODO:
  //  - we'd better send an empty UDP packet 
  //    for this purpose.

  unsigned char ping_chr[2];

  ping_chr[0] = 0;
  ping_chr[1] = 0;

  AmRtpPacket rp;
  rp.payload = payload;
  rp.marker = true;
  rp.sequence = sequence++;
  rp.timestamp = 0;   
  rp.ssrc = l_ssrc;
  rp.compile((unsigned char*)ping_chr,2);

  rp.setAddr(&r_saddr);
  if(rp.send(l_sd, *AmConfig.media_ifs[l_if].proto_info[laddr_if],&l_saddr) < 0){
    CLASS_ERROR("while sending RTP packet.\n");
    return -1;
  }
  //if (logger) rp.logSent(logger, &l_saddr);
  log_sent_rtp_packet(rp);

  return 2;
}

int AmRtpStream::compile_and_send(const int payload, bool marker, unsigned int ts, 
				  unsigned char* buffer, unsigned int size) {
  AmRtpPacket rp;
  rp.payload = payload;
  rp.timestamp = ts;
  rp.marker = marker;
  rp.sequence = sequence++;
  rp.ssrc = l_ssrc;
  rp.compile((unsigned char*)buffer,size);

  rp.setAddr(&r_saddr);

#ifdef WITH_ZRTP
  if (session && session->enable_zrtp){
    if (NULL == session->zrtp_session_state.zrtp_audio) {
      ERROR("ZRTP enabled on session, but no audio stream created\n");
      return -1;
    }

    unsigned int size = rp.getBufferSize();
    zrtp_status_t status = zrtp_process_rtp(session->zrtp_session_state.zrtp_audio,
					    (char*)rp.getBuffer(), &size);
    switch (status) {
    case zrtp_status_drop: {
      DBG("ZRTP says: drop packet! %u - %u\n", size, rp.getBufferSize());
      return 0;
    } 
    case zrtp_status_ok: {
      //      DBG("ZRTP says: ok!\n");
      if (rp.getBufferSize() != size)
//       DBG("SEND packet size before: %d, after %d\n", 
// 	   rp.getBufferSize(), size);
      rp.setBufferSize(size);
    } break;
    default:
    case zrtp_status_fail: {
      DBG("ZRTP says: fail!\n");
      //      DBG("(f)");
      return 0;
    }

    }
    
  }
#endif

  if(rp.send(l_sd, *AmConfig.media_ifs[l_if].proto_info[laddr_if], &l_saddr) < 0){
    CLASS_ERROR("while sending RTP packet.\n");
    return -1;
  }

  add_if_no_exist(outgoing_payloads,rp.payload);
  outgoing_bytes+=rp.getDataSize();
  //if (logger) rp.logSent(logger, &l_saddr);
  log_sent_rtp_packet(rp);
 
  return size;
}

int AmRtpStream::send( unsigned int ts, unsigned char* buffer, unsigned int size )
{
  if ((mute) || (hold))
    return 0;

  if(remote_telephone_event_pt.get() &&
      dtmf_sender.sendPacket(ts,remote_telephone_event_pt->payload_type,this))
    return size;

 if(!size)
    return -1;

  PayloadMappingTable::iterator it = pl_map.find(payload);
  if ((it == pl_map.end()) || (it->second.remote_pt < 0)) {
    CLASS_ERROR("sending packet with unsupported remote payload type %d\n", payload);
    return -1;
  }
  
  return compile_and_send(it->second.remote_pt, false, ts, buffer, size);
}

int AmRtpStream::send_raw( char* packet, unsigned int length )
{
  if ((mute) || (hold))
    return 0;

  AmRtpPacket rp;
  rp.compile_raw((unsigned char*)packet, length);
  rp.setAddr(&r_saddr);

  if(rp.send(l_sd, *AmConfig.media_ifs[l_if].proto_info[laddr_if], &l_saddr) < 0){
    CLASS_ERROR("while sending raw RTP packet.\n");
    return -1;
  }

  //if (logger) rp.logSent(logger, &l_saddr);
  log_sent_rtp_packet(rp);

  return length;
}

// returns 
// @param ts              [out] timestamp of the received packet, 
//                              in audio buffer relative time
// @param audio_buffer_ts [in]  current ts at the audio_buffer 

int AmRtpStream::receive( unsigned char* buffer, unsigned int size,
              unsigned int& ts, int &out_payload, bool &relayed)
{
  AmRtpPacket* rp = NULL;
  int err = nextPacket(rp);
    
  if(err <= 0)
    return err;

  if (!rp)
    return 0;

  relayed = rp->relayed;

  if(!relayed) {
    handleSymmetricRtp(&rp->addr,false);

      /* do we have a new talk spurt? */
    begin_talk = ((last_payload == 13) || rp->marker);
    last_payload = rp->payload;

    add_if_no_exist(incoming_payloads,rp->payload);
  }

  if(!rp->getDataSize()) {
    mem.freePacket(rp);
    return RTP_EMPTY;
  }

  if (rp->payload == getLocalTelephoneEventPT())
  {
      if(!relayed) recvDtmfPacket(rp);
      mem.freePacket(rp);
      return RTP_DTMF;
  }

  assert(rp->getData());
  if(rp->getDataSize() > size){
    CLASS_ERROR("received too big RTP packet\n");
    mem.freePacket(rp);
    return RTP_BUFFER_SIZE;
  }

  memcpy(buffer,rp->getData(),rp->getDataSize());
  ts = rp->timestamp;
  out_payload = rp->payload;

  int res = rp->getDataSize();
  mem.freePacket(rp);
  return res;
}

AmRtpStream::AmRtpStream(AmSession* _s, int _if, int _addr_if)
  : r_port(0),
    l_if(_if),
    laddr_if(_addr_if),
    l_port(0),
    l_sd(0),
    l_sd_ctx(-1),
    l_rtcp_sd_ctx(-1),
    r_ssrc_i(false),
    session(_s),
    logger(NULL),
	sensor(NULL),
    passive(false),
    passive_rtcp(false),
    offer_answer_used(true),
    active(false), // do not return any data unless something really received
    mute(false),
    hold(false),
    receiving(true),
    monitor_rtp_timeout(true),
    relay_stream(NULL),
    relay_enabled(false),
    relay_raw(false),
    sdp_media_index(-1),
    relay_transparent_ssrc(true),
    relay_transparent_seqno(true),
    relay_filter_dtmf(false),
	force_relay_dtmf(true),
	relay_timestamp_aligning(false),
	symmetric_rtp_ignore_rtcp(false),
	symmetric_rtp_endless(false),
    force_receive_dtmf(false),
	rtp_ping(false),
	force_buffering(false),
	dead_rtp_time(AmConfig.dead_rtp_time),
    incoming_bytes(0),
	outgoing_bytes(0),
	decode_errors(0),
	rtp_parse_errors(0),
	out_of_buffer_errors(0),
	ts_adjust(0),
	last_sent_ts(0),
	last_sent_ts_diff(0),
	last_send_rtcp_report_ts(0)
{

  DBG("AmRtpStream[%p](%p)",this,session);
  memset(&r_saddr,0,sizeof(struct sockaddr_storage));
  memset(&l_saddr,0,sizeof(struct sockaddr_storage));

  l_ssrc = get_random();
  sequence = get_random();
  clearRTPTimeout();

  // by default the system codecs
  payload_provider = AmPlugIn::instance();
}

AmRtpStream::~AmRtpStream()
{
  DBG("~AmRtpStream[%p]() session = %p",this,session);
  if(l_sd){
    if (AmRtpReceiver::haveInstance()){
      AmRtpReceiver::instance()->removeStream(l_sd,l_sd_ctx);
      l_sd_ctx = -1;
      AmRtpReceiver::instance()->removeStream(l_rtcp_sd,l_rtcp_sd_ctx);
      l_rtcp_sd_ctx = -1;
    }
    close(l_sd);
    close(l_rtcp_sd);
  }
  if(session) session->onRTPStreamDestroy(this);
  if (logger) dec_ref(logger);
  if (sensor) dec_ref(sensor);
}

int AmRtpStream::getLocalPort()
{
  //  if (hold)
  //    return 0;

  if(!l_port)
    setLocalPort();

  return l_port;
}

int AmRtpStream::getLocalRtcpPort()
{
  if(!l_rtcp_port)
    setLocalPort();

  return l_rtcp_port;
}

int AmRtpStream::getRPort()
{
  return r_port;
}

string AmRtpStream::getRHost()
{
  return r_host;
}

void AmRtpStream::setRAddr(const string& addr, unsigned short port,
			   unsigned short rtcp_port)
{
  CLASS_DBG("RTP remote address set to %s:(%u/%u)\n",
      addr.c_str(),port,rtcp_port);

  struct sockaddr_storage ss;
  memset (&ss, 0, sizeof (ss));

  /* inet_aton only supports dot-notation IP address strings... but an RFC
   * 4566 unicast-address, as found in c=, can be an FQDN (or other!).
   */
  dns_handle dh;
  dns_priority priority = IPv4_only;
  if(AmConfig.media_ifs[l_if].proto_info[laddr_if]->type_ip == IP_info::IPv6) {
      priority = IPv6_only;
  }
  if (resolver::instance()->resolve_name(addr.c_str(),&dh,&ss,priority) < 0) {
    CLASS_WARN("Address not valid (host: %s).\n", addr.c_str());
    throw string("invalid address") + addr;
  }

  r_host = addr;

  if(port) {
    memcpy(&r_saddr,&ss,sizeof(struct sockaddr_storage));
    r_port = port;
    am_set_port(&r_saddr,r_port);
  }

  if(rtcp_port) {
    memcpy(&r_rtcp_saddr,&ss,sizeof(struct sockaddr_storage));
    r_rtcp_port = rtcp_port;
    am_set_port(&r_rtcp_saddr,r_rtcp_port);
  }

  mute = ((r_saddr.ss_family == AF_INET) && 
	  (SAv4(&r_saddr)->sin_addr.s_addr == INADDR_ANY)) ||
    ((r_saddr.ss_family == AF_INET6) && 
     IN6_IS_ADDR_UNSPECIFIED(&SAv6(&r_saddr)->sin6_addr));
}

void AmRtpStream::handleSymmetricRtp(struct sockaddr_storage* recv_addr, bool rtcp) {

    if((!rtcp && passive) || (rtcp && (!symmetric_rtp_ignore_rtcp && passive_rtcp))) {

        struct sockaddr_in* in_recv = (struct sockaddr_in*)recv_addr;
        struct sockaddr_in6* in6_recv = (struct sockaddr_in6*)recv_addr;

        struct sockaddr_in* in_addr = (struct sockaddr_in*)&r_saddr;
        struct sockaddr_in6* in6_addr = (struct sockaddr_in6*)&r_saddr;

        unsigned short port = am_get_port(recv_addr);

        // symmetric RTP
        if ( (!rtcp && (port != r_port)) || (rtcp && (port != r_rtcp_port)) ||
             ( (recv_addr->ss_family == AF_INET) &&
               (in_addr->sin_addr.s_addr != in_recv->sin_addr.s_addr)) ||
             ( (recv_addr->ss_family == AF_INET6) &&
               (memcmp(&in6_addr->sin6_addr,
                       &in6_recv->sin6_addr,
                       sizeof(struct in6_addr)))))
        {
            string addr_str = get_addr_str(recv_addr);
            setRAddr(addr_str, !rtcp ? port : 0, rtcp ? port : 0);
            if(!symmetric_rtp_endless) {
                CLASS_DBG("Symmetric %s: setting new remote address: %s:%i\n",
                    !rtcp ? "RTP" : "RTCP", addr_str.c_str(),port);
            }
        } else {
            if(!symmetric_rtp_endless) {
                const char* prot = rtcp ? "RTCP" : "RTP";
                CLASS_DBG("Symmetric %s: remote end sends %s from advertised address."
                    " Leaving passive mode.\n",prot,prot);
            }
        }

        // avoid comparing each time sender address
        // don't switch to passive mode if endless switching flag set
        if(!symmetric_rtp_endless){
            if(!rtcp)
                passive = false;
            else
                passive_rtcp = false;
        }
    }
}

void AmRtpStream::setPassiveMode(bool p)
{
  passive_rtcp = passive = p;
  if (p) {
    CLASS_DBG("The other UA is NATed or passive mode forced: switched to passive mode.\n");
  } else {
    CLASS_DBG("Passive mode not activated.\n");
  }
}

void AmRtpStream::getSdp(SdpMedia& m)
{
  m.port = getLocalPort();
  m.nports = 0;
  m.transport = TP_RTPAVP;
  m.send = !hold;
  m.recv = receiving;
  m.dir = SdpMedia::DirBoth;
}

void AmRtpStream::getSdpOffer(unsigned int index, SdpMedia& offer)
{
  sdp_media_index = index;
  getSdp(offer);
  offer.payloads.clear();
  payload_provider->getPayloads(offer.payloads);
}

void AmRtpStream::getSdpAnswer(unsigned int index, const SdpMedia& offer, SdpMedia& answer)
{
  sdp_media_index = index;
  getSdp(answer);
  offer.calcAnswer(payload_provider,answer);
}

int AmRtpStream::init(const AmSdp& local,
		      const AmSdp& remote,
                      bool force_passive_mode)
{
  if((sdp_media_index < 0) ||
     ((unsigned)sdp_media_index >= local.media.size()) ||
     ((unsigned)sdp_media_index >= remote.media.size()) ) {

    CLASS_ERROR("Media index %i is invalid, either within local or remote SDP (or both)",sdp_media_index);
    return -1;
  }

  const SdpMedia& local_media = local.media[sdp_media_index];
  const SdpMedia& remote_media = remote.media[sdp_media_index];

  CLASS_DBG("AmRtpStream[%p]::init() sdp_media_index = %d",this,sdp_media_index);

  payloads.clear();
  pl_map.clear();
  payloads.resize(local_media.payloads.size());

  int i=0;
  vector<SdpPayload>::const_iterator sdp_it = local_media.payloads.begin();
  vector<Payload>::iterator p_it = payloads.begin();

  // first pass on local SDP - fill pl_map with intersection of codecs
  while(sdp_it != local_media.payloads.end()) {

    int int_pt;

    if (local_media.transport == TP_RTPAVP && sdp_it->payload_type < 20) int_pt = sdp_it->payload_type;
    else int_pt = payload_provider->getDynPayload(sdp_it->encoding_name,
        sdp_it->clock_rate,
        sdp_it->encoding_param);

    amci_payload_t* a_pl = NULL;
    if(int_pt >= 0) 
      a_pl = payload_provider->payload(int_pt);

    if(a_pl == NULL){
      if (relay_payloads.get(sdp_it->payload_type)) {
        // this payload should be relayed, ignore
        ++sdp_it;
        continue;
      } else {
        CLASS_DBG("No internal payload corresponding to type %s/%i (ignoring)\n",
              sdp_it->encoding_name.c_str(),
              sdp_it->clock_rate);
	// ignore this payload
        ++sdp_it;
        continue;
      }
    };
    
    p_it->pt         = sdp_it->payload_type;
    p_it->name       = sdp_it->encoding_name;
    p_it->codec_id   = a_pl->codec_id;
    p_it->clock_rate = a_pl->sample_rate;
    p_it->advertised_clock_rate = sdp_it->clock_rate;

    pl_map[sdp_it->payload_type].index     = i;
    pl_map[sdp_it->payload_type].remote_pt = -1;
    
    ++p_it;
    ++sdp_it;
    ++i;
  }

  // remove payloads which were not initialised (because of unknown payloads
  // which are to be relayed)
  if (p_it != payloads.end()) payloads.erase(p_it, payloads.end());

  // second pass on remote SDP - initialize payload IDs used by remote (remote_pt)
  sdp_it = remote_media.payloads.begin();
  while(sdp_it != remote_media.payloads.end()) {

    // TODO: match not only on encoding name
    //       but also on parameters, if necessary
    //       Some codecs define multiple payloads
    //       with different encoding parameters
    PayloadMappingTable::iterator pmt_it = pl_map.end();
    if(sdp_it->encoding_name.empty() || (local_media.transport == TP_RTPAVP && sdp_it->payload_type < 20)){
      // must be a static payload
      pmt_it = pl_map.find(sdp_it->payload_type);
    }
    else {
      for(p_it = payloads.begin(); p_it != payloads.end(); ++p_it){

	if(!strcasecmp(p_it->name.c_str(),sdp_it->encoding_name.c_str()) && 
	   (p_it->advertised_clock_rate == (unsigned int)sdp_it->clock_rate)){
	  pmt_it = pl_map.find(p_it->pt);
	  break;
	}
      }
    }

    // TODO: remove following code once proper 
    //       payload matching is implemented
    //
    // initialize remote_pt if not already there
    if(pmt_it != pl_map.end() && (pmt_it->second.remote_pt < 0)){
      pmt_it->second.remote_pt = sdp_it->payload_type;
    }
    ++sdp_it;
  }

  if(!l_port){
    // only if socket not yet bound:
    if(session) {
      setLocalIP(session->localMediaIP());
    }
    else {
      // set local address - media c-line having precedence over session c-line
      if (local_media.conn.address.empty())
	setLocalIP(local.conn.address);
      else
	setLocalIP(local_media.conn.address);
    }

    CLASS_DBG("setting local port to %i",local_media.port);
    setLocalPort(local_media.port);
  }

  setPassiveMode(remote_media.dir == SdpMedia::DirActive || force_passive_mode);

  // set remote address - media c-line having precedence over session c-line
  if (remote.conn.address.empty() && remote_media.conn.address.empty()) {
    CLASS_WARN("no c= line given globally or in m= section in remote SDP\n");
    return -1;
  }
  if (remote_media.conn.address.empty())
    setRAddr(remote.conn.address, remote_media.port, remote_media.port+1);
  else
    setRAddr(remote_media.conn.address, remote_media.port, remote_media.port+1);

  if(local_media.payloads.empty()) {
    CLASS_DBG("local_media.payloads.empty()\n");
    return -1;
  }

  remote_telephone_event_pt.reset(remote.telephoneEventPayload());
  if (remote_telephone_event_pt.get()) {
      CLASS_DBG("remote party supports telephone events (pt=%i)\n",
	  remote_telephone_event_pt->payload_type);
  } else {
    CLASS_DBG("remote party doesn't support telephone events\n");
  }

  local_telephone_event_pt.reset(local.telephoneEventPayload());

  CLASS_DBG("recv = %d, send = %d",
	  local_media.recv, local_media.send);

  if(local_media.recv) {
    resume();
  } else {
    pause();
  }

  if(local_media.send && !hold
     && (remote_media.port != 0)
     && (((r_saddr.ss_family == AF_INET) 
	  && (SAv4(&r_saddr)->sin_addr.s_addr != 0)) ||
	 ((r_saddr.ss_family == AF_INET6) 
	  && (!IN6_IS_ADDR_UNSPECIFIED(&SAv6(&r_saddr)->sin6_addr))))
     ) {
    mute = false;
  } else {
    mute = true;
  }
  CLASS_DBG("mute = %d",mute);

  payload = getDefaultPT();
  if(payload < 0) {
    CLASS_DBG("could not set a default payload\n");
    return -1;
  }
  CLASS_DBG("default payload selected = %i\n",payload);
  last_payload = payload;

#ifdef WITH_ZRTP  
  if( session->zrtp_audio  ) {
    CLASS_DBG("now starting zrtp stream...\n");
    zrtp_start_stream( session->zrtp_audio );
  }
#endif

  active = false; // mark as nothing received yet

  if(rtp_ping) ping(); //generate fake initial rtp packet

  gettimeofday(&rtp_stats.start, nullptr);
  rtcp_reports.init(l_ssrc);

  return 0;
}

void AmRtpStream::setReceiving(bool r) {
  CLASS_DBG("set receiving=%s\n",r?"true":"false");
  receiving = r;
}

void AmRtpStream::pause()
{
  CLASS_DBG("pausing (receiving=false)\n");
  receiving = false;
}

void AmRtpStream::resume()
{
  CLASS_DBG("resuming (receiving=true, clearing biffers/TS/TO)\n");
  clearRTPTimeout();
  receive_mut.lock();
  mem.clear();
  receive_buf.clear();
  while (!rtp_ev_qu.empty())
    rtp_ev_qu.pop();
  receive_mut.unlock();
  receiving = true;

#ifdef WITH_ZRTP
  if (session && session->enable_zrtp) {
    session->zrtp_session_state.startStreams(get_ssrc());
  }
#endif
}

void AmRtpStream::setOnHold(bool on_hold) {
  hold = on_hold;
}

bool AmRtpStream::getOnHold() {
  return hold;
}

void AmRtpStream::recvDtmfPacket(AmRtpPacket* p) {
  if (p->payload == getLocalTelephoneEventPT()) {
    dtmf_payload_t* dpl = (dtmf_payload_t*)p->getData();

	/*CLASS_DBG("DTMF: event=%i; e=%i; r=%i; volume=%i; duration=%i; ts=%u session = [%p]\n",
	dpl->event,dpl->e,dpl->r,dpl->volume,ntohs(dpl->duration),p->timestamp, session);*/
    if (session) 
      session->postDtmfEvent(new AmRtpDtmfEvent(dpl, getLocalTelephoneEventRate(), p->timestamp));
  }
}

void AmRtpStream::bufferPacket(AmRtpPacket* p)
{
  clearRTPTimeout(&p->recv_time);

  update_receiver_stats(*p);

  if (!receiving) {

    if (passive) {
      handleSymmetricRtp(&p->addr,false);
    }

    if (force_receive_dtmf) {
      recvDtmfPacket(p);
    }

    mem.freePacket(p);
    return;
  }

  if (relay_enabled) {
	if (force_receive_dtmf) {
		recvDtmfPacket(p);
	}

	bool is_dtmf_packet = (p->payload == getLocalTelephoneEventPT());

	if (relay_raw
		|| (is_dtmf_packet
			&& (force_relay_dtmf ||!active))
			//can relay
		|| (relay_payloads.get(p->payload)
			&& NULL != relay_stream
			//avoid asymmetric payloads
			&& (p->payload == relay_stream->getLastPayload()
				//force CN relay
				|| (force_relay_cn
					&& p->payload == COMFORT_NOISE_PAYLOAD_TYPE))))
	{
		if(active){
			CLASS_DBG("switching to relay-mode\t(ts=%u;stream=%p)\n",p->timestamp,this);
			active = false;
		}

		handleSymmetricRtp(&p->addr,false);
		add_if_no_exist(incoming_relayed_payloads,p->payload);

		if (NULL != relay_stream							//we have relay stream
			&& (!(relay_filter_dtmf&& is_dtmf_packet)))		//packet is not dtmf or relay dtmf is not filtered
		{
			relay_stream->relay(p, is_dtmf_packet,
								force_receive_dtmf && !force_relay_dtmf);
			if(force_buffering && p->relayed) {
				receive_mut.lock();
				if(!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp,p)).second) {
					mem.freePacket(p);
				}
				receive_mut.unlock();
				return;
			}
		}

		mem.freePacket(p);
		return;
	}
  }

#ifndef WITH_ZRTP
  // throw away ZRTP packets 
  if(p->version != RTP_VERSION) {
      mem.freePacket(p);
      return;
  }
#endif

  receive_mut.lock();
  // NOTE: useless, as DTMF events are pushed into 'rtp_ev_qu'
  // free packet on double packet for TS received
  // if(p->payload == getLocalTelephoneEventPT()) {
  //   if (receive_buf.find(p->timestamp) != receive_buf.end()) {
  //     mem.freePacket(receive_buf[p->timestamp]);
  //   }
  // }  

#ifdef WITH_ZRTP
  if (session && session->enable_zrtp) {

    if (NULL == session->zrtp_session_state.zrtp_audio) {
      WARN("dropping received packet, as there's no ZRTP stream initialized\n");
      receive_mut.unlock();
      mem.freePacket(p);
      return;      
    }
 
    unsigned int size = p->getBufferSize();    
    zrtp_status_t status = zrtp_process_srtp(session->zrtp_session_state.zrtp_audio, (char*)p->getBuffer(), &size);
    switch (status)
      {
      case zrtp_status_forward:
      case zrtp_status_ok: {
	p->setBufferSize(size);
	if (p->parse() < 0) {
	  ERROR("parsing decoded packet!\n");
	  mem.freePacket(p);
	} else {

          if(p->payload == getLocalTelephoneEventPT()) {
            rtp_ev_qu.push(p);
          } else {
	    if(!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp,p)).second) {
	      // insert failed
	      mem.freePacket(p);
	    }
          }

	}
      }	break;

      case zrtp_status_drop: {
	//
	// This is a protocol ZRTP packet or masked RTP media.
	// In either case the packet must be dropped to protect your 
	// media codec
	mem.freePacket(p);
	
      } break;

      case zrtp_status_fail:
      default: {
	CLASS_ERROR("zrtp_status_fail!\n");
        //
        // This is some kind of error - see logs for more information
        //
	mem.freePacket(p);
      } break;
      }
  } else {
#endif // WITH_ZRTP

    if(p->payload == getLocalTelephoneEventPT()) {
      rtp_ev_qu.push(p);
    } else {
      if(!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp,p)).second) {
	// insert failed
	mem.freePacket(p);
      }
    }

#ifdef WITH_ZRTP
  }
#endif
  receive_mut.unlock();
}

void AmRtpStream::clearRTPTimeout(struct timeval* recv_time) {
  memcpy(&last_recv_time, recv_time, sizeof(struct timeval));
}

void AmRtpStream::clearRTPTimeout() {
  gettimeofday(&last_recv_time,NULL);
}

int AmRtpStream::getDefaultPT()
{
  for(PayloadCollection::iterator it = payloads.begin();
      it != payloads.end(); ++it){

    // skip telephone-events payload
    if(it->codec_id == CODEC_TELEPHONE_EVENT)
      continue;

    // skip incompatible payloads
    PayloadMappingTable::iterator pl_it = pl_map.find(it->pt);
    if ((pl_it == pl_map.end()) || (pl_it->second.remote_pt < 0))
      continue;

    return it->pt;
  }

  return -1;
}

int AmRtpStream::nextPacket(AmRtpPacket*& p)
{
  if (!receiving && !passive)
    return RTP_EMPTY;

  struct timeval now;
  struct timeval diff;
  gettimeofday(&now,NULL);

  receive_mut.lock();
  timersub(&now,&last_recv_time,&diff);
  if(monitor_rtp_timeout &&
	 dead_rtp_time &&
     (diff.tv_sec > 0) &&
	 ((unsigned int)diff.tv_sec > dead_rtp_time)){
	CLASS_DBG("[%p] RTP Timeout detected. Last received packet is too old "
	 "(diff.tv_sec = %i, limit = %i, "
	 "remote_addr: %s:%i, "
	 "local_addr: %s:%i, "
	 "local_ssrc: 0x%x, local_tag: %s)\n",
		 this,
		 (unsigned int)diff.tv_sec,dead_rtp_time,
		 get_addr_str(&r_saddr).c_str(),am_get_port(&r_saddr),
		 get_addr_str(&l_saddr).c_str(),am_get_port(&l_saddr),
		 l_ssrc,session ? session->getLocalTag().c_str() : "no session");
	receive_mut.unlock();
    return RTP_TIMEOUT;
  }

  if(!rtp_ev_qu.empty()) {
    // first return RTP telephone event payloads
    p = rtp_ev_qu.front();
    rtp_ev_qu.pop();
    receive_mut.unlock();
    return 1;
  }

  if(receive_buf.empty()){
    receive_mut.unlock();
    return RTP_EMPTY;
  }

  p = receive_buf.begin()->second;
  receive_buf.erase(receive_buf.begin());
  receive_mut.unlock();

  return 1;
}

AmRtpPacket *AmRtpStream::reuseBufferedPacket()
{
  AmRtpPacket *p = NULL;

  receive_mut.lock();
  if(!receive_buf.empty()) {
    p = receive_buf.begin()->second;
    receive_buf.erase(receive_buf.begin());
  }
  receive_mut.unlock();
  return p;
}

void AmRtpStream::recvPacket(int fd)
{
    AmRtpPacket* p = mem.newPacket();
    if (!p) p = reuseBufferedPacket();
    if (!p) {
        out_of_buffer_errors++;
        receive_mut.lock();
        CLASS_DBG("out of buffers for RTP packets, dropping."
                  "receive_buf: %ld, rtp_ev_qu: %ld",
                  receive_buf.size(),rtp_ev_qu.size());
        mem.debug();
        receive_mut.unlock();
        // drop received data
        AmRtpPacket dummy;
        dummy.recv(fd);
        return;
    }

    if(p->recv(fd) > 0) {
        int parse_res = 0;

        // recv_time is set by SO_TIMESTAMP
        //gettimeofday(&p->recv_time,NULL);

        log_rcvd_rtp_packet(*p);
        incoming_bytes += p->getBufferSize();

        if(fd == l_rtcp_sd) {
            recvRtcpPacket(p);
            mem.freePacket(p);
            return;
        }

        if(!relay_raw
#ifdef WITH_ZRTP
           && !(session && session->enable_zrtp)
#endif
        ) {
            parse_res = p->rtp_parse();
        }

        if (parse_res == RTP_PACKET_PARSE_ERROR) {
            rtp_parse_errors++;
            CLASS_ERROR("error while parsing RTP packet. "
                        "(remote_addr: %s:%i, "
                        "local_ssrc: 0x%x, local_tag: %s)\n",
                        get_addr_str(&r_saddr).c_str(),am_get_port(&r_saddr),
                        l_ssrc,session ? session->getLocalTag().c_str() : "no session");
            clearRTPTimeout(&p->recv_time);
            mem.freePacket(p);
        } else if(parse_res==RTP_PACKET_PARSE_RTCP) {
            recvRtcpPacket(p);
            mem.freePacket(p);
            return;
        } else {
            if(rtp_ping)	//clear mark for all packets in stream
                p->marker = false;
            bufferPacket(p);
        }

    } else {
        mem.freePacket(p);
    }
}

void AmRtpStream::recvRtcpPacket(AmRtpPacket* p)
{
    handleSymmetricRtp(&p->addr,true);
    p->rtcp_parse_update_stats(rtp_stats);
}

void AmRtpStream::relay(AmRtpPacket* p, bool is_dtmf_packet, bool process_dtmf_queue)
{
    // not yet initialized
    // or muted/on-hold
    if (!l_port || mute || hold)
        return;

    if(session && !session->onBeforeRTPRelay(p,&r_saddr))
        return;

    if(!relay_raw) {
        rtp_hdr_t* hdr = (rtp_hdr_t*)p->getBuffer();

        if(process_dtmf_queue && remote_telephone_event_pt.get()) {
            hdr->ssrc = htonl(l_ssrc);
            if(dtmf_sender.sendPacket(p->timestamp,remote_telephone_event_pt->payload_type,this))
                return;
            hdr->seq = htons(sequence++);
        } else {
            if (!relay_transparent_seqno)
                hdr->seq = htons(sequence++);
            if (!relay_transparent_ssrc)
                hdr->ssrc = htonl(l_ssrc);
        }

        if(is_dtmf_packet && local_telephone_event_pt.get()) {
            hdr->pt = local_telephone_event_pt->payload_type;
        }

        if(relay_timestamp_aligning) {
            //timestamp adjust code
            unsigned int orig_ts = p->timestamp;
            unsigned int new_ts = orig_ts+ts_adjust; //adjust ts
            unsigned int ts_diff = last_sent_ts ? ts_unsigned_diff(new_ts,last_sent_ts) : 0;

            //check if diff changed more than 4 times
            if(last_sent_ts_diff && (ts_diff > (last_sent_ts_diff<<2))) {
                //it's right time to adjust
                CLASS_DBG("AmRtpStream::relay()[%p] timestamp adjust condition reached: "
                    "orig_ts: %i,"
                    "new_ts: %i, "
                    "ts_adjust: %d, "
                    "ts_diff: %i, "
                    "last_sent_ts_diff: %i",
                    this,orig_ts,new_ts,ts_adjust,ts_diff,last_sent_ts_diff);

                signed int old_ts_adjust = ts_adjust;

                ts_adjust = (last_sent_ts+last_sent_ts_diff) - orig_ts;

                CLASS_DBG("AmRtpStream::relay()[%p] ts_adjust changed from %d to %d",
                    this,old_ts_adjust,ts_adjust);

                //adjust again
                new_ts = p->timestamp+ts_adjust;

                last_sent_ts_diff = last_sent_ts ? ts_unsigned_diff(last_sent_ts,new_ts) : 0;
            } else { //if (<adjust condition>)
                //no need to recalc last_sent_ts_diff. we can use value from ts_diff
                last_sent_ts_diff = ts_diff;
            }

            p->timestamp = last_sent_ts = new_ts;
            hdr->ts = htonl(p->timestamp);

            /*CLASS_DBG("AmRtpStream::relay()[%p] packet: orig_ts: %i, ts_adjust: %d, last_sent_ts(new_ts): %i, last_sent_ts_diff: %i",
                this,orig_ts,ts_adjust,last_sent_ts,last_sent_ts_diff);*/

        } //if(relay_timestamp_aligning)

    } //if(!relay_raw)

    p->setAddr(&r_saddr);

    if(p->send(l_sd, *AmConfig.media_ifs[l_if].proto_info[laddr_if], &l_saddr) < 0){
        CLASS_ERROR("while sending RTP packet to '%s':%i\n",
        get_addr_str(&r_saddr).c_str(),am_get_port(&r_saddr));
    } else {
        //if (logger) p->logSent(logger, &l_saddr);
        p->relayed = true;
        log_sent_rtp_packet(*p);
        if(session) session->onAfterRTPRelay(p,&r_saddr);
        add_if_no_exist(outgoing_relayed_payloads,p->payload);
        outgoing_bytes += p->getBufferSize();
    }
}

int AmRtpStream::getLocalTelephoneEventRate()
{
  if (local_telephone_event_pt.get())
    return local_telephone_event_pt->clock_rate;
  return 0;
}

int AmRtpStream::getLocalTelephoneEventPT()
{
  if(local_telephone_event_pt.get())
    return local_telephone_event_pt->payload_type;
  return -1;
}

void AmRtpStream::setPayloadProvider(AmPayloadProvider* pl_prov)
{
  payload_provider = pl_prov;
}

void AmRtpStream::sendDtmf(int event, unsigned int duration_ms) {
  CLASS_DBG("AmRtpStream::sendDtmf(event = %d, duration = %u)",event,duration_ms);
  dtmf_sender.queueEvent(event,duration_ms,getLocalTelephoneEventRate());
}

void AmRtpStream::setRelayStream(AmRtpStream* stream) {
  relay_stream = stream;
  CLASS_DBG("set relay stream [%p]\n",
      stream);
}

void AmRtpStream::setRelayPayloads(const PayloadMask &_relay_payloads)
{
  relay_payloads = _relay_payloads;
}

void AmRtpStream::enableRtpRelay() {
  CLASS_DBG("enabled RTP relay\n");
  relay_enabled = true;
}

void AmRtpStream::disableRtpRelay() {
  CLASS_DBG("disabled RTP relay\n");
  relay_enabled = false;
}

void AmRtpStream::enableRawRelay()
{
  CLASS_DBG("enabled RAW relay\n");
  relay_raw = true;
}

void AmRtpStream::disableRawRelay()
{
  CLASS_DBG("disabled RAW relay\n");
  relay_raw = false;
}
 
void AmRtpStream::setRtpRelayTransparentSeqno(bool transparent) {
  CLASS_DBG("%sabled RTP relay transparent seqno\n",
      transparent ? "en":"dis");
  relay_transparent_seqno = transparent;
}

void AmRtpStream::setRtpRelayTransparentSSRC(bool transparent) {
  CLASS_DBG("%sabled RTP relay transparent SSRC\n",
      transparent ? "en":"dis");
  relay_transparent_ssrc = transparent;
}

void AmRtpStream::setRtpRelayFilterRtpDtmf(bool filter) {
  CLASS_DBG("%sabled RTP relay filtering of RTP DTMF (2833 / 3744)\n",
      filter ? "en":"dis");
  relay_filter_dtmf = filter;
}

void AmRtpStream::setRtpRelayTimestampAligning(bool enable_aligning) {
  CLASS_DBG("%sabled RTP relay timestamp aligning\n",
      enable_aligning ? "en":"dis");
  relay_timestamp_aligning = enable_aligning;
}

void AmRtpStream::setRtpForceRelayDtmf(bool relay) {
  CLASS_DBG("%sabled force relay of RTP DTMF (2833 / 3744)\n",
      relay ? "en":"dis");
  force_relay_dtmf = relay;
}

void AmRtpStream::setRtpForceRelayCN(bool relay) {
  CLASS_DBG("%sabled force relay CN payload\n",
      relay ? "en":"dis");
  force_relay_cn = relay;
}

void AmRtpStream::setSymmetricRtpEndless(bool endless) {
  CLASS_DBG("%sabled endless symmetric RTP switching\n",
      endless ? "en":"dis");
  symmetric_rtp_endless = endless;
}

void AmRtpStream::setSymmetricRtpIgnoreRTCP(bool ignore) {
  CLASS_DBG("%sabled ignore RTCP in symmetric RTP\n",
      ignore ? "en":"dis");
  symmetric_rtp_ignore_rtcp = ignore;
}

void AmRtpStream::setRtpPing(bool enable){
	CLASS_DBG("%sabled RTP Ping\n",
		enable ? "en":"dis");
	rtp_ping = enable;
}

void AmRtpStream::setRtpTimeout(unsigned int timeout){
	dead_rtp_time = timeout;
	CLASS_DBG("set RTP dead time to %i\n",
		dead_rtp_time);
}

unsigned int AmRtpStream::getRtpTimeout(){
	return dead_rtp_time;
}

void AmRtpStream::stopReceiving()
{
  if (hasLocalSocket()){
    CLASS_DBG("remove stream from RTP receiver\n");
    AmRtpReceiver::instance()->removeStream(getLocalSocket(),l_sd_ctx);
    l_sd_ctx = -1;
    if (l_rtcp_sd > 0) {
        AmRtpReceiver::instance()->removeStream(l_rtcp_sd,l_rtcp_sd_ctx);
        l_rtcp_sd_ctx = -1;
    }
  }
}

void AmRtpStream::resumeReceiving()
{
  if (hasLocalSocket()){
    CLASS_DBG("add/resume stream into RTP receiver\n");
    l_sd_ctx = AmRtpReceiver::instance()->addStream(getLocalSocket(), this, l_sd_ctx);
    if (l_rtcp_sd > 0) {
        l_rtcp_sd_ctx = AmRtpReceiver::instance()->addStream(l_rtcp_sd, this, l_rtcp_sd_ctx);
    }
    if(l_sd_ctx < 0 || (l_rtcp_sd > 0 && l_rtcp_sd_ctx < 0)){
        CLASS_ERROR("error on add/resuming stream. rtp_ctx = %d, rtcp_ctx = %d",
                    l_sd_ctx, l_rtcp_sd_ctx);
    }
  }
}

string AmRtpStream::getPayloadName(int payload_type)
{
  for(PayloadCollection::iterator it = payloads.begin();
      it != payloads.end(); ++it){

    if (it->pt == payload_type) return it->name;
  }

  return string("");
}

void AmRtpStream::payloads_id2str(const std::vector<int> i, std::vector<string> &s){
	std::vector<int>::const_iterator it = i.begin();
	for(;it!=i.end();++it){
		std::string pname;
		pname = getPayloadName(*it);
		if(pname.empty()){
			if(*it==COMFORT_NOISE_PAYLOAD_TYPE)
				pname = "CN";
			else
				pname = int2str(*it);
		} else {
			transform(pname.begin(), pname.end(), pname.begin(), ::tolower);
		}
		s.push_back(pname);
	}
}

void AmRtpStream::log_sent_rtp_packet(AmRtpPacket &p){
	update_sender_stats(p);
	if(logger)
		p.logSent(logger, &l_saddr);
	if(sensor)
		p.mirrorSent(sensor, &l_saddr);
}

void AmRtpStream::log_rcvd_rtp_packet(AmRtpPacket &p){
	if(logger)
		p.logReceived(logger, &l_saddr);
	if(sensor)
		p.mirrorReceived(sensor, &l_saddr);
}

void AmRtpStream::log_sent_rtcp_packet(const char *buffer, int len, struct sockaddr_storage &send_addr) {
	static const cstring empty;
	if (logger)
		logger->log((const char *)buffer, len, &l_rtcp_saddr, &send_addr, empty);
}

void AmRtpStream::getMediaStats(struct MediaStats &s)
{
    auto &p = s.payloads;
    payloads_id2str(incoming_payloads,p.incoming);
    payloads_id2str(incoming_relayed_payloads,p.incoming_relayed);
    payloads_id2str(outgoing_payloads,p.outgoing);
    payloads_id2str(outgoing_relayed_payloads,p.outgoing_relayed);

    auto &e  = s.errors;
    e.decode_errors = decode_errors;
    e.rtp_parse_errors = rtp_parse_errors;
    e.out_of_buffer_errors = out_of_buffer_errors;

    s.incoming_bytes = incoming_bytes;
    s.outgoing_bytes = outgoing_bytes;
}

PacketMem::PacketMem()
  : cur_idx(0), n_used(0)
{
  memset(used, 0, sizeof(used));
}

inline AmRtpPacket* PacketMem::newPacket() 
{
  //bool desired;

  if(n_used >= MAX_PACKETS)
    return NULL; // full


  while(used[cur_idx].exchange(true)) {
    cur_idx = (cur_idx + 1) & MAX_PACKETS_MASK;
  }

  n_used.fetch_add(1);

  AmRtpPacket* p = &packets[cur_idx];
  cur_idx = (cur_idx + 1) & MAX_PACKETS_MASK;

  return p;
}

inline void PacketMem::freePacket(AmRtpPacket* p) 
{
  if (!p)  return;

  int idx = p-packets;
  assert(idx >= 0);
  assert(idx < MAX_PACKETS);

  if(!used[idx]) {
    CLASS_ERROR("freePacket() double free: n_used = %d, idx = %d",
                n_used.load(),idx);
    return;
  }

  used[p-packets].store(false);
  n_used.fetch_sub(1);
}

inline void PacketMem::clear() 
{
  memset(used, 0, sizeof(used));
  n_used.store(0);
  cur_idx = 0;
}

void PacketMem::debug() {
   DBG("cur_idx: %i, n_used: %i",cur_idx,n_used.load());
}

void AmRtpStream::setLogger(msg_logger* _logger)
{
  if (logger) dec_ref(logger);
  logger = _logger;
  if (logger) inc_ref(logger);
}

void AmRtpStream::setSensor(msg_sensor *_sensor)
{
	CLASS_DBG("AmRtpStream: change sensor to %p",_sensor);

	if(sensor) dec_ref(sensor);
	sensor = _sensor;
	if(sensor) inc_ref(sensor);
}

void AmRtpStream::debug()
{
#define BOOL_STR(b) ((b) ? "yes" : "no")

  if(hasLocalSocket() > 0) {
	CLASS_DBG("\t<%i> <-> <%s:%i>", getLocalPort(),
        getRHost().c_str(), getRPort());
  } else {
    CLASS_DBG("\t<unbound> <-> <%s:%i>",
        getRHost().c_str(), getLocalPort());
  }

  if (relay_enabled && relay_stream) {
    CLASS_DBG("\tinternal relay to stream %p (local port %i)",
      relay_stream, relay_stream->getLocalPort());
  }
  else CLASS_DBG("\tno relay");

  CLASS_DBG("\tmute: %s, hold: %s, receiving: %s",
      BOOL_STR(mute), BOOL_STR(hold), BOOL_STR(receiving));

#undef BOOL_STR
}

void AmRtpStream::getInfo(AmArg &ret){
	std::stringstream s;
	s << std::hex << this;
	ret["self_ptr"] = s.str();

	s.clear();
	if(relay_stream) {
		std::stringstream s;
		s << std::hex << relay_stream;
		ret["relay_ptr"] = s.str();
	} else {
		ret["relay_ptr"] = "nullptr";
	}

	ret["sdp_media_index"] = sdp_media_index;
	ret["l_ssrc"] = int2hex(l_ssrc);

	if(hasLocalSocket() > 0){
		AmArg &a = ret["socket"];
		a["local_ip"] = AmConfig.media_ifs[l_if].proto_info[laddr_if]->getIP();
		a["local_port"] = getLocalPort();
		a["remote_host"] = getRHost();
		a["remote_port"] = getRPort();
	} else {
		ret["socket"] = "unbound";
	}

	ret["mute"] = mute;
	ret["hold"] = hold;
	ret["receiving"] = receiving;
}

void AmRtpStream::update_sender_stats(const AmRtpPacket &p)
{
	AmLock l(rtp_stats);

	//struct timeval now;

	//gettimeofday(&now, nullptr);

	rtp_stats.rtp_tx_last_ts = p.timestamp;
	rtp_stats.rtp_tx_last_seq = p.sequence;

	RtcpUnidirectionalStat &s = rtp_stats.tx;

	//s.update = now;
	//s.update_cnt++;

	s.pkt++;
	s.bytes += p.getDataSize();
}

void AmRtpStream::fill_sender_report(RtcpSenderReportHeader &s, struct timeval &now, unsigned int user_ts)
{
	uint64_t i;

	s.sender_pcount = htonl(rtp_stats.tx.pkt);
	s.sender_bcount = htonl(rtp_stats.tx.bytes);
	s.rtp_ts = htonl(user_ts);

	i = now.tv_usec;
	i <<= 32;
	i /= 1000000;
	s.ntp_frac = htonl(i);

	i = now.tv_sec;
	i += NTP_TIME_OFFSET;
	s.ntp_sec = htonl(i);
}

void AmRtpStream::init_receiver_info(const AmRtpPacket &p)
{
	r_ssrc = p.ssrc;
	rtcp_reports.update(r_ssrc);
	r_ssrc_i = true;

	rtp_stats.init_seq(p.sequence);
	rtp_stats.max_seq--;
	rtp_stats.probation = MIN_SEQUENTIAL;
}

void AmRtpStream::update_receiver_stats(const AmRtpPacket &p)
{
    AmLock l(rtp_stats);

    if((!r_ssrc_i) || (p.ssrc!=r_ssrc))
        init_receiver_info(p);

    rtp_stats.rx.pkt++;
    rtp_stats.rx.bytes += p.getDataSize();

    if(!rtp_stats.update_seq(p.sequence)) {
        /* skip jitter measurement
           for duplicated/reordered/unexpected sequence packets */
        return;
    }

    //https://tools.ietf.org/html/rfc3550#appendix-A.8
    uint64_t recv_time_msec = p.recv_time.tv_sec*1000 + p.recv_time.tv_usec/1000;
    int transit = (recv_time_msec << 3) - p.timestamp;
    if(rtp_stats.transit) {
        int d = rtp_stats.transit - transit;
        if(d < 0) d = -d;
        rtp_stats.rx.rtcp_jitter += d - ((rtp_stats.rx.rtcp_jitter + 8) >> 4);
    }
    rtp_stats.transit = transit;

    if(timerisset(&rtp_stats.rx_recv_time)) {
        timeval diff;
        timersub(&p.recv_time, &rtp_stats.rx_recv_time, &diff);
        int delay_msec = (diff.tv_sec * 1000) + (diff.tv_usec / 1000);
        rtp_stats.rx.delay_stats.update(delay_msec);
    }
    rtp_stats.rx_recv_time = p.recv_time;
}

void AmRtpStream::fill_receiver_report(RtcpReceiverReportHeader &r, struct timeval &now)
{
    struct timeval delay;

    rtp_stats.update_lost();

    r.total_lost_0 = rtp_stats.total_lost >> 16;
    r.total_lost_1 = (rtp_stats.total_lost >> 8) & 0xff;
    r.total_lost_2 = rtp_stats.total_lost & 0xff;

    r.fract_lost = rtp_stats.fraction_lost;

    r.last_seq = ((rtp_stats.cycles << 16) | (rtp_stats.max_seq & 0xffff));
    r.last_seq = htonl(r.last_seq);

    if(rtp_stats.sr_lsr) {
        r.lsr = htonl(rtp_stats.sr_lsr);

        timersub(&now,&rtp_stats.sr_recv_time,&delay);
        r.dlsr = (delay.tv_sec << 16);
        r.dlsr |= (uint16_t)(delay.tv_usec*65536/1e6);
        r.dlsr = htonl(r.dlsr);
    } else {
        r.lsr = 0;
        r.dlsr = 0;
    }

    r.jitter = htonl(rtp_stats.rx.rtcp_jitter >> 4);
}


void AmRtpStream::processRtcpTimers(unsigned long long system_ts, unsigned int user_ts)
{
    unsigned long long scaled_ts = system_ts/WALLCLOCK_RATE;

    if(!last_send_rtcp_report_ts) {
        last_send_rtcp_report_ts = scaled_ts;
    } else {
        if((scaled_ts - last_send_rtcp_report_ts) > RTCP_REPORT_SEND_INTERVAL_SECONDS) {
            last_send_rtcp_report_ts = scaled_ts;
            rtcp_send_report(user_ts);
        }
    }
}

void AmRtpStream::rtcp_send_report(unsigned int user_ts)
{
    int err;
    void *buf;
    struct timeval now;
    unsigned int len;

    gettimeofday(&now, nullptr);

    rtp_stats.lock();

    if(rtp_stats.tx.pkt) {
        if(rtp_stats.rx.pkt) {
            //SR with RR data
            fill_sender_report(rtcp_reports.sr.sr.sender,now,user_ts);
            fill_receiver_report(rtcp_reports.sr.sr.receiver, now);
            buf = &rtcp_reports.sr;
            len = sizeof(rtcp_reports.sr);
        } else {
            //SR without RR data
            fill_sender_report(rtcp_reports.sr_empty.sr.sender,now,user_ts);
            buf = &rtcp_reports.sr_empty;
            len = sizeof(rtcp_reports.sr_empty);
        }
    } else { //no data sent
        if(rtp_stats.rx.pkt) {
            //RR with data
            fill_receiver_report(rtcp_reports.rr.rr.receiver, now);
            buf = &rtcp_reports.rr;
            len = sizeof(rtcp_reports.rr);
        } else {
            //RR without data
            buf = &rtcp_reports.rr_empty;
            len = sizeof(rtcp_reports.rr_empty);
        }
    }

    rtp_stats.unlock();

    const MEDIA_info &iface = *AmConfig.media_ifs[l_if].proto_info[laddr_if];
    if(iface.net_if_idx && iface.sig_sock_opts&trsp_socket::use_raw_sockets) {
        err = raw_sender::send(
            (const char *)buf,len,
            iface.net_if_idx,
            &l_rtcp_saddr, &r_rtcp_saddr,
            iface.tos_byte);
    } else {
        err = sendto(l_rtcp_sd,
            (const char *)buf,len,
            0,
            (const struct sockaddr *)&r_rtcp_saddr, SA_len(&r_rtcp_saddr));
        DBG("err = %d",err);
    }
    //TODO: process case with AmConfig.force_outbound_if properly

    if(err < 0) {
        CLASS_ERROR("failed to send RTCP packet: %s. fd: %d, raddr: %s:%d, buf: %p:%d",
                    strerror(errno),
                    l_rtcp_sd,
                    get_addr_str(&r_rtcp_saddr).c_str(),
                    am_get_port(&r_rtcp_saddr),
                    buf,len);
        return;
    }

#define ADDR_ARGS(addr) am_inet_ntop(&addr).c_str(),am_get_port(&addr)

	/*CLASS_DBG("RTCP report is sent from %s:%d to %s:%d",
			  ADDR_ARGS(l_rtcp_saddr),
			  ADDR_ARGS(r_rtcp_saddr));*/

	log_sent_rtcp_packet((const char *)buf, len, r_rtcp_saddr);
}
