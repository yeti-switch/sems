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

#include "AmSession.h"
#include "AmSdp.h"
#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmApi.h"
#include "AmSessionContainer.h"
#include "AmSessionProcessor.h"
#include "AmMediaProcessor.h"
#include "AmDtmfDetector.h"
#include "AmPlayoutBuffer.h"
#include "AmAppTimer.h"

#include "signal.h"
#include "sys/types.h"

#include <typeinfo>

#include "log.h"

#include <algorithm>

#include <unistd.h>
#include <assert.h>
#include <sys/time.h>
#include "sip/parse_via.h"

volatile unsigned int AmSession::session_num = 0;
AmMutex AmSession::session_num_mut;
volatile unsigned int AmSession::max_session_num = 0;
volatile unsigned long long AmSession::avg_session_num = 0;
bool AmSession::terminate_on_no_sessions = true;

struct timeval get_now() {
  struct timeval res;
  gettimeofday(&res, NULL);
  return res;
}
struct timeval avg_last_timestamp = get_now();
struct timeval avg_first_timestamp = avg_last_timestamp;

static const char* ProcessingStatusStr[] = {
    "ProcessingEvents",
    "WaitingDisconnected",
    "EndedDisconnected"
};

// AmSession methods

AmSession::AmSession(AmSipDialog* p_dlg)
  : AmEventQueue(this),
    m_dtmfDetector(this), m_dtmfEventQueue(&m_dtmfDetector),
    m_dtmfDetectionEnabled(true),
    record_audio_enabled(false),
    processing_status(SESSION_PROCESSING_EVENTS),
#ifdef SESSION_THREADPOOL
    start_on_same_thread(false),
    _pid(this),
#endif
    no_reply(false),
    sess_stopped(false),
    accept_early_session(false),
    override_frame_size(0),
    media_transport(TransProt::TP_NONE),
    media_type(MediaType::MT_AUDIO),
    reuse_media_slot(true),
    use_ice_media_stream(false),
    rtcp_multiplexing(false),
    rtp_interface(-1),
    rtp_proto_id(-1),
    sdp_offer_owner(true),
    symmetric_rtp_endless(false),
    symmetric_candidate(AmConfig.force_symmetric_candidate),
    input(nullptr), output(nullptr),
    refresh_method(REFRESH_UPDATE_FB_REINV),
    enable_zrtp(false),
    dlg(p_dlg)
{
    DBG3("AmSession[%p](%p)",this,dlg);
    if(!dlg) dlg = new AmSipDialog(this);
    else {
        dlg->setEventhandler(this);
        dlg->setRel100Handler(this);
    }
}

AmSession::~AmSession()
{
  DBG3("~AmSession[%p]",this);

  for(vector<AmSessionEventHandler*>::iterator evh = ev_handlers.begin();
      evh != ev_handlers.end(); evh++) {
    
    if((*evh)->destroy)
      delete *evh;
  }

  delete dlg;
}

AmSipDialog* AmSession::createSipDialog()
{
  return new AmSipDialog(this);
}

void AmSession::setCallgroup(const string& cg) {
  callgroup = cg;
}

string AmSession::getCallgroup() {
  return callgroup;
}

void AmSession::changeCallgroup(const string& cg) {
  callgroup = cg;
  AmMediaProcessor::instance()->changeCallgroup(this, cg);
}

void AmSession::startMediaProcessing() 
{
  if(getStopped() || isProcessingMedia())
    return;

  if(isAudioSet()) {
    AmMediaProcessor::instance()->addSession(this, callgroup);
  }
  else {
    DBG("no audio input and output set. "
	"Session will not be attached to MediaProcessor.\n");
  }
}

void AmSession::stopMediaProcessing() 
{
  if(!isProcessingMedia())
    return;

  AmMediaProcessor::instance()->removeSession(this);
}

void AmSession::setMediaTransport(TransProt trsp)
{
    CLASS_DBG("set transport to: %d(%s)",trsp, transport_p_2_str(trsp).c_str());
    media_transport = trsp;
}

void AmSession::setMediaType(MediaType type)
{
    CLASS_DBG("set type to: %d(%s)",type, SdpMedia::type2str(type).c_str());
    media_type = type;
}

void AmSession::setReuseMediaSlot(bool reuse_media)
{
    CLASS_DBG("set reuse media slot: %s", reuse_media ? "true" : "false");
    reuse_media_slot = reuse_media;
}

void AmSession::addHandler(AmSessionEventHandler* sess_evh)
{
  if (sess_evh != NULL)
    ev_handlers.push_back(sess_evh);
}

void AmSession::setInput(AmAudio* in)
{
  lockAudio();
  input = in;
  unlockAudio();
}

void AmSession::setOutput(AmAudio* out)
{
  DBG("AmSession[%p]::setOutput(AmAudio* out = %p)",this,out);
  lockAudio();
  output = out;
  unlockAudio();
}

void AmSession::setInOut(AmAudio* in,AmAudio* out)
{
  lockAudio();
  input = in;
  output = out;
  unlockAudio();
}
  
bool AmSession::isAudioSet()
{
  lockAudio();
  bool set = input || output;
  unlockAudio();
  return set;
}

void AmSession::lockAudio() const
{ 
  audio_mut.lock();
}

void AmSession::unlockAudio() const
{
  audio_mut.unlock();
}

const string& AmSession::getCallID() const
{ 
  return dlg->getCallid();
}

const string& AmSession::getRemoteTag() const
{ 
  return dlg->getRemoteTag();
}

const string& AmSession::getLocalTag() const
{
  return dlg->getLocalTag();
}

const string& AmSession::getFirstBranch() const
{
  return dlg->get1stBranch();
}

void AmSession::setUri(const string& uri)
{
  DBG("AmSession::setUri(%s)",uri.c_str());
  /* TODO: sdp.uri = uri;*/
}

void AmSession::setRtpFrameSize(unsigned int frame_size)
{
  DBG("AmSession::setRtpFrameSize(%u)",frame_size);
  override_frame_size = frame_size;
}

bool AmSession::getRtpFrameSize(unsigned int& frame_size)
{
    if(override_frame_size) {
        frame_size = override_frame_size;
        return true;
    }

    return false;
}

void AmSession::setLocalTag()
{
  if (dlg->getLocalTag().empty()) {
    string new_id = getNewId();
    dlg->setLocalTag(new_id);
    DBG3("AmSession::setLocalTag() - session id set to %s", new_id.c_str());
  }
}

void AmSession::setLocalTag(const string& tag)
{
  DBG3("AmSession::setLocalTag(%s)",tag.c_str());
  dlg->setLocalTag(tag);
}

const vector<SdpPayload*>& AmSession::getPayloads()
{
  return m_payloads;
}

int AmSession::getRPort()
{
  return RTPStream()->getRPort(RTP_TRANSPORT);
}

void AmSession::setRecordAudio(bool record_audio)
{
    record_audio_enabled = record_audio;
}

void AmSession::addStereoRecorder(int channel_id, const string &recorder_id)
{
    CLASS_DBG("add stereo recorder. recorder_id: %s, channel_id: %d",
        recorder_id.c_str(),channel_id);

    stereo_recorders.add(
        recorder_id.empty() ? getLocalTag() : recorder_id,
        channel_id);

    if(!hasRtpStream()) return;

    DBG("update RTP stream stereo recorders info");

    RTPStream()->setStereoRecorders(stereo_recorders, this);
    RTPStream()->disableRtpRelay();
}

void AmSession::delStereoRecorder(int channel_id, const string &recorder_id)
{
    CLASS_DBG("remove stereo recorder. recorder_id: %s, channel_id: %d",
        recorder_id.c_str(),channel_id);

    stereo_recorders.del(
        recorder_id.empty() ? getLocalTag() : recorder_id,
        channel_id);

    if(!hasRtpStream()) return;

    DBG("update RTP stream stereo recorders info");

    RTPStream()->setStereoRecorders(stereo_recorders, this);
}

#ifdef SESSION_THREADPOOL
void AmSession::start() {
  AmSessionProcessorThread* processor_thread = 
    AmSessionProcessor::getProcessorThread(start_on_same_thread);
  if (NULL == processor_thread) 
    throw string("no processing thread available");

  // have the thread register and start us
  processor_thread->startSession(this);
}

bool AmSession::is_stopped() {
  return processing_status == SESSION_ENDED_DISCONNECTED;
}
#else
// in this case every session has its own thread 
// - this is the main processing loop
void AmSession::run() {
  DBG("startup session");
  setThreadName("AmSession");
  if (!startup())
    return;

  DBG("running session event loop");
  while (true) {
    waitForEvent();
    if (!processingCycle())
      break;
  }

  DBG("session event loop ended, finalizing session");
  finalize();
}
#endif

bool AmSession::startup() {
  session_started();

  try {
    try {
      onStart();
    } 
    catch(const AmSession::Exception& e){ throw e; }
    catch(const string& str){
      ERROR("%s",str.c_str());
      throw AmSession::Exception(500,"unexpected exception.");
    }
    catch(...){
      throw AmSession::Exception(500,"unexpected exception.");
    }
    
  } catch(const AmSession::Exception& e){
    ERROR("%i %s",e.code,e.reason.c_str());
    onBeforeDestroy();
    destroy();
    
    session_stopped();

    return false;
  }

  return true;
}

bool AmSession::processEventsCatchExceptions(EventStats *stats)
{
    try {
        try {
            processEvents(stats);
        } catch(const AmSession::Exception& e) {
            throw e;
        } catch(const string& str) {
            DBG("%s", str.c_str());
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        } catch(...) {
            throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
        }
    } catch(const AmSession::Exception& e) {
        DBG("processEventsCatchExceptions(): got exception %i %s", e.code,e.reason.c_str());
        return onException(e.code,e.reason);
    }

    return true;
}

void AmSession::postEvent(AmEvent* event)
{
    if(!is_stopped())
        AmEventQueue::postEvent(event);
    else {
        AmSipRequestEvent* ev_req = dynamic_cast<AmSipRequestEvent*>(event);
        if(ev_req) {
            AmSipDialog::reply_error(ev_req->req,481,SIP_REPLY_NOT_EXIST);
        }
        delete event;
    }
}

/** one cycle of the event processing loop. 
    this should be called until it returns false. */
bool AmSession::processingCycle(EventStats *stats) {

    DBG("vv S [%s|%s] %s, %s, %i UACTransPending, %i usages vv",
        dlg->getCallid().c_str(),getLocalTag().c_str(),
        dlg->getStatusStr(),
        sess_stopped.get()?"stopped":"running",
        dlg->getUACTransPending(),
        dlg->getUsages());

    switch (processing_status) {
    case SESSION_PROCESSING_EVENTS: {
        if (!processEventsCatchExceptions(stats)) {
            // exception occured, stop processing
            processing_status = SESSION_ENDED_DISCONNECTED;
            return false;
        }

        AmSipDialog::Status dlg_status = dlg->getStatus();
        bool s_stopped = sess_stopped.get();

        DBG("^^ S [%s|%s] %s, %s, %i UACTransPending, %i usages ^^",
            dlg->getCallid().c_str(),getLocalTag().c_str(),
            AmBasicSipDialog::getStatusStr(dlg_status),
            s_stopped?"stopped":"running",
            dlg->getUACTransPending(),
            dlg->getUsages());

        // session running?
        if (!s_stopped || (dlg_status == AmSipDialog::Disconnecting)
            || dlg->getUsages())
        {
            return true;
        }

        // session stopped?
        if (s_stopped &&
            (dlg_status == AmSipDialog::Disconnected))
        {
            processing_status = SESSION_ENDED_DISCONNECTED;
            return false;
        }

        // wait for session's status to be disconnected
        // todo: set some timer to tear down the session anyway,
        //       or react properly on negative reply to BYE (e.g. timeout)
        processing_status = SESSION_WAITING_DISCONNECTED;

        if ((dlg_status != AmSipDialog::Disconnected) &&
            (dlg_status != AmSipDialog::Cancelling)&&
            !no_reply)
        {
            DBG("app did not send BYE - do that for the app");
            if (dlg->bye("",SIP_FLAGS_VERBATIM,true) != 0) {
                processing_status = SESSION_ENDED_DISCONNECTED;
                // BYE sending failed - don't wait for dlg status to go disconnected
                return false;
            }
            //check if dialog status was changed to Disconnected by dlg->bye()
            //so we can cleanly end session
            if (s_stopped &&
                (dlg->getStatus() == AmSipDialog::Disconnected))
            {
                processing_status = SESSION_ENDED_DISCONNECTED;
                return false;
            }
        }

        return true;

    } break; //SESSION_PROCESSING_EVENTS

    case SESSION_WAITING_DISCONNECTED: {
        // processing events until dialog status is Disconnected

        if (!processEventsCatchExceptions(stats)) {
            processing_status = SESSION_ENDED_DISCONNECTED;
            return false; // exception occured, stop processing
        }

        bool res = dlg->getStatus() != AmSipDialog::Disconnected;
        if (!res)
            processing_status = SESSION_ENDED_DISCONNECTED;

        DBG("^^ S [%s|%s] %s, %s, %i UACTransPending, %i usages ^^",
            dlg->getCallid().c_str(),getLocalTag().c_str(),
            dlg->getStatusStr(),
            sess_stopped.get()?"stopped":"running",
            dlg->getUACTransPending(),
            dlg->getUsages());

        return res;
    }; break; //SESSION_WAITING_DISCONNECTED

    default: {
        ERROR("unknown session processing state");
        return false; // stop processing
    }}
}

void AmSession::finalize()
{
  DBG3("running finalize sequence...");
  dlg->finalize();

  onBeforeDestroy();
  destroy();
  
  session_stopped();

  DBG3("session is stopped.");
}
#ifndef SESSION_THREADPOOL
  void AmSession::on_stop() 
#else
  void AmSession::stop()
#endif  
{
  DBG3("AmSession::stop()");

  if (!isDetached())
    AmMediaProcessor::instance()->clearSession(this);
  else
    clearAudio();
}

void AmSession::setStopped(bool wakeup) {
  if (!sess_stopped.get()) {
    sess_stopped.set(true); 
    onStop();
  }
  if (wakeup) 
    AmSessionContainer::instance()->postEvent(getLocalTag(), 
					      new AmEvent(0));
}

string AmSession::getAppParam(const string& param_name) const
{
  map<string,string>::const_iterator param_it;
  param_it = app_params.find(param_name);
  if(param_it != app_params.end())
    return param_it->second;
  else
    return "";
}

void AmSession::destroy() {
  DBG3("AmSession::destroy()");
  AmSessionContainer::instance()->destroySession(this);
}

string AmSession::getNewId() {
  struct timeval t;
  gettimeofday(&t,NULL);

  string id = AmConfig.node_id_prefix;

  id += int2hex(get_random()) + "-";
  id += int2hex(t.tv_sec) + int2hex(t.tv_usec) + "-";
  id += int2hex((unsigned int)((unsigned long)pthread_self()));

  return id;
}
/* bookkeeping functions - TODO: move to monitoring */
void AmSession::session_started() {
  struct timeval now, delta;

  session_num_mut.lock();
  //avg session number
  gettimeofday(&now, NULL);
  timersub(&now, &avg_last_timestamp, &delta);
  avg_session_num = avg_session_num + (session_num * (delta.tv_sec * 1000000ULL + delta.tv_usec));
  avg_last_timestamp = now;

  //current session number
  session_num = session_num + 1;

  //maximum session number
  if(session_num > max_session_num) max_session_num = session_num;

  session_num_mut.unlock();
}

void AmSession::session_stopped() {
  struct timeval now, delta;
  session_num_mut.lock();
  //avg session number
  gettimeofday(&now, NULL);
  timersub(&now, &avg_last_timestamp, &delta);
  avg_session_num = avg_session_num + (session_num * (delta.tv_sec * 1000000ULL + delta.tv_usec));
  avg_last_timestamp = now;
  //current session number
  session_num = session_num - 1;
  if(AmConfig.shutdown_mode
     && terminate_on_no_sessions
     &&!session_num)
  {
    AmConfig.shutdown_handlers_processor.onShutdownRequested();
  }
  session_num_mut.unlock();
}

unsigned int AmSession::getSessionNum() {
  unsigned int res = 0;
  session_num_mut.lock();
  res = session_num;
  session_num_mut.unlock();
  return res;
}

unsigned int AmSession::getMaxSessionNum() {
  unsigned int res = 0;
  session_num_mut.lock();
  res = max_session_num;
  max_session_num = session_num;
  session_num_mut.unlock();
  return res;
}

unsigned int AmSession::getAvgSessionNum() {
  unsigned int res = 0;
  struct timeval now, delta;
  session_num_mut.lock();
  gettimeofday(&now, NULL);
  timersub(&now, &avg_last_timestamp, &delta);
  avg_session_num = avg_session_num + (session_num * (delta.tv_sec * 1000000ULL + delta.tv_usec));
  timersub(&now, &avg_first_timestamp, &delta);
  unsigned long long d_usec = delta.tv_sec * 1000000ULL + delta.tv_usec;
  if (!d_usec) {
    res = 0;
    WARN("zero delta!");
  } else {
    //Round up
    res = (unsigned int)((avg_session_num + d_usec - 1) / d_usec);
  }
  avg_session_num = 0;
  avg_last_timestamp = now;
  avg_first_timestamp = now;
  session_num_mut.unlock();
  return res;
}

void AmSession::setInbandDetector(Dtmf::InbandDetectorType t)
{ 
  m_dtmfDetector.setInbandDetector(t, RTPStream()->getSampleRate()); 
}

void AmSession::postDtmfEvent(AmDtmfEvent *evt)
{
   DBG("AmSession::postDtmfEvent(evt: { class: %s, event_id: %d, event: %d, duration: %d})",
       typeid(*evt).name(),evt->event_id,evt->event(),evt->duration());
   //log_stacktrace(L_DBG);

  if (m_dtmfDetectionEnabled)
    {
	  if (/*dynamic_cast<AmSipDtmfEvent *>(evt) ||*/
	  dynamic_cast<AmRtpDtmfEvent *>(evt))
        {   
	  // this is a raw event from sip info or rtp
		  //DBG("post as raw event");
	  m_dtmfEventQueue.postEvent(evt);
        }
	  else
        {
	  // this is an aggregated event, 
	  // post it into our event queue
		  //DBG("post as aggregated event");
		postEvent(evt);
        }
    }
}

void AmSession::processDtmfEvents()
{
  if (m_dtmfDetectionEnabled)
    {
      m_dtmfEventQueue.processEvents();
    }
}

void AmSession::putDtmfAudio(const unsigned char *buf, int size, unsigned long long system_ts)
{
  bool dtmf_detected;
  m_dtmfEventQueue.putDtmfAudio(dtmf_detected, buf, size, system_ts);
}

void AmSession::sendDtmf(int event, unsigned int duration_ms, int volume)
{
    RTPStream()->sendDtmf(event, duration_ms, volume);
}


void AmSession::onDtmf(AmDtmfEvent* e)
{
  DBG("AmSession::onDtmf(%i,%i)",e->event(),e->duration());
}

void AmSession::clearAudio()
{
  lockAudio();

  if (input) {
    input->close();
    input = NULL;
  }
  if (output) {
    output->close();
    output = NULL;
  }

  unlockAudio();
  DBG3("Audio cleared !!!");
  postEvent(new AmAudioEvent(AmAudioEvent::cleared));
}

void AmSession::process(AmEvent* ev)
{
  CALL_EVENT_H(process,ev);

  DBG3("AmSession processing event");

  if (ev->event_id == E_SYSTEM) {
    AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
    if(sys_ev){	
      DBG3("Session received system Event");
      onSystemEvent(sys_ev);
      return;
    }
  }

  AmSipEvent* sip_ev = dynamic_cast<AmSipEvent*>(ev);
  if(sip_ev){
    (*sip_ev)(dlg);
    return;
  }

  AmAudioEvent* audio_ev = dynamic_cast<AmAudioEvent*>(ev);
  if(audio_ev){
    onAudioEvent(audio_ev);
    return;
  }

  AmDtmfEvent* dtmf_ev = dynamic_cast<AmDtmfEvent*>(ev);
  if (dtmf_ev) {
    DBG3("Session received DTMF, event = %d, duration = %d", 
	dtmf_ev->event(), dtmf_ev->duration());
    onDtmf(dtmf_ev);
    return;
  }

  AmRtpTimeoutEvent* timeout_ev = dynamic_cast<AmRtpTimeoutEvent*>(ev);
  if(timeout_ev){
    onRtpTimeout();
    return;
  }
}

void AmSession::onSipRequest(const AmSipRequest& req)
{
  CALL_EVENT_H(onSipRequest,req);

  DBG3("onSipRequest: method = %s",req.method.c_str());

  updateRefreshMethod(req.hdrs);

  if(req.method == SIP_METH_INVITE){

    try {
      onInvite(req);
    }
    catch(const string& s) {
	  DBG("AmSession::string exception: %s",s.c_str());
      setStopped();
	  onInviteException(500,SIP_REPLY_SERVER_INTERNAL_ERROR,false);
	  dlg->reply(req, 500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
    catch(const AmSession::Exception& e) {
	  DBG("AmSession::Exception: %i %s",e.code,e.reason.c_str());
      setStopped();
      no_reply = (e.code == NO_REPLY_DISCONNECT_CODE);
	  onInviteException(e.code,e.reason,no_reply);
      if(!no_reply)
        dlg->reply(req, e.code, e.reason, NULL, e.hdrs);
      else
          DBG("AmSession::onSipREquest() suspress reply with reason '%s'",
              e.reason.c_str());
    }
  }
  else if(req.method == SIP_METH_ACK){
    return;
  }
  else if( req.method == SIP_METH_BYE ){
    dlg->reply(req,200,"OK");
    onBye(req);
  }
  else if( req.method == SIP_METH_CANCEL ){
    onCancel(req);
  } 
  else if( req.method == SIP_METH_INFO ){
	Dtmf::SipEventType type;
	const AmMimeBody* dtmf_body;
	bool supported = false;

	if ((dtmf_body = req.body.hasContentType("application/dtmf-relay"))) {
		type = Dtmf::DTMF_RELAY;
		supported = true;
	} else if((dtmf_body = req.body.hasContentType("application/dtmf"))){
		type = Dtmf::DTMF;
		supported = true;
	}

	if(supported){
		string dtmf_body_str((const char*)dtmf_body->getPayload(),
				 dtmf_body->getLen());
		postDtmfEvent(new AmSipDtmfEvent(dtmf_body_str,type));
		dlg->reply(req, 200, "OK");
	} else {
		dlg->reply(req, 415, "Unsupported Media Type");
	}
  } else if (req.method == SIP_METH_PRACK) {
    // TODO: SDP
    dlg->reply(req, 200, "OK");
    // TODO: WARN: only include latest SDP if req.rseq == dlg->rseq (latest 1xx)
  }
  else {
    dlg->reply(req, 501, "Not implemented");
  }
}

void AmSession::onSipReply(const AmSipRequest& req, const AmSipReply& reply,
			   AmBasicSipDialog::Status old_dlg_status)
{
  CALL_EVENT_H(onSipReply, req, reply, old_dlg_status);

  updateRefreshMethod(reply.hdrs);

  if (dlg->getStatus() < AmSipDialog::Connected &&
      reply.code == 180) {
    onRinging(reply);
  }

  if (old_dlg_status != dlg->getStatus()) {
    DBG("Dialog status changed %s -> %s (stopped=%s) ", 
	AmBasicSipDialog::getStatusStr(old_dlg_status), 
	dlg->getStatusStr(),
	sess_stopped.get() ? "true" : "false");
  } else {
    DBG("Dialog status stays %s (stopped=%s)", 
	AmBasicSipDialog::getStatusStr(old_dlg_status), 
	sess_stopped.get() ? "true" : "false");
  }
}

void AmSession::onInvite2xx(const AmSipReply& reply)
{
  dlg->send_200_ack(reply.cseq);
}

void AmSession::onRemoteDisappeared(const AmSipReply&) {
  // see 3261 - 12.2.1.2: should end dialog on 408/481
  DBG("Remote end unreachable - ending session");
  dlg->bye();
  setStopped();
}

void AmSession::onNoAck(unsigned int cseq)
{
  if (dlg->getStatus() == AmSipDialog::Connected)
    dlg->bye();
  dlg->drop();
  setStopped();
}

void AmSession::onNoPrack(const AmSipRequest &req, const AmSipReply &rpl)
{
  dlg->reply(req, 504, "Server Time-out");
  // TODO: handle forking case (when more PRACKs are sent, out of which some
  // might time-out/fail).
  if (dlg->getStatus() < AmSipDialog::Connected)
    setStopped();
}

void AmSession::onAudioEvent(AmAudioEvent* audio_ev)
{
  if (audio_ev->event_id == AmAudioEvent::cleared)
    setStopped();
}

void AmSession::onInvite(const AmSipRequest& req)
{
  dlg->reply(req,200,"OK");
}

void AmSession::onBye(const AmSipRequest& req)
{
  setStopped();
}

void AmSession::onCancel(const AmSipRequest& cancel)
{
  dlg->bye();
  setStopped();
}

void AmSession::onSystemEvent(AmSystemEvent* ev) {
  if (ev->sys_event == AmSystemEvent::ServerShutdown) {
    setStopped();
    return;
  }
}

void AmSession::onSendRequest(AmSipRequest& req, int& flags)
{
  CALL_EVENT_H(onSendRequest,req,flags);
}

void AmSession::onSendReply(const AmSipRequest& req, AmSipReply& reply, int& flags)
{
  CALL_EVENT_H(onSendReply,req,reply,flags);
}

/** Hook called when an SDP offer is required */
bool AmSession::getSdpOffer(AmSdp& offer)
{
  DBG("AmSession::getSdpOffer(...) ...");

  offer.version = 0;
  offer.origin.user = AmConfig.sdp_origin;
  //offer.origin.sessId = 1;
  //offer.origin.sessV = 1;
  offer.sessionName = AmConfig.sdp_session_name;

  // TODO: support mutiple media types (needs multiples RTP streams)
  // TODO: support update instead of clearing everything

  if(RTPStream()->getSdpMediaIndex() < 0)
    offer.media.clear();

  unsigned int media_idx = 0;
  if(!offer.media.size()) {
    offer.media.push_back(SdpMedia());
  } else {
    media_idx = RTPStream()->getSdpMediaIndex();
      if(!reuse_media_slot && offer.media[media_idx].type != media_type) {
          offer.media[media_idx].port = 0;
          offer.media[media_idx].send = false;
          offer.media[media_idx].recv = false;
      } else {
          offer.media.clear();
      }

      offer.media.push_back(SdpMedia());
      media_idx = offer.media.size() - 1;
  }

  if(!offer.media.empty() && override_frame_size) {
    auto &m = offer.media.back();
    m.frame_size = override_frame_size;
  }

  RTPStream()->setLocalIP();
  RTPStream()->getSdpOffer(media_idx,offer.media.back());

  sockaddr_storage ss;
  am_inet_pton(RTPStream()->getLocalIP().c_str(), &ss);
  offer.conn.network = NT_IN;
  offer.conn.addrType = ss.ss_family == AF_INET ? AT_V4 : AT_V6;
  offer.conn.address = RTPStream()->getLocalAddress();
  return true;
}

struct codec_priority_cmp
{
public:
  codec_priority_cmp() {}

  bool operator()(const SdpPayload& left, const SdpPayload& right)
  {
    for (vector<string>::iterator it = AmConfig.codec_order.begin(); it != AmConfig.codec_order.end(); it++) {
      if (strcasecmp(left.encoding_name.c_str(),it->c_str())==0 && strcasecmp(right.encoding_name.c_str(), it->c_str())!=0)
	return true;
      if (strcasecmp(right.encoding_name.c_str(),it->c_str())==0)
	return false;
    }

    return false;
  }
};

/** Hook called when an SDP answer is required */
bool AmSession::getSdpAnswer(const AmSdp& offer, AmSdp& answer)
{
    CLASS_DBG("AmSession::getSdpAnswer(...) ...");

    bool connection_line_is_processed = false;

    answer.version = 0;
    answer.origin.user = AmConfig.sdp_origin;
    answer.sessionName = AmConfig.sdp_session_name;

    AddressType addrtype = AT_V4;

    if(!offer.conn.address.empty()) {
        addrtype = offer.conn.addrType;
        connection_line_is_processed = true;
    }

    answer.media.clear();

    bool audio_1st_stream = true;
    unsigned int media_index = 0;

    for(const auto &m: offer.media) {
        answer.media.push_back(SdpMedia());
        SdpMedia& answer_media = answer.media.back();
        auto &answer_payloads = answer_media.payloads;

        if( m.type == MT_AUDIO
            && m.transport != TP_UDPTL
            && media_type != MT_IMAGE
            && audio_1st_stream
            && (m.port != 0) )
        {
            if(!connection_line_is_processed) {
                if(m.conn.address.empty()) {
                    throw Exception(488, "missed c= line");
                }
                addrtype = m.conn.addrType;
                connection_line_is_processed = true;
            }

            setRtcpMultiplexing(m.is_multiplex);

            RTPStream()->setLocalIP(addrtype);
            RTPStream()->getSdpAnswer(media_index,m,answer_media);

            /* TODO: here could be issue when multiple media streams
               use different address families. add additional checks */
            
            if(answer_media.is_use_ice()) {
                answer.use_ice = true;
            }

            answer_media.frame_size = override_frame_size ? override_frame_size : m.frame_size;

            if(answer_payloads.empty() ||
               ((answer_payloads.size() == 1) &&
               (answer_payloads[0].encoding_name == "telephone-event")))
            {
                // no compatible media found
                throw Exception(488,"no compatible payload");
            }

            audio_1st_stream = false;
        } else if(m.type == MT_IMAGE
                  && (m.transport == TP_UDPTL || m.transport == TP_UDPTLSUDPTL)
                  && media_type == MT_IMAGE
                  && (m.port != 0)) {
            RTPStream()->setLocalIP(addrtype);
            RTPStream()->getSdpAnswer(media_index,m,answer_media);
        } else {
            answer_media.type = m.type;
            answer_media.port = 0;
            answer_media.nports = 0;
            answer_media.transport = m.transport;
            answer_media.send = false;
            answer_media.recv = false;
            answer_media.frame_size = m.frame_size;
            answer_media.fmt = m.fmt;
            answer_payloads.clear();
            if(!m.payloads.empty()) {
                SdpPayload dummy_pl = m.payloads.front();
                dummy_pl.encoding_name.clear();
                dummy_pl.sdp_format_parameters.clear();
                answer_payloads.push_back(dummy_pl);
            }
            answer_media.attributes.clear();
        }
        // sort payload type in the answer according to the priority given in the codec_order configuration key
        std::stable_sort(answer_payloads.begin(),answer_payloads.end(),codec_priority_cmp());
        media_index++;
    } //

    answer.conn.network = NT_IN;
    answer.conn.addrType = addrtype;
    answer.conn.address = RTPStream()->getLocalAddress();
    return true;
}

int AmSession::onSdpCompleted(const AmSdp& local_sdp, const AmSdp& remote_sdp, bool sdp_offer_owner)
{
  DBG("AmSession::onSdpCompleted(..., %d) ...", sdp_offer_owner);
  this->sdp_offer_owner = sdp_offer_owner;

  if(local_sdp.media.empty() || remote_sdp.media.empty()) {

    ERROR("Invalid SDP");

    string debug_str;
    local_sdp.print(debug_str);
    ERROR("Local SDP:\n%s",
	  debug_str.empty() ? "<empty>"
	  : debug_str.c_str());
    
    remote_sdp.print(debug_str);
    ERROR("Remote SDP:\n%s",
	  debug_str.empty() ? "<empty>"
	  : debug_str.c_str());

    return -1;
  }

  /*bool set_on_hold = false;
  if (!remote_sdp.media.empty()) {
    vector<SdpAttribute>::const_iterator pos =
      std::find(remote_sdp.media[0].attributes.begin(), remote_sdp.media[0].attributes.end(), SdpAttribute("sendonly"));
    set_on_hold = pos != remote_sdp.media[0].attributes.end();
  }*/

  lockAudio();

  // TODO: 
  //   - get the right media ID
  //   - check if the stream coresponding to the media ID 
  //     should be created or updated   
  //
  int ret = 0;

  try {
    ret = RTPStream()->init(local_sdp, remote_sdp, sdp_offer_owner, AmConfig.force_symmetric_rtp);
    RTPStream()->setStereoRecorders(getStereoRecorders(), nullptr);
  } catch (const string& s) {
    ERROR("Error while initializing RTP stream: '%s'", s.c_str());
    ret = -1;
  } catch (...) {
    ERROR("Error while initializing RTP stream (unknown exception in AmRTPStream::init)");
    ret = -1;
  }

  unlockAudio();

  if(ret == -1) onInitStreamFailed();

  if (!isProcessingMedia()) {
    setInbandDetector(AmConfig.default_dtmf_detector);
  }

  return ret;
}

void AmSession::onEarlySessionStart()
{
  startMediaProcessing();
}

void AmSession::onSessionStart()
{
  startMediaProcessing();
}

void AmSession::onRtpTimeout()
{
  DBG("RTP timeout, stopping Session");
  dlg->bye();
  setStopped();
}

void AmSession::onSessionTimeout() {
  DBG("Session Timer: Timeout, ending session.");
  dlg->bye();
  setStopped();
}

void AmSession::updateRefreshMethod(const string& headers) {
  if (refresh_method == REFRESH_UPDATE_FB_REINV) {
    if (key_in_list(getHeader(headers, SIP_HDR_ALLOW),
		    SIP_METH_UPDATE)) {
      DBG("remote allows UPDATE, using UPDATE for session refresh.");
      refresh_method = REFRESH_UPDATE;
    }
  }
}

bool AmSession::refresh(int flags) {
  // no session refresh if not connected
  if (dlg->getStatus() != AmSipDialog::Connected)
    return false;

  if (refresh_method == REFRESH_UPDATE) {
    DBG("Refreshing session with UPDATE");
    return sendUpdate( NULL, "") == 0;
  } else {

    if (dlg->getUACInvTransPending()) {
      DBG("INVITE transaction pending - not refreshing now");
      return false;
    }

    DBG("Refreshing session with re-INVITE");
    return sendReinvite(true, "", flags) == 0;
  }
}

int AmSession::sendUpdate(const AmMimeBody* body,
			  const string &hdrs)
{
  return dlg->update(body, hdrs);
}

void AmSession::onInvite1xxRel(const AmSipReply &reply)
{
  // TODO: SDP
  if (dlg->prack(reply, NULL, /*headers*/"") < 0)
    ERROR("failed to send PRACK request in session '%s'.",sid4dbg().c_str());
}

void AmSession::onPrack2xx(const AmSipReply &reply)
{
  /* TODO: SDP */
}

string AmSession::sid4dbg()
{
  string dbg;
  dbg = dlg->getCallid() + "/" + dlg->getLocalTag() + "/" 
    + dlg->getRemoteTag() + "/" 
    + int2str(RTPStream()->getLocalPort()) + "/" 
    + RTPStream()->getRHost(RTP_TRANSPORT) + ":" + int2str(RTPStream()->getRPort(RTP_TRANSPORT));
  return dbg;
}

int AmSession::sendReinvite(bool updateSDP, const string& headers, int flags) 
{
  if(updateSDP){
    // Forces SDP offer/answer 
    AmMimeBody sdp;
    sdp.addPart(SIP_APPLICATION_SDP);
    return dlg->reinvite(headers, &sdp, flags);
  }
  else {
    return dlg->reinvite(headers, NULL, flags);
  }
}

int AmSession::sendInvite(const string& headers) 
{
  onOutgoingInvite(headers);

  // Forces SDP offer/answer
  AmMimeBody sdp;
  sdp.addPart(SIP_APPLICATION_SDP);
  return dlg->invite(headers, &sdp);
}

void AmSession::setOnHold(bool hold)
{
  lockAudio();
  bool old_hold = RTPStream()->getOnHold();
  RTPStream()->setOnHold(hold);
  if (hold != old_hold) 
    sendReinvite();
  unlockAudio();
}

void AmSession::onFailure()
{
  // switch (cause) {
  //   case FAIL_REL100_421:
  //   case FAIL_REL100_420:
  //     if (rpl) {
  //       dlg.cancel();
  //       if (dlg.getStatus() < AmSipDialog::Connected)
  //         setStopped();
  //     } else if (req) {
  //       if (cause == FAIL_REL100_421) {
  //         dlg.reply(*req, 421, SIP_REPLY_EXTENSION_REQUIRED, NULL,
  //             SIP_HDR_COLSP(SIP_HDR_REQUIRE) SIP_EXT_100REL CRLF);
  //       } else {
  //         dlg.reply(*req, 420, SIP_REPLY_BAD_EXTENSION, NULL,
  //             SIP_HDR_COLSP(SIP_HDR_UNSUPPORTED) SIP_EXT_100REL CRLF);
  //       }
  //       /* finally, stop session if running */
  //       if (dlg.getStatus() < AmSipDialog::Connected)
  //         setStopped();
  //     }
  //     break;
  //   default:
  //     break;
  // }
}


int AmSession::getRtpInterface()
{
  if(rtp_interface < 0){
    // TODO: get default media interface for signaling IF instead
    std::string media_interface = AmConfig.sip_ifs[dlg->getOutboundIf()].default_media_if;
    auto media_it = AmConfig.media_if_names.find(media_interface);
    if(media_it == AmConfig.media_if_names.end()) {
        return 0;
    }
    rtp_interface = media_it->second;
    if(rtp_interface < 0) {
      DBG("No media interface for signaling interface:");
      DBG("Using default media interface instead.");
      rtp_interface = 0;
    }
  }
  return rtp_interface;
}

void AmSession::setRtpInterface(int _rtp_interface) {
  DBG("setting media interface to %d", _rtp_interface);
  rtp_interface = _rtp_interface;
}

int AmSession::getRtpProtoId()
{
    if(rtp_proto_id < 0) {
        int rtp_if = getRtpInterface();
        int rtp_proto_id = AmConfig.media_ifs[rtp_if].findProto(
            dlg->getOutboundAddrType(), MEDIA_info::RTP);
        if(rtp_proto_id >= 0) {
            setRtpProtoId(rtp_proto_id);
        }
    }

    return rtp_proto_id;
}

int AmSession::setRtpProtoId(int _rtp_proto_id)
{
  DBG("setting media address of interface to %d", _rtp_proto_id);
  rtp_proto_id = _rtp_proto_id;
  return 0;
}

void AmSession::getMediaAcl(trsp_acl& acl)
{
    acl = media_acl;
}

void AmSession::setMediaAcl(const std::vector<AmSubnet>& networks)
{
    media_acl.set_action(trsp_acl::Drop);
    for(auto& network : networks)
        media_acl.add_network(network);
}

AddressType AmSession::getLocalMediaAddressType()
{
    // sets rtp_interface if not initialized
    getRtpInterface();
    getRtpProtoId();

    //assert(rtp_interface >= 0);
    if(rtp_interface < 0)
        throw string ("AmSession::localMediaIP: failed to resolve rtp interface index");
    assert((unsigned int)rtp_interface < AmConfig.media_ifs.size());

    if(rtp_proto_id < 0)
        throw string ("AmSession::localMediaIP: failed to resolve  rtp addr type");
    assert((unsigned int)rtp_proto_id < AmConfig.media_ifs[rtp_interface].proto_info.size());

    return AmConfig.media_ifs[rtp_interface].proto_info[rtp_proto_id]->type_ip;
}

bool AmSession::timersSupported() {
  WARN("this function is deprecated; application timers are always supported");
  return true;
}

bool AmSession::setTimer(int timer_id, double timeout) {
  if (timeout <= 0.005) {
    DBG("setting timer %d with immediate timeout - posting Event", timer_id);
    AmTimeoutEvent* ev = new AmTimeoutEvent(timer_id);
    postEvent(ev);
    return true;
  }

  DBG("setting timer %d with timeout %f", timer_id, timeout);
  AmAppTimer::instance()->setTimer(getLocalTag(), timer_id, timeout);

  return true;
}

bool AmSession::removeTimer(int timer_id) {

  DBG("removing timer %d", timer_id);
  AmAppTimer::instance()->removeTimer(getLocalTag(), timer_id);

  return true;
}

bool AmSession::removeTimers() {

  DBG("removing timers");
  AmAppTimer::instance()->removeTimers(getLocalTag());

  return true;
}

int AmSession::readStreams(unsigned long long ts, unsigned char *buffer) 
{ 
  int res = 0;
  lockAudio();

  AmRtpAudio *stream = RTPStream();
  unsigned int f_size = stream->getFrameSize();
  if (stream->checkInterval(ts)) {
    int got = stream->get(ts, buffer, stream->getSampleRate(), f_size);
    if (got < 0) res = -1;
    if (got > 0) {
      if (isDtmfDetectionEnabled())
        putDtmfAudio(buffer, got, ts);
      stream->feedInbandDetector(buffer, got, ts);
      if (input) res = input->put(ts, buffer, stream->getSampleRate(), got);
    }
  }
  
  unlockAudio();
  return res;
}

int AmSession::writeStreams(unsigned long long ts, unsigned char *buffer) 
{ 
  int res = 0;
  lockAudio();

  AmRtpAudio *stream = RTPStream();
  if (stream->sendIntReached()) { // FIXME: shouldn't depend on checkInterval call before!
    auto f_size = stream->getFrameSize();
    auto output_sample_rate = stream->getSampleRate();
    int got = 0;

    if(0==output_sample_rate) [[unlikely]] {
        unlockAudio();
        return 0;
    }

    if (output) {
        got = output->get(ts, buffer, output_sample_rate, f_size);
        if(got < 0) got = 0; //suppress errors
    }

    stream->processRtcpTimers(ts, stream->scaleSystemTS(ts));

    if (got < 0) res = -1;
    if (got > 0) {
        stream->applyPendingStereoRecorders(nullptr);
        res = stream->put(ts, buffer, output_sample_rate, got);
    } else {
        stream->put_on_idle(ts);
    }
  }

  unlockAudio();
  return res;

}

void AmSession::ping(unsigned long long ts)
{
    RTPStream()->ping(ts);
}

const char *AmSession::getProcessingStatusStr() const
{
    ProcessingStatus s = getProcessingStatus();
    if(s<0 || s>=SESSION_STATUS_MAX){
        return "Invalid";
    }
    return ProcessingStatusStr[s];
}

void AmSession::setRtpEndlessSymmetricRtp(bool endless)
{
    symmetric_rtp_endless = endless;
}

void AmSession::setRtpSymmetricCandidate(bool e)
{
    symmetric_candidate = e;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 2
 * End:
 */
