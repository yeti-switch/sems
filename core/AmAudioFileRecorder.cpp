#include "AmAudioFileRecorder.h"
#include "AmAudioFileRecorderMono.h"
#include "AmAudioFileRecorderStereoMP3.h"
#include "AmAudioFileRecorderStereoWav.h"
#include "AmAudioFileRecorderStereoRaw.h"
#include "AmEventDispatcher.h"

#define RECORDER_QUEUE_NAME "AmAudioFileRecorder"
#define EPOLL_MAX_EVENTS  2048

_AmAudioFileRecorderProcessor::_AmAudioFileRecorderProcessor()
  : AmEventFdQueue(this),
    audio_events_ready(false),
    stopped(false),
    recorders_opened(0),
    recorders_closed(0)
{
    //recorders.resize(AmAudioFileRecorder::RecorderTypeMax-1);
}

_AmAudioFileRecorderProcessor::~_AmAudioFileRecorderProcessor()
{
    close(epoll_fd);
}

void _AmAudioFileRecorderProcessor::run()
{
    int ret;
    bool running = true;
    struct epoll_event events[EPOLL_MAX_EVENTS];
    AudioRecorderEvent *rec_ev; (void)rec_ev;

    AudioEventsQueue audio_events_local;

    setThreadName("recorder");

    AmEventDispatcher::instance()->addEventQueue(RECORDER_QUEUE_NAME, this);

    if((epoll_fd = epoll_create(10)) == -1){
        ERROR("epoll_create call failed");
        throw std::string("epoll_create call failed");
    }

    epoll_link(epoll_fd);
    audio_events_ready.link(epoll_fd);
    stop_event.link(epoll_fd);

    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);
        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int f = e.data.fd;

            if(f== -queue_fd()){
                processEvents();
                clear_pending();
            } else if(f==audio_events_ready){
                audio_events_ready.read();

                audio_events_lock.lock();
                audio_events_local.swap(audio_events);
                audio_events_lock.unlock();

                //process queue
                while(!audio_events_local.empty()){
                    AudioRecorderEvent *rec_ev = audio_events_local.front();
                    processRecorderEvent(*rec_ev);
                    audio_events_local.pop_front();
                    delete rec_ev;
                }
            } else if(f==stop_event) {
                running = false;
                break;
            }
        }

    } while(running);

    AmEventDispatcher::instance()->delEventQueue(RECORDER_QUEUE_NAME);

    audio_events_lock.lock();
    DBG("%ld unprocessed events on stop",audio_events.size());
    for(AudioEventsQueue::iterator it = audio_events.begin();
        it!=audio_events.end();++it)
    {
        delete *it;
    }
    audio_events_lock.unlock();

    DBG("%ld mono recorders on stop",mono_recorders.size());
    for(auto r: mono_recorders)
        delete r.second;

    DBG("%ld stereo recorders on stop",stereo_recorders.size());
    for(auto r: stereo_recorders)
        delete r.second;

    DBG("Audio recorder stopped");
    stopped.set(true);
}

void _AmAudioFileRecorderProcessor::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void _AmAudioFileRecorderProcessor::process(AmEvent *ev)
{
    if (ev->event_id == E_SYSTEM) {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }
        return;
    }
}

void _AmAudioFileRecorderProcessor::addRecorder(
    const string &recorder_id,
    const string &file_path,
    const string sync_ctx_id)
{
    putEvent(new AudioRecorderCtlEvent(
        recorder_id,
        AudioRecorderEvent::addRecorder,
        AmAudioFileRecorder::RecorderMonoAmAudioFile,
        file_path,sync_ctx_id));
}

void _AmAudioFileRecorderProcessor::removeRecorder(const string &recorder_id)
{
    putEvent(new AudioRecorderCtlEvent(recorder_id,AudioRecorderEvent::delRecorder));
}

void _AmAudioFileRecorderProcessor::putEvent(AudioRecorderEvent *event)
{
    audio_events_lock.lock();
    audio_events.push_back(event);
    audio_events_lock.unlock();

    audio_events_ready.fire();
}

void _AmAudioFileRecorderProcessor::processRecorderEvent(AudioRecorderEvent &ev)
{
    AmAudioFileRecorder *recorder;
    AudioRecorderCtlEvent *ctl_event = nullptr;

    RecordersMap &r = ev.getRecorderClassByEventId()==AudioRecorderCtlEvent::RecorderClassMono ?
        mono_recorders : stereo_recorders;

    RecordersMap::iterator recorder_it = r.find(ev.recorder_id);
    if(recorder_it == r.end()) {
        if(ev.event_id == AudioRecorderEvent::addRecorder ||
           ev.event_id == AudioRecorderEvent::addStereoRecorder)
        {
            ctl_event = static_cast<AudioRecorderCtlEvent *>(&ev);
            auto rtype = ctl_event->rtype;

            DBG("add recorder %s with type: %d",ev.recorder_id.c_str(),rtype);

            if(rtype == AmAudioFileRecorder::RecorderMonoAmAudioFile)
                recorder = new AmAudioFileRecorderMono(ev.recorder_id);
            else if(rtype == AmAudioFileRecorder::RecorderStereoMP3Internal)
                recorder = new AmAudioFileRecorderStereoMP3(ev.recorder_id);
            else if(rtype == AmAudioFileRecorder::RecorderStereoWavInternal)
                recorder = new AmAudioFileRecorderStereoWav(ev.recorder_id);
            else if(rtype == AmAudioFileRecorder::RecorderStereoRaw)
                recorder = new AmAudioFileRecorderStereoRaw(ev.recorder_id);
            else {
                ERROR("unknown recorder type: %d",rtype);
                return;
            }

            if(0!=recorder->init(ctl_event->file_path,ctl_event->sync_ctx_id)) {
                ERROR("can't init recorder %s with path '%s'",
                      ev.recorder_id.c_str(),
                      ctl_event->file_path.c_str());
                delete recorder;
                return;
            }

            DBG("recorder %s inited with file: %s",
                ev.recorder_id.c_str(),
                ctl_event->file_path.c_str());

            r[ev.recorder_id] = recorder;
            recorders_opened++;
        }/*else {
            //non add event for not existent recorder. ignore it
        }*/
        return;
    }

    recorder = recorder_it->second;

    switch(ev.event_id) {
    //samples
    case AudioRecorderEvent::putSamples: {
        AudioRecorderSamplesEvent &samples_event = static_cast<AudioRecorderSamplesEvent &>(ev);
        recorder->writeSamples(samples_event.data,samples_event.data_size,
                               samples_event.sample_rate);
    } break;
    case AudioRecorderEvent::putStereoSamples: {
        AudioRecorderStereoSamplesEvent &samples_event = static_cast<AudioRecorderStereoSamplesEvent &>(ev);
        recorder->writeStereoSamples(samples_event.ts,samples_event.data,samples_event.data_size,
                                     samples_event.sample_rate,samples_event.channel_id);
    } break;
    //ctl
    case AudioRecorderEvent::addRecorder:
    case AudioRecorderEvent::addStereoRecorder:
        ctl_event = static_cast<AudioRecorderCtlEvent *>(&ev);
        DBG("update recorder %s",ev.recorder_id.c_str());
        if(0!=recorder->add_file(ctl_event->file_path)) {
            ERROR("failed to add file to the recorder %s with path '%s'",
                  ev.recorder_id.c_str(),
                  ctl_event->file_path.c_str());
        } else {
            DBG("recorder %s updated with file: %s",
                ev.recorder_id.c_str(),
                ctl_event->file_path.c_str());
        }
    break;
    case AudioRecorderEvent::delRecorder:
    case AudioRecorderEvent::delStereoRecorder:
        DBG("delete recorder %p with id: %s",
            recorder,recorder_it->first.c_str());
        delete recorder;
        r.erase(recorder_it);
        recorders_closed++;
    break;
    case AudioRecorderEvent::setTag: {
        const auto &tag_event = static_cast<AudioRecorderSetTagEvent&>(ev);
        DBG("tag recorder %p(%s) channel_id %u, tag %u",
            recorder, recorder_it->first.c_str(),
            tag_event.channel_id, tag_event.tag);
        recorder->setTag(tag_event.channel_id, tag_event.tag);
    } break;

    case AudioRecorderEvent::markRecordStopped:
        const auto &stop_event = static_cast<AudioRecorderMarkStoppedEvent&>(ev);
        DBG("mark recorder %p(%s) as stopped. file_path:'%s'",
            recorder, recorder_it->first.c_str(),
            stop_event.file_path.c_str()
        );
        recorder->markRecordStopped(stop_event.file_path);
    } //switch(ev.event_id)
}

void _AmAudioFileRecorderProcessor::getStats(AmArg &ret)
{
    ret["active_mono"] = mono_recorders.size();
    ret["active_stereo"] = stereo_recorders.size();
    ret["opened"] = recorders_opened;
    ret["closed"] = recorders_closed;
}

