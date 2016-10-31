#include "AmAudioFileRecorder.h"
#include "AmEventDispatcher.h"

#define RECORDER_QUEUE_NAME "AmAudioFileRecorder"

AmAudioFileRecorder::AmAudioFileRecorder()
{ }

AmAudioFileRecorder::~AmAudioFileRecorder()
{
    for(vector<AmAudioFile *>::iterator it = files.begin();
        it!=files.end(); ++it)
    {
        delete *it;
    }
}

int AmAudioFileRecorder::init(const string &path)
{
    files.push_back(new AmAudioFile());
    return files.back()->open(path,AmAudioFile::Write);
}

int AmAudioFileRecorder::add_file(const string &path)
{
    for(vector<AmAudioFile *>::const_iterator it = files.begin();
        it!=files.end(); ++it)
    {
            if((*it)->getFileName()==path) {
                ERROR("attempt to add the same file to the recorder: %s",
                    path.c_str());
                return 1;
            }
    }
    AmAudioFile *f = new AmAudioFile();
    if(0!=f->open(path,AmAudioFile::Write)){
        ERROR("failed to open: %s", path.c_str());
        delete f;
        return 1;
    }
    files.push_back(f);
    DBG("recorder has %zd opened files",  files.size());
    return 0;
}

int AmAudioFileRecorder::writeSamples(unsigned char *samples, size_t size, int input_sample_rate)
{
    //DBG("%s %p %ld",FUNC_NAME,samples,size);
    for(vector<AmAudioFile *>::iterator it = files.begin();
        it!=files.end(); ++it)
    {
        (*it)->put(0,samples,input_sample_rate,size);
    }
    return 0;
}

/*int AmAudioFileRecorder::writeFrames(unsigned char *frames, size_t size, int src_codec_id)
{
    DBG("%s %p %ld %d",FUNC_NAME,frames,size,src_codec_id);
    return size;
}*/

_AmAudioFileRecorderProcessor::_AmAudioFileRecorderProcessor()
  : AmEventFdQueue(this),
    audio_events_ready(false),
    stopped(false),
    recorders_opened(0),
    recorders_closed(0)
{}

_AmAudioFileRecorderProcessor::~_AmAudioFileRecorderProcessor()
{
    close(epoll_fd);
}

#define EPOLL_MAX_EVENTS  2048

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
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int f = e.data.fd;

            if(f==queue_fd()){
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

    DBG("%ld recorders on stop",recorders.size());
    for(RecordersMap::iterator it = recorders.begin();
        it!=recorders.end(); ++it)
    {
        delete it->second;
    }
    recorders.clear();

    DBG("Audio recorder stopped");
    stopped.set(true);
}

void _AmAudioFileRecorderProcessor::on_stop()
{
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

void _AmAudioFileRecorderProcessor::addRecorder(const string &recorder_id,const string &file_path)
{
    putEvent(new AudioRecorderEvent(recorder_id,AudioRecorderEvent::addRecorder,file_path));
}

void _AmAudioFileRecorderProcessor::removeRecorder(const string &recorder_id)
{
    putEvent(new AudioRecorderEvent(recorder_id,AudioRecorderEvent::delRecorder));
}

void _AmAudioFileRecorderProcessor::putSamples(const string &recorder_id, const unsigned char *samples, size_t len, int input_sample_rate)
{
    putEvent(new AudioRecorderEvent(recorder_id,samples,len,input_sample_rate));
}

/*void _AmAudioFileRecorderProcessor::putFrames(const string &recorder_id, const unsigned char *frames, size_t len, int codec_id)
{
    putEvent(new AudioRecorderEvent(recorder_id,frames,len,codec_id));
}*/

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

    RecordersMap::iterator recorder_it = recorders.find(ev.recorder_id);
    if(recorder_it == recorders.end()) {
        if(ev.event_id==AudioRecorderEvent::addRecorder){
            DBG("add recorder %s",ev.recorder_id.c_str());
            recorder = new AmAudioFileRecorder();
            if(0!=recorder->init(ev.file_path)){
                ERROR("can't init recorder %s with path '%s'",
                      ev.recorder_id.c_str(),
                      ev.file_path.c_str());
                delete recorder;
                return;
            } else {
                DBG("recorder %s inited with file: %s",
                    ev.recorder_id.c_str(),
                    ev.file_path.c_str());
            }
            recorders[ev.recorder_id] = recorder;
            recorders_opened++;
        } else {
            /*DBG("event for not existent recorder %s. ignore it",
                ev.recorder_id.c_str());*/
        }
        return;
    }

    recorder = recorder_it->second;

    switch(ev.event_id){
    case AudioRecorderEvent::addRecorder:
        DBG("update recorder %s",ev.recorder_id.c_str());
        if(0!=recorder->add_file(ev.file_path)) {
            ERROR("failed to add file to the recorder %s with path '%s'",
                  ev.recorder_id.c_str(),
                  ev.file_path.c_str());
        } else {
            DBG("recorder %s updated with file: %s",
                ev.recorder_id.c_str(),
                ev.file_path.c_str());
        }
        break;
    case AudioRecorderEvent::putSamples:
        recorder->writeSamples(ev.data,ev.data_size,ev.sample_rate);
        break;
    /*case AudioRecorderEvent::putFrames:
        recorder->writeFrames(ev.data,ev.data_size,ev.codec_id);
        break;*/
    case AudioRecorderEvent::delRecorder:
        DBG("delete recorder %p with id: %s",
            recorder,recorder_it->first.c_str());
        delete recorder;
        recorders.erase(recorder_it);
        recorders_closed++;
        break;
    }
}

void _AmAudioFileRecorderProcessor::getStats(AmArg &ret)
{
    ret["active"] = recorders.size();
    ret["opened"] = recorders_opened;
    ret["closed"] = recorders_closed;
}

