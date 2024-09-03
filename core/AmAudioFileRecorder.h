#pragma once

#include <singleton.h>
#include "AmEventFdQueue.h"
#include "AmAudio.h"

#include <queue>
#include <list>
#include <stdexcept>

class AmAudioFileRecorder {
  public:
    enum RecorderType {
        RecorderMonoAmAudioFile = 0,
        RecorderStereoMP3Internal,
        RecorderStereoWavInternal,
        RecorderStereoRaw,
        RecorderTypeMax,
    };

  private:
    RecorderType type;

  protected:
    string sync_ctx_id;
    string recorder_id;

  public:
    AmAudioFileRecorder(RecorderType type, const string& id)
      : type(type), recorder_id(id)
    {}
    virtual ~AmAudioFileRecorder() { }

    RecorderType getType() { return type; }

    virtual int init(const string &path, const string &sync_ctx) = 0;
    virtual int add_file(const string &path) = 0;

    virtual void writeSamples([[maybe_unused]] unsigned char *samples,
                              [[maybe_unused]] size_t size,
                              [[maybe_unused]] int input_sample_rate)
    {
        throw std::logic_error("not implemented");
    }

    virtual void writeStereoSamples([[maybe_unused]] unsigned long long ts,
                                    [[maybe_unused]] unsigned char *samples,
                                    [[maybe_unused]] size_t size,
                                    [[maybe_unused]] int input_sample_rate,
                                    [[maybe_unused]] int channel_id)
    {
        throw std::logic_error("not implemented");
    }

    virtual void setTag([[maybe_unused]] unsigned int channel_id,
                        [[maybe_unused]] unsigned int tag)
    {
        throw std::logic_error("not implemented");
    }

    virtual void markRecordStopped([[maybe_unused]] const string& file_path)
    {
        throw std::logic_error("not implemented");
    }
};

struct AudioRecorderEvent
{
    string recorder_id;

    enum event_type {
        addRecorder = 0,
        addStereoRecorder,
        delRecorder,
        delStereoRecorder,
        putSamples,
        putStereoSamples,
        markRecordStopped,
        setTag
    } event_id;

    AudioRecorderEvent(const string &recorder_id, event_type event_id)
      : recorder_id(recorder_id),
        event_id(event_id)
    {}
    virtual ~AudioRecorderEvent(){}

    enum recorder_class {
        RecorderClassMono,
        RecorderClassStereo
    };

    inline recorder_class getRecorderClassByEventId()
    {
        switch(event_id) {
        case addRecorder:
        case delRecorder:
        case putSamples:
            return RecorderClassMono;
        case addStereoRecorder:
        case delStereoRecorder:
        case putStereoSamples:
        case markRecordStopped:
        case setTag:
            return RecorderClassStereo;
        default:
            throw std::logic_error("unknown event type");
        }
    }
};

struct AudioRecorderCtlEvent
  : AudioRecorderEvent
{
    string file_path;
    string sync_ctx_id;
    AmAudioFileRecorder::RecorderType rtype;

    AudioRecorderCtlEvent(const string &recorder_id,event_type event_id)
      : AudioRecorderEvent(recorder_id,event_id),
        rtype(AmAudioFileRecorder::RecorderTypeMax)
    {}

    AudioRecorderCtlEvent(const string &recorder_id,
                          event_type event_id,
                          AmAudioFileRecorder::RecorderType rtype,
                          const string &file_path, const string sync_ctx_id)
      : AudioRecorderEvent(recorder_id,event_id),
        file_path(file_path), sync_ctx_id(sync_ctx_id),
        rtype(rtype)
    {}
};

struct AudioRecorderSetTagEvent
  : AudioRecorderEvent
{
    unsigned int channel_id;
    unsigned int tag;

    AudioRecorderSetTagEvent(const string &recorder_id, event_type event_id,
                             unsigned int channel_id, unsigned int tag)
      : AudioRecorderEvent(recorder_id, event_id),
        channel_id(channel_id), tag(tag)
    {}
};

class _AmAudioFileRecorderProcessor
    : public
        AmThread,
        AmEventHandler,
        AmEventFdQueue
{
    int epoll_fd;

    typedef std::list<AudioRecorderEvent *> AudioEventsQueue;
    typedef std::map<string, AmAudioFileRecorder *> RecordersMap;

    RecordersMap mono_recorders;
    RecordersMap stereo_recorders;

    AudioEventsQueue audio_events;
    AmEventFd audio_events_ready, stop_event;
    AmMutex audio_events_lock;
    AmCondition<bool> stopped;

    long long int recorders_opened,
                  recorders_closed;

    void processRecorderEvent(AudioRecorderEvent &ev);

  public:
    _AmAudioFileRecorderProcessor();
    ~_AmAudioFileRecorderProcessor();

    //AmThread
    void run();
    void on_stop();

    //AmEventHandler
    void process(AmEvent *ev);

    //ctl interface
    void addRecorder(const string &recorder_id,
                     const string &file_path,
                     const string sync_ctx_id = string());
    void removeRecorder(const string &recorder_id);
    void putEvent(AudioRecorderEvent *event);

    //rpc commands
    void getStats(AmArg &ret);
    
    //singleton function
    void dispose(){ stop(); }
};

typedef singleton<_AmAudioFileRecorderProcessor> AmAudioFileRecorderProcessor;
