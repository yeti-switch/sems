#pragma once

#include <singleton.h>
#include "AmEventFdQueue.h"
#include "AmAudio.h"
#include "AmAudioFile.h"

#include <queue>
#include <list>

class AmAudioFileRecorder {
  public:
    enum RecorderType {
        RecorderMonoAmAudioFile = 0,
        RecorderStereoMP3Internal,
        RecorderTypeMax,
    };
  private:
    RecorderType type;
  public:
    AmAudioFileRecorder(RecorderType type)
      : type(type)
    {}
    virtual ~AmAudioFileRecorder() { }

    RecorderType getType() { return type; }

    virtual int init(const string &path) = 0;
    virtual int add_file(const string &path) = 0;

    virtual void writeSamples(unsigned char *samples, size_t size, int input_sample_rate)
    {
        throw std::logic_error("not implemented");
    }
    virtual void writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size, int input_sample_rate, int channel_id)
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
        putStereoSamples
    } event_id;

    AudioRecorderEvent(const string &recorder_id, event_type event_id)
      : recorder_id(recorder_id),
        event_id(event_id)
    {}

    inline AmAudioFileRecorder::RecorderType getRecorderType()
    {
        switch(event_id) {
        case addRecorder:
        case delRecorder:
        case putSamples:
            return AmAudioFileRecorder::RecorderMonoAmAudioFile;
        case addStereoRecorder:
        case delStereoRecorder:
        case putStereoSamples:
            return AmAudioFileRecorder::RecorderStereoMP3Internal;
        default:
            throw std::logic_error("unknown event type");
        }
    }
};

struct AudioRecorderCtlEvent
  : AudioRecorderEvent
{
    string file_path;

    AudioRecorderCtlEvent(const string &recorder_id,event_type event_id)
      : AudioRecorderEvent(recorder_id,event_id)
    {}

    AudioRecorderCtlEvent(const string &recorder_id,event_type event_id, const string &file_path)
      : AudioRecorderEvent(recorder_id,event_id),
        file_path(file_path)
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

    RecordersMap recorders[AmAudioFileRecorder::RecorderTypeMax];
    //vector<RecordersMap> recorders;

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
    void addRecorder(const string &recorder_id, const string &file_path);
    void removeRecorder(const string &recorder_id);
    void putEvent(AudioRecorderEvent *event);

    //rpc commands
    void getStats(AmArg &ret);
};

typedef singleton<_AmAudioFileRecorderProcessor> AmAudioFileRecorderProcessor;
