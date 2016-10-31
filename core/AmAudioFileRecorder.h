#pragma once

#include <singleton.h>
#include "AmEventFdQueue.h"
#include "AmAudio.h"
#include "AmAudioFile.h"

#include <queue>
#include <list>

struct AudioRecorderEvent {
    string recorder_id;
    string file_path;

    enum event_type {
        addRecorder,
        delRecorder,
        putSamples/*,
        putFrames*/
    } event_id;

    unsigned char data[AUDIO_BUFFER_SIZE];
    size_t data_size;
    int sample_rate;

    int codec_id;

    AudioRecorderEvent(const string &recorder_id,event_type event_id)
      : recorder_id(recorder_id),
        event_id(event_id)
    {}

    AudioRecorderEvent(const string &recorder_id,event_type event_id, const string &file_path)
      : recorder_id(recorder_id),
        event_id(event_id),
        file_path(file_path)
    {}

    AudioRecorderEvent(const string &recorder_id, const unsigned char *samples, size_t len, int input_sample_rate)
      : recorder_id(recorder_id),
        event_id(putSamples),
        data_size(len),
        sample_rate(input_sample_rate)
    {
        memcpy(data,samples,len);
    }

    /*AudioRecorderEvent(const string &recorder_id, const unsigned char *frames, size_t len, int codec_id)
      : recorder_id(recorder_id),
        event_id(putFrames),
        data_size(len),
        sample_rate(input_sample_rate),
        codec_id(codec_id)
    {
        memcpy(data,frames,len);
    }*/
};

class AmAudioFileRecorder {
    vector<AmAudioFile *> files;
    //unsigned char buf[AUDIO_BUFFER_SIZE]; //for internal decoding

  public:
    AmAudioFileRecorder();
    ~AmAudioFileRecorder();
    int init(const string &path);
    int add_file(const string &path);
    int writeSamples(unsigned char *samples, size_t size, int input_sample_rate);
    //int writeFrames(unsigned char *frames, size_t size, int src_codec_id);
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

    RecordersMap recorders;

    AudioEventsQueue audio_events;
    AmEventFd audio_events_ready, stop_event;
    AmMutex audio_events_lock;
    AmCondition<bool> stopped;

    long long int recorders_opened,
                  recorders_closed;

    void processRecorderEvent(AudioRecorderEvent &ev);
    void putEvent(AudioRecorderEvent *event);

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
    void putSamples(const string &recorder_id, const unsigned char *samples, size_t len, int input_sample_rate);
    //void putFrames(const string &recorder_id, const unsigned char *frames, size_t len, int codec_id);

    //rpc commands
    void getStats(AmArg &ret);
};

#define RecorderPutSamples(id,buffer,size,rate)\
    AmAudioFileRecorderProcessor::instance_unsafe()->putSamples(\
        recorder_id, buffer, size, rate);

typedef singleton<_AmAudioFileRecorderProcessor> AmAudioFileRecorderProcessor;
