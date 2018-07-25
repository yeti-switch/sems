#pragma once

#include "AmAudioFileRecorder.h"

struct AudioRecorderSamplesEvent
  : AudioRecorderEvent
{
    unsigned char data[AUDIO_BUFFER_SIZE];
    size_t data_size;
    int sample_rate;

    AudioRecorderSamplesEvent(const string &recorder_id, const unsigned char *samples, size_t len, int input_sample_rate)
      : AudioRecorderEvent(recorder_id,putSamples),
        data_size(len),
        sample_rate(input_sample_rate)
    {
        memcpy(data,samples,len);
    }
};

class AmAudioFileRecorderMono
  : public AmAudioFileRecorder
{
    vector<AmAudioFile *> files;

  public:
    AmAudioFileRecorderMono();
    ~AmAudioFileRecorderMono();

    int init(const string &path, const string &sync_ctx);
    int add_file(const string &path);
    void writeSamples(unsigned char *samples, size_t size, int input_sample_rate);
};

#define RecorderPutSamples(id,buffer,size,rate)\
    AmAudioFileRecorderProcessor::instance_unsafe()->putEvent(\
        new AudioRecorderSamplesEvent(id,buffer,size,rate));

