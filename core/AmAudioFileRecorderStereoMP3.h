#pragma once

#include "AmAudioFileRecorder.h"

#include <lame/lame.h>

#define AudioRecorderChannelLeft 0
#define AudioRecorderChannelRight 1

struct AudioRecorderStereoSamplesEvent
  : AudioRecorderEvent
{
    unsigned long long ts;
    unsigned char data[AUDIO_BUFFER_SIZE];
    size_t data_size;
    int sample_rate;
    int channel_id;

     AudioRecorderStereoSamplesEvent(const string &recorder_id, unsigned long long  ts, const unsigned char *samples, size_t len, int input_sample_rate, int channel_id)
      : AudioRecorderEvent(recorder_id,putStereoSamples),
        ts(ts),
        data_size(len),
        sample_rate(input_sample_rate),
        channel_id(channel_id)
    {
        memcpy(data,samples,len);
    }
};

class AmAudioFileRecorderStereoMP3
  : public AmAudioFileRecorder
{
    class file_data {
        string path;
        FILE* fp;
        lame_global_flags* gfp;
      public:
        file_data(FILE* fp, lame_global_flags* gfp, const string &path);
        ~file_data();

        void close();
        bool operator ==(const string &new_path);
        int put(unsigned char *out, unsigned char *lbuf, unsigned char *rbuf, size_t l);
    };

    unsigned long long ts_l, ts_r;
    unsigned char samples_l[AUDIO_BUFFER_SIZE], samples_r[AUDIO_BUFFER_SIZE];
    unsigned char out[AUDIO_BUFFER_SIZE];
    size_t size_l, size_r;
    vector<file_data> files;

    //open file, init codec, push to vector
    int open(const string& filename);

    //put samples to the all opened files
    int put(unsigned char *lbuf, unsigned char *rbuf, size_t l);

  public:
    AmAudioFileRecorderStereoMP3();
    ~AmAudioFileRecorderStereoMP3();

    int init(const string &path);
    int add_file(const string &path);
    void writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size, int input_sample_rate, int channel_id);
};

#define RecorderPutStereoSamples(id,ts,buffer,size,rate,channel_id)\
    AmAudioFileRecorderProcessor::instance_unsafe()->putEvent(\
        new AudioRecorderStereoSamplesEvent(id,ts,buffer,size,rate,channel_id));

