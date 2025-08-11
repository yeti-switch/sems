#pragma once

#include "AmAudioFileRecorder.h"

#define AudioRecorderChannelLeft  0
#define AudioRecorderChannelRight 1

#define IN_BUF_SIZE  AUDIO_BUFFER_SIZE
#define OUT_BUF_SIZE AUDIO_BUFFER_SIZE

class AmAudioFileRecorderException {
  public:
    const std::string &reason;
    int                code;
    AmAudioFileRecorderException(const std::string &_reason, int _code)
        : reason(_reason)
        , code(_code)
    {
    }
    ~AmAudioFileRecorderException() {}

    void log() const { ERROR("stereo recorder error: reason - %s code is %d", reason.c_str(), code); }
};

struct AudioRecorderStereoSamplesEvent : AudioRecorderEvent {
    unsigned long long ts;
    unsigned char      data[AUDIO_BUFFER_SIZE];
    size_t             data_size;
    int                sample_rate;
    int                channel_id;

    AudioRecorderStereoSamplesEvent(const string &recorder_id, unsigned long long ts, const unsigned char *samples,
                                    size_t len, int input_sample_rate, int channel_id)
        : AudioRecorderEvent(recorder_id, putStereoSamples)
        , ts(ts)
        , data_size(len)
        , sample_rate(input_sample_rate)
        , channel_id(channel_id)
    {
        memcpy(data, samples, len);
    }
};

struct AudioRecorderMarkStoppedEvent : AudioRecorderEvent {
    string file_path;

    AudioRecorderMarkStoppedEvent(const string &recorder_id, const string &file_path = "")
        : AudioRecorderEvent(recorder_id, markRecordStopped)
        , file_path(file_path)
    {
    }
};

class AmAudioFileRecorderStereo : public AmAudioFileRecorder {
  public:
    typedef std::unique_ptr<AmResamplingState> ResamplingStatePtr;

    enum StereoRecorderType { StereoMP3Internal, StereoWavInternal };

    static RecorderType stereoRecorderTypeToRecorderType(StereoRecorderType type)
    {
        switch (type) {
        case StereoMP3Internal: return RecorderStereoMP3Internal;
        case StereoWavInternal: return RecorderStereoWavInternal;
        }
        return RecorderTypeMax;
    }

    AmAudioFileRecorderStereo(StereoRecorderType type, unsigned int file_samplerate, const string &id);
    virtual ~AmAudioFileRecorderStereo();

  protected:
    class file_data {
      protected:
        string path;
        FILE  *fp;
        bool   stopped;

        void open();
        void close();

      public:
        file_data(const string &path);
        virtual ~file_data();

        virtual int put(unsigned char *out, unsigned char *lbuf, unsigned char *rbuf, size_t l) = 0;

        string get_path() { return path; }
        void   mark_stopped() { stopped = true; }
        bool   is_stopped() { return stopped; }

        bool operator==(const string &new_path);
    };

    unsigned long long ts_l, ts_r;

    unsigned char samples_l[IN_BUF_SIZE], samples_r[IN_BUF_SIZE];
    unsigned char out[OUT_BUF_SIZE];
    size_t        size_l, size_r;

    ResamplingStatePtr resampling_state_l, resampling_state_r;

    vector<file_data *> files;
    unsigned int        file_sp;

    virtual file_data *create_file_data(const string &path) = 0;

  public:
    int  init(const string &path, const string &sync_ctx) override;
    int  add_file(const string &path) override;
    void markRecordStopped(const string &file_path) override;
    void writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size, int input_sample_rate,
                            int channel_id) override;

    int put(unsigned char *lbuf, unsigned char *rbuf, size_t l);

  private:
    unsigned int resample(ResamplingStatePtr &state, unsigned char *samples, unsigned int size, int input_sample_rate);
};
