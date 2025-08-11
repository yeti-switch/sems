#pragma once

#include "AmAudioFileRecorder.h"
#include <map>

using std::map;

class AmAudioFileRecorderStereoRaw : public AmAudioFileRecorder {
  public:
    AmAudioFileRecorderStereoRaw(const string &id);
    ~AmAudioFileRecorderStereoRaw();

  private:
    struct file_offsets {
        unsigned long long begin;
        unsigned long long end;
        bool               wait_for_initial_samples;
        file_offsets()
            : begin(0)
            , end(0)
            , wait_for_initial_samples(true)
        {
        }
    };

    map<string, file_offsets>              files;
    map<unsigned char, unsigned long long> last_ts;

    FILE *fp;
    int   max_sample_rate;
    bool  wait_for_initial_samples;

  protected:
    virtual int  init(const string &path, const string &sync_ctx) override;
    virtual int  add_file(const string &path) override;
    virtual void writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size, int input_sample_rate,
                                    int channel_id) override;
    virtual void setTag(unsigned int channel_id, unsigned int tag) override;
    virtual void markRecordStopped(const string &file_path) override;

    unsigned long long get_last_ts();
};
