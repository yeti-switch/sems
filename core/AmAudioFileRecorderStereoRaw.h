#ifndef _AM_AUDIO_FILE_RECORDER_RAW_H_
#define _AM_AUDIO_FILE_RECORDER_RAW_H_

#include "AmAudioFileRecorder.h"
#include <map>

using std::map;

class AmAudioFileRecorderStereoRaw : public AmAudioFileRecorder
{
public:
    AmAudioFileRecorderStereoRaw(const string& id);
    ~AmAudioFileRecorderStereoRaw();
private:
    map<string, unsigned long long> files;
    map<unsigned char, unsigned long long> last_ts;
    FILE* fp;
protected:
    virtual int init(const string &path, const string &sync_ctx);
    virtual int add_file(const string &path);
    virtual void writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size, int input_sample_rate, int channel_id);
};

#endif/*_AM_AUDIO_FILE_RECORDER_RAW_H_*/
