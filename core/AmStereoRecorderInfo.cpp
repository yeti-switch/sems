#include "AmStereoRecorderInfo.h"
#include "AmAudioFileRecorderStereoMP3.h"

void StereoRecordersList::put(unsigned long long  ts, const unsigned char *samples, size_t len, int input_sample_rate)
{
    for(const auto &i : *this) {
        AmAudioFileRecorderProcessor::instance_unsafe()->putEvent(
            new AudioRecorderStereoSamplesEvent(
                i.recorder_id,ts,samples,len,input_sample_rate,i.channel_id)
        );
    }
}
