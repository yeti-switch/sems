#include "AmStereoRecorderInfo.h"
#include "AmAudioFileRecorderStereo.h"

void StereoRecordersList::add(const string &recorder_id, int channel_id)
{
    for (const auto &i : *this) {
        if (i.recorder_id == recorder_id && i.channel_id == channel_id)
            return;
    }
    emplace_back(recorder_id, channel_id);
}

bool StereoRecordersList::del(const string &recorder_id, int channel_id)
{
    std::erase_if(*this, [&recorder_id, channel_id](const StereoRecorderInfo &r) -> bool {
        return r.recorder_id == recorder_id && r.channel_id == channel_id;
    });
    return !empty();
}

void StereoRecordersList::put(unsigned long long ts, const unsigned char *samples, size_t len, int input_sample_rate)
{
    for (const auto &i : *this) {
        AmAudioFileRecorderProcessor::instance_unsafe()->putEvent(
            new AudioRecorderStereoSamplesEvent(i.recorder_id, ts, samples, len, input_sample_rate, i.channel_id));
    }
}
