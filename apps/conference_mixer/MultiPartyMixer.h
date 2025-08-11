#pragma once
#include <set>
#include <map>
#include <vector>

#include "AmThread.h"
#include "SampleArray.h"
#include "Rings.h"

#ifndef AUDIO_BUFFER_SIZE
#define AUDIO_BUFFER_SIZE (1 << 13) /* 8192  */
#endif

#if 0
struct MxrBufferState
{
    typedef std::map<int,SampleArrayShort*> ChannelMap;

    int             sample_rate;
    unsigned int    last_ts;
    ChannelMap      channels;
    SampleArrayInt  *mixed_channel;

    MxrBufferState(int num_channels, unsigned int sample_rate);
    MxrBufferState(unsigned int sample_rate, std::set<int>& channelids);
    MxrBufferState(const MxrBufferState& other);
    ~MxrBufferState();

    void add_channel(unsigned int channel_id);
    void remove_channel(unsigned int channel_id);
    SampleArrayShort* get_channel(unsigned int channel_id);
    void fix_channels(std::set<int>& curchannelids);
    void free_channels();
};
#endif

/**
 * \brief Mixer for one conference.
 *
 * MultiPartyMixer mixes the audio from all channels,
 * and returns the audio of all other channels.
 */
class MultiPartyMixer {
    /** per channel samples storage for echo suppression */
    struct ChannelData {
        int              samplerate;
        SampleArrayShort samples;
        ChannelData(int samplerate)
            : samplerate(samplerate)
            , samples()
        {
        }
    };

  public:
    using ext_resampling_state_ptr = std::unique_ptr<AmLibSamplerateResamplingState>;

  private:
    std::vector<ext_resampling_state_ptr> ext_resampling;

    typedef std::map<int, ChannelData> ChannelsMap;
    SampleArrayInt                     ext_samples_sum;
    SampleArrayInt                     mixed_channel;

    ChannelsMap channels;

    int current_sample_rate;

    int scaling_factor;
    int tmp_buffer[AUDIO_BUFFER_SIZE / 2];

    /*    std::deque<MxrBufferState>::iterator findOrCreateBufferState(unsigned int sample_rate);
        std::deque<MxrBufferState>::iterator findBufferStateForReading(unsigned int sample_rate,
                                                                       unsigned long long last_ts);*/
    void cleanupBufferStates(unsigned int last_ts);

    void update_current_sample_rate();
    void mix_add_int(int *dest, int *src1, int *src2, unsigned int size);
    void mix_add(int *dest, int *src1, short *src2, unsigned int size);
    void mix_sub(int *dest, int *src1, short *src2, unsigned int size);
    void scale(short *buffer, int *tmp_buf, unsigned int size);

  public:
    AmMutex            mpm_mut;
    unsigned long long last_ts;
    uint64_t           ext_id;
    unsigned           backlog_id, neighbors;

    MultiPartyMixer() = delete;
    MultiPartyMixer(int64_t ext_id, unsigned backlog_id, unsigned external_num, int sample_rate);

    ~MultiPartyMixer();

    int get_backlog_id() { return backlog_id; }

    const ext_resampling_state_ptr &get_ext_resampler(int neighbor_idx) { return ext_resampling[backlog_id]; }

    void addExternalChannels(int num, unsigned int sample_rate);

    int  addChannel(int sample_rate);
    void removeChannel(int channel_id);

    void PutChannelPacket(unsigned int channel_id, unsigned long long system_ts, unsigned char *buffer,
                          unsigned int size);

    void GetChannelPacket(unsigned int channel, unsigned long long system_ts, unsigned char *buffer, unsigned int &size,
                          unsigned int &output_sample_rate);


    void PutExtChannelPacket(int neighbor_idx, unsigned long long system_ts, unsigned char *buffer, unsigned int size);

    int GetExtChannelPacket(unsigned long long system_ts, unsigned char *buffer, unsigned int &output_sample_rate);

    int GetCurrentSampleRate() { return current_sample_rate; }
};
