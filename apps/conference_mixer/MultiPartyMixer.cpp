#include <bits/stdc++.h>
#include "ConferenceChannel.h"
#include "ampi/MixerAPI.h"
#include "AmRtpStream.h"
#include "log.h"
#include "MultiPartyMixer.h"

#include <assert.h>
#include <math.h>

// PCM16 range: [-32767:32768]
#define MAX_LINEAR_SAMPLE 32737

// the internal delay of the mixer (between put and get)
#define MIXER_DELAY_MS 20

#define MAX_BUFFER_STATES 50 // 1 sec max @ 20ms


MultiPartyMixer::MultiPartyMixer(int64_t ext_id, unsigned backlog_id, unsigned neighbors, int sample_rate)
  : channels(), scaling_factor(16),
    ext_id(ext_id), backlog_id(backlog_id), neighbors(neighbors), current_sample_rate(0)
{
    DBG("%s neighbors_num %d sample_rate %d ext_id %ld bl_id %d", __func__, neighbors, sample_rate, ext_id, backlog_id);

    ext_resampling.resize(neighbors);

    for (int i=0; i<neighbors; ++i)
        ext_resampling[i].reset(new AmLibSamplerateResamplingState());
}


MultiPartyMixer::~MultiPartyMixer()
{
    DBG("%s", __func__);
}


void inline MultiPartyMixer::update_current_sample_rate()
{
    current_sample_rate = channels.size()
            ? std::max_element( channels.begin(),
                                channels.end(),
                                    [](const std::pair<int, ChannelData>&a, const std::pair<int, ChannelData>&b) -> bool
                                    { return a.second.samplerate < b.second.samplerate; })->second.samplerate
            : 0;
}


int MultiPartyMixer::addChannel(int sample_rate)
{
    int cur_channel_id = 0;

    const auto &rit = channels.rbegin();
    if (rit != channels.rend())
        cur_channel_id = rit->first + 1;

    channels.emplace(std::make_pair(cur_channel_id, ChannelData(sample_rate)));

    update_current_sample_rate();

    DBG("XXDebugMixerXX: added channel: #%i current_sample_rate=%d\n",
         cur_channel_id, current_sample_rate);

    return cur_channel_id;
}


void MultiPartyMixer::removeChannel(int channel_id)
{
    int before_sample_rate = GetCurrentSampleRate();

    channels.erase(channel_id);

    update_current_sample_rate();

    DBG("XXDebugMixerXX: removed channel: #%i current_sample_rate=%d\n",channel_id, current_sample_rate);

    if (before_sample_rate != GetCurrentSampleRate()) {
        ext_samples_sum.init = false;
        mixed_channel.init = false;

        for (auto &it : channels)
            it.second.samples.init = false;
    }
}


void MultiPartyMixer::PutExtChannelPacket(int neighbor_idx,
                                          unsigned long long system_ts,
                                          unsigned char* buffer,
                                          unsigned int   size)
{
    if(!size)
        return;

    /**
        #define SIZE_MIX_BUFFER   (1<<14)
        int samples[SIZE_MIX_BUFFER];

        SampleArrayInt  ext_samples_sum
    */

    unsigned samples = PCM16_B2S(size);

    assert(samples <= SIZE_MIX_BUFFER); /// ???

    unsigned long long put_ts = system_ts + (MIXER_DELAY_MS * WALLCLOCK_RATE / 1000);
    unsigned long long user_put_ts = put_ts * (GetCurrentSampleRate()/100) / (WALLCLOCK_RATE/100);

    ext_samples_sum.get(user_put_ts,tmp_buffer,samples);
    mix_add(tmp_buffer,tmp_buffer,(short*)buffer,samples);
    ext_samples_sum.put(user_put_ts,tmp_buffer,samples);
}


void MultiPartyMixer::PutChannelPacket(unsigned int   channel_id,
                                       unsigned long long system_ts,
                                       unsigned char* buffer,
                                       unsigned int   size)
{
    if(!size)
        return;

    unsigned samples = PCM16_B2S(size);

    assert(samples <= SIZE_MIX_BUFFER);

#if 0
    SampleArrayShort* channel = 0;
    if((channel = bstate->get_channel(channel_id)) != 0) {

        unsigned samples = PCM16_B2S(size);
        unsigned long long put_ts = system_ts + (MIXER_DELAY_MS * WALLCLOCK_RATE / 1000);
        unsigned long long user_put_ts = put_ts * (GetCurrentSampleRate()/100) / (WALLCLOCK_RATE/100);

        channel->put(user_put_ts,(short*)buffer,samples);

        bstate->mixed_channel->get(user_put_ts,tmp_buffer,samples);
        mix_add(tmp_buffer,tmp_buffer,(short*)buffer,samples);
        bstate->mixed_channel->put(user_put_ts,tmp_buffer,samples);
        bstate->last_ts = put_ts + (samples * (WALLCLOCK_RATE/100) / (GetCurrentSampleRate()/100));
    }
#endif
    unsigned long long put_ts = system_ts + (MIXER_DELAY_MS * WALLCLOCK_RATE / 1000);
    unsigned long long user_put_ts = put_ts * (GetCurrentSampleRate()/100) / (WALLCLOCK_RATE/100);

    //bstate->mixed_channel_ext->get(user_put_ts,tmp_buffer,samples);
    //mix_add(tmp_buffer,tmp_buffer,(short*)buffer,samples);
    //bstate->mixed_channel_ext->put(user_put_ts,tmp_buffer,samples);

    const auto &it = channels.find(channel_id);

    if (it != channels.end())
        it->second.samples.put(user_put_ts, (short*)buffer,samples);

    mixed_channel.get(user_put_ts,tmp_buffer,samples);
    mix_add(tmp_buffer,tmp_buffer,(short*)buffer,samples);
    mixed_channel.put(user_put_ts,tmp_buffer,samples);

}

void MultiPartyMixer::GetChannelPacket(unsigned int   channel_id,
                     unsigned long long system_ts,
                     unsigned char* buffer,
                     unsigned int&  size,
                     unsigned int&  output_sample_rate)
{
    if (!size)
        return;

    assert(size <= AUDIO_BUFFER_SIZE);

    output_sample_rate = GetCurrentSampleRate();

    unsigned int last_ts = system_ts + (PCM16_B2S(size) * (WALLCLOCK_RATE/100) / (GetCurrentSampleRate()/100));

    unsigned int samples = PCM16_B2S(size); // * (bstate->sample_rate/100) / (GetCurrentSampleRate()/100); => 1
    assert(samples <= PCM16_B2S(AUDIO_BUFFER_SIZE));

    unsigned long long cur_ts = system_ts * (output_sample_rate/100) / (WALLCLOCK_RATE/100);

    /** mix external channels */
    ext_samples_sum.get(cur_ts,(int*)buffer,samples);

    mixed_channel.get(cur_ts,tmp_buffer,samples);
    mix_add_int(tmp_buffer,tmp_buffer,(int*)buffer,samples);


    const auto &it = channels.find(channel_id);

    if (it != channels.end()) {
        it->second.samples.get(cur_ts,(short*)buffer,samples);
        mix_sub(tmp_buffer,tmp_buffer,(short*)buffer,samples);
    }

    /// TODO: remove echo
    //channel->get(cur_ts,(short*)buffer,samples);
    //mix_sub(tmp_buffer,tmp_buffer,(short*)buffer,samples);

    scale((short*)buffer,tmp_buffer,samples);

    size = PCM16_S2B(samples);


#if 0
    unsigned int last_ts = system_ts + (PCM16_B2S(size) * (WALLCLOCK_RATE/100) / (GetCurrentSampleRate()/100));
    std::deque<MxrBufferState>::iterator bstate = findBufferStateForReading(GetCurrentSampleRate(), last_ts);

    SampleArrayShort* channel = 0;
    if (bstate != buffer_state.end() && (channel = bstate->get_channel(channel_id)) != 0) {

        unsigned int samples = PCM16_B2S(size) * (bstate->sample_rate/100) / (GetCurrentSampleRate()/100);
        assert(samples <= PCM16_B2S(AUDIO_BUFFER_SIZE));

        unsigned long long cur_ts = system_ts * (bstate->sample_rate/100) / (WALLCLOCK_RATE/100);

        /** mix external channels */
        ext_samples_sum.get(cur_ts,(int*)buffer,samples);
        // bstate->mixed_channel_ext->get(cur_ts,(int*)buffer,samples);

        bstate->mixed_channel->get(cur_ts,tmp_buffer,samples);
        mix_add_int(tmp_buffer,tmp_buffer,(int*)buffer,samples);

        channel->get(cur_ts,(short*)buffer,samples);
        mix_sub(tmp_buffer,tmp_buffer,(short*)buffer,samples);

        scale((short*)buffer,tmp_buffer,samples);

        size = PCM16_S2B(samples);
        output_sample_rate = bstate->sample_rate;
    } else if (bstate != buffer_state.end()) {
        memset(buffer,0,size);
        output_sample_rate = GetCurrentSampleRate();
        DBG("XXDebugMixerXX: GetChannelPacket returned zeroes, ts=%u, last_ts=%u, output_sample_rate=%u", system_ts, last_ts, output_sample_rate);
    }

    cleanupBufferStates(last_ts);
#endif
}


int MultiPartyMixer::GetExtChannelPacket(unsigned long long system_ts,
                     unsigned char* buffer,
                     unsigned int&  output_sample_rate)
{
    unsigned int size = PCM16_S2B(WC_INC_MS*GetCurrentSampleRate()/1000);

    if (!size || size > AUDIO_BUFFER_SIZE)
        return 0;

    output_sample_rate = GetCurrentSampleRate();

    unsigned int last_ts = system_ts + (PCM16_B2S(size) * (WALLCLOCK_RATE/100) / (GetCurrentSampleRate()/100));

    unsigned int samples = PCM16_B2S(size); // * (bstate->sample_rate/100) / (GetCurrentSampleRate()/100);
    assert(samples <= PCM16_B2S(AUDIO_BUFFER_SIZE));

    unsigned long long cur_ts = system_ts * (output_sample_rate/100) / (WALLCLOCK_RATE/100);

    mixed_channel.get(cur_ts,tmp_buffer,samples);
    scale((short*)buffer,tmp_buffer,samples);

    return PCM16_S2B(samples);


#if 0
    // unsigned int last_ts = system_ts + (PCM16_B2S(size) * (WALLCLOCK_RATE/100) / (GetCurrentSampleRate()/100));
    //std::deque<MxrBufferState>::iterator bstate = findBufferStateForReading(GetCurrentSampleRate(), last_ts);

    //if (bstate != buffer_state.end() && bstate->sample_rate && bstate->mixed_channel) {



    unsigned int samples = PCM16_B2S(size) * (bstate->sample_rate/100) / (GetCurrentSampleRate()/100);
    assert(samples <= PCM16_B2S(AUDIO_BUFFER_SIZE));

    //fprintf(stderr,"S %d  bstate_rate %d  mixer_cur %d\n", samples, bstate->sample_rate, GetCurrentSampleRate());
    unsigned long long cur_ts = system_ts * (bstate->sample_rate/100) / (WALLCLOCK_RATE/100);

    // fprintf(stderr,"GET %d system_ts %ld last_ts %ld cur_ts %ld\n", samples,system_ts, last_ts, cur_ts );

    bstate->mixed_channel->get(cur_ts,tmp_buffer,samples);
    //bstate->mixed_channel->get(cur_ts,tmp_buffer,samples);
    scale((short*)buffer,tmp_buffer,samples);

    //bstate->mixed_channel_ext->get(cur_ts,(int*)buffer,samples);
    //bstate->mixed_channel_short_ext->get(cur_ts,(short*)buffer,samples);
    //scale((short*)buffer,(int*)buffer,samples);
    //scale((short*)buffer,tmp_buffer,samples);

    output_sample_rate = bstate->sample_rate;

    return PCM16_S2B(samples);
#endif
    return 0;
}

/*
int MultiPartyMixer::GetCurrentSampleRate()
{
  SampleRateSet::reverse_iterator sit = samplerates.rbegin();
  if (sit != samplerates.rend()) {
	return *sit;
  } else {
	return -1;
  }
}*/

// int   dest[size/2]
// int   src1[size/2]
// short src2[size/2]
//

void MultiPartyMixer::mix_add_int(int* dest,int* src1,int* src2,unsigned int size)
{
  int* end_dest = dest + size;

  while(dest != end_dest)
    *(dest++) = *(src1++) + *(src2++);
}


void MultiPartyMixer::mix_add(int* dest,int* src1,short* src2,unsigned int size)
{
  int* end_dest = dest + size;

  while(dest != end_dest)
    *(dest++) = *(src1++) + int(*(src2++));
}

void MultiPartyMixer::mix_sub(int* dest,int* src1,short* src2,unsigned int size)
{
  int* end_dest = dest + size;

  while(dest != end_dest)
    *(dest++) = *(src1++) - int(*(src2++));
}

void MultiPartyMixer::scale(short* buffer,int* tmp_buf,unsigned int size)
{
  short* end_dest = buffer + size;
    
  if(scaling_factor<64)
    scaling_factor++;
    
  while(buffer != end_dest){
	
    int s = (*tmp_buf * scaling_factor) >> 6;
    if(abs(s) > MAX_LINEAR_SAMPLE){
      scaling_factor = abs( (MAX_LINEAR_SAMPLE<<6) / (*tmp_buf) );
      if(s < 0)
	s = -MAX_LINEAR_SAMPLE;
      else
	s = MAX_LINEAR_SAMPLE;
    }
    *(buffer++) = short(s);
    tmp_buf++;
  }
}

#if 0
std::deque<MxrBufferState>::iterator MultiPartyMixer::findOrCreateBufferState(unsigned int sample_rate)
{
  for (std::deque<MxrBufferState>::iterator it = buffer_state.begin(); it != buffer_state.end(); it++) {
    if (it->sample_rate == sample_rate) {
      it->fix_channels(channelids);
      //DEBUG_MIXER_BUFFER_STATE(*it, "returned to PutChannelPacket");
      return it;
    }
  }

  DBG("XXDebugMixerXX: Creating buffer state (from PutChannelPacket)");
  buffer_state.push_back(MxrBufferState(sample_rate, channelids));
  std::deque<MxrBufferState>::reverse_iterator rit = buffer_state.rbegin();
  //DEBUG_MIXER_BUFFER_STATE(*((rit + 1).base()), "returned to PutChannelPacket");
  return (rit + 1).base();
}

std::deque<MxrBufferState>::iterator
MultiPartyMixer::findBufferStateForReading(unsigned int sample_rate,
					     unsigned long long last_ts)
{
  for (std::deque<MxrBufferState>::iterator it = buffer_state.begin();
       it != buffer_state.end(); it++) {

    if (sys_ts_less()(last_ts,it->last_ts) || (last_ts == it->last_ts)) {
      it->fix_channels(channelids);
      //DEBUG_MIXER_BUFFER_STATE(*it, "returned to PutChannelPacket");
      return it;
    }
  }

  if (buffer_state.size() < MAX_BUFFER_STATES) {
  DBG("XXDebugMixerXX: Creating buffer state (from GetChannelPacket)");
  buffer_state.push_back(MxrBufferState(sample_rate, channelids));
  } // else just reuse the last buffer - conference without a speaker
  std::deque<MxrBufferState>::reverse_iterator rit = buffer_state.rbegin();
  //DEBUG_MIXER_BUFFER_STATE(*((rit + 1).base()), "returned to PutChannelPacket");
  return (rit + 1).base();
}


void MultiPartyMixer::cleanupBufferStates(unsigned int last_ts)
{
  while (!buffer_state.empty() 
	 && (buffer_state.front().last_ts != 0 && buffer_state.front().last_ts < last_ts) 
	 && (unsigned int)GetCurrentSampleRate() != buffer_state.front().sample_rate) {

    //DEBUG_MIXER_BUFFER_STATE(buffer_state.front(), "freed in cleanupBufferStates");
    buffer_state.front().free_channels();
    buffer_state.pop_front();
  }
}


MxrBufferState::MxrBufferState(unsigned int sample_rate, std::set<int>& channelids)
  : sample_rate(sample_rate), last_ts(0), channels(), mixed_channel(NULL)
{
  for (std::set<int>::iterator it = channelids.begin(); it != channelids.end(); it++) {
    channels.insert(std::make_pair(*it,new SampleArrayShort()));
  }

  mixed_channel = new SampleArrayInt();
}


MxrBufferState::MxrBufferState(int num_channels, unsigned int sample_rate)
  : sample_rate(sample_rate), last_ts(0), channels(), mixed_channel(NULL)
{
    for (int i=0; i<num_channels; ++i)
        channels.insert(std::make_pair(i,new SampleArrayShort()));

    mixed_channel = new SampleArrayInt();
}


MxrBufferState::MxrBufferState(const MxrBufferState& other)
  : sample_rate(other.sample_rate), last_ts(other.last_ts), 
    channels(other.channels),
    mixed_channel(other.mixed_channel)
{}


MxrBufferState::~MxrBufferState()
{}


void MxrBufferState::add_channel(unsigned int channel_id)
{
  if (channels.find(channel_id) == channels.end())
    channels.insert(std::make_pair(channel_id,new SampleArrayShort()));
}

void MxrBufferState::remove_channel(unsigned int channel_id)
{
  ChannelMap::iterator channel_it = channels.find(channel_id);
  if (channel_it != channels.end()) {
    delete channel_it->second;
    channels.erase(channel_it);
  }
}

SampleArrayShort* MxrBufferState::get_channel(unsigned int channel_id)
{
  ChannelMap::iterator channel_it = channels.find(channel_id);
  if(channel_it == channels.end()){
    ERROR("XXMixerDebugXX: channel #%i does not exist\n",channel_id);
    return NULL;
  }

  return channel_it->second;
}

void MxrBufferState::fix_channels(std::set<int>& curchannelids)
{
  for (std::set<int>::iterator it = curchannelids.begin(); it != curchannelids.end(); it++) {
    if (channels.find(*it) == channels.end()) {
      DBG("XXMixerDebugXX: fixing channel #%d", *it);
      channels.insert(std::make_pair(*it,new SampleArrayShort()));
    }
  }
}

void MxrBufferState::free_channels()
{
  for (ChannelMap::iterator it = channels.begin(); it != channels.end(); it++) {
    if (it->second != NULL)
      delete it->second;
  }

  delete mixed_channel;
}
#endif
