#include "Mixer.h"
#include "ConferenceChannel.h"

#if 0
#define ALSA_PCM_NEW_HW_PARAMS_API
#include <alsa/asoundlib.h>
#define PCM_DEVICE "default"
static snd_pcm_t *init_hw(unsigned int samplerate, int fr)
{
    snd_pcm_t *pcm_handle;
    snd_pcm_hw_params_t *params;
    snd_pcm_uframes_t frames = fr;
    int dir;

    fprintf(stderr,"Try init ALSA to samplerate %d frames %ld\n", samplerate, frames);

    /* Open the PCM device in playback mode */
    snd_pcm_open(&pcm_handle, PCM_DEVICE, SND_PCM_STREAM_PLAYBACK, 0);

    snd_pcm_hw_params_alloca(&params);
    snd_pcm_hw_params_any(pcm_handle, params);

    snd_pcm_hw_params_set_access(pcm_handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_hw_params_set_format(pcm_handle, params, SND_PCM_FORMAT_S16_LE);
    snd_pcm_hw_params_set_channels(pcm_handle, params, 1);
    snd_pcm_hw_params_set_rate_near(pcm_handle, params, &samplerate, &dir);
    snd_pcm_hw_params_set_period_size_near(pcm_handle, params, &frames, &dir);

    int rc = snd_pcm_hw_params(pcm_handle, params);
    if (rc < 0) {
        fprintf(stderr, "unable to set hw parameters: %s\n", snd_strerror(rc));
        throw string("unable to set hw parameters");
    }

    /* Allocate buffer to hold single period */
    snd_pcm_hw_params_get_period_size(params, &frames, &dir);

    fprintf(stderr,"# frames in a period: %ld\n", frames);
    return pcm_handle;
}
#endif


ConferenceChannel::ConferenceChannel(int mpmixer_ch_id, int64_t ext_id, mixer_ptr mpmixer)
    : ext_id(ext_id), mpmixer_ch_id(mpmixer_ch_id), mpmixer(mpmixer)
{}


void ConferenceChannel::put_external(int neighbor_idx,
                                     unsigned long long ts,
                                     unsigned char *buffer,
                                     int sample_rate,
                                     int size)
{
    // fprintf(stderr,"%s #%d rate %d size %d\n", __func__, neighbor_num, sample_rate, size);
    int current_sample_rate = mpmixer->GetCurrentSampleRate();

    if (current_sample_rate == sample_rate)
        mpmixer->PutExtChannelPacket(neighbor_idx, ts, buffer, size);
    else {

        const MultiPartyMixer::ext_resampling_state_ptr
                &resampler  = mpmixer->get_ext_resampler(neighbor_idx);

        memcpy((unsigned char*)samples, buffer, size);
         // size = resampleInput(samples, size, sample_rate, current_sample_rate);
        size = resampler->resample(samples, size, ((double) current_sample_rate) / ((double) sample_rate ));
        mpmixer->PutExtChannelPacket(neighbor_idx, ts, (unsigned char*)samples, size);
    }
}


#if 0
/**  backlog logic, receive side */
void ConferenceChannel::run_backlog(unsigned long long ts, unsigned char* buffer)
{
    // todo: need boundary check
    unsigned char buf[AUDIO_BUFFER_SIZE*2];

    struct backlog *bl = get_backlog(mpmixer->backlog_id);

    for (int i=0; i<getNeighbors_num(); ++i) {

#if 1
        RingFrame       *frames[4];

        int  got = get_frames_from_backlog(bl->status, i, frames);

        if (!got)
            continue;

        int length       = 0;
        int samplerate   = 0;

        for (int j=0; j<4; ++j) {
            RingFrame *fr = frames[j];

            if (!fr)
                continue;

            MixerFrameHdr *h = (MixerFrameHdr *)fr->data;

            samplerate = h->sample_rate;

            memcpy(&buf[length], fr->data+sizeof(MixerFrameHdr), h->length);
            length +=h->length;
        }

        if (samplerate && length)
            put_external(i, ts, buf, samplerate, length);


#else
        RingFrame   *frame = get_frame_from_backlog(bl->status, i);

        if (!frame)
            continue;

        MixerFrameHdr* h = (MixerFrameHdr *)frame->data;
        int length       = h->length;
        int samplerate   = h->sample_rate;

        if (samplerate && length)
            put_external(i, ts, frame->data+sizeof(MixerFrameHdr), samplerate, length);
#endif
    }

}
#endif


/** todo: need boundary check
 * Линеаризуем буфера из backlog раздельно по каждому neighbor
 * контроль изменения sample_rate при линеаризации -
 *  игнорируем кадры с изменившимся sample_rate...
*/
void ConferenceChannel::run_backlog(unsigned long long ts, unsigned char* buffer)
{
    struct NeighborData {
        int             length;
        int             sample_rate;
        unsigned char   buf[AUDIO_BUFFER_SIZE * MIXER_BACKLOG_SIZE];
    };

    int neighbors_num = getNeighbors_num();
    if(!neighbors_num) {
        //ERROR("incorrect configuration or anything else: neighbors_num = 0");
        return;
    }

    NeighborData   data[neighbors_num];

    for (int i=0; i< neighbors_num; ++i)
        data[i].length = data[i].sample_rate = 0;

    struct backlog *bl = get_backlog(mpmixer->backlog_id);

    while (bl->start.get() != bl->end.get()) {
        unsigned last = (bl->start.get() + 1) & MIXER_BACKLOG_MASK;

        RxFrame         &fr = bl->frame[last];
        MixerFrameHdr   *h = fr.hdr;
        NeighborData    *d = &data[fr.neighbor_id];

        // fprintf(stderr,"BL) #%d length=%d idx=%d\n", last, h->length, fr.neighbor_id);

        /// ignore frames with new sample rate
        if (!d->sample_rate || d->sample_rate == h->sample_rate) {

            memcpy(&d->buf[d->length], fr.data + sizeof(MixerFrameHdr), h->length);

            d->sample_rate = h->sample_rate;
            d->length += h->length;
        }

        bl->start.set(last);
    }

    for (int i=0; i< neighbors_num; ++i)
        if (data[i].length && data[i].sample_rate)
            put_external(i, ts, data[i].buf, data[i].sample_rate, data[i].length);
}


/** I) step in media round:
        ConferenceChannel::put (this) */
int ConferenceChannel::put(unsigned long long system_ts, unsigned char* buffer,
                           int input_sample_rate, unsigned int size)
{
    AmLock l(mpmixer->mpm_mut);

    /// run_backlog every new media round
    mpmixer->last_ts = system_ts;

    run_backlog(system_ts, buffer);

    if(stereo_record_enabled) {
      stereo_recorders.put(system_ts,buffer,size,input_sample_rate);
    }

    int samplerate = mpmixer->GetCurrentSampleRate();

    if (input_sample_rate != samplerate)  {
        // is it necessary memcpy() for resample hire, can we resample buffer ???
        memcpy((unsigned char*)samples,buffer,size);
        size = resampleInput(samples, size, input_sample_rate, samplerate);
        mpmixer->PutChannelPacket(mpmixer_ch_id, system_ts, (unsigned char*)samples, size);
    } else
        mpmixer->PutChannelPacket(mpmixer_ch_id,system_ts, buffer,size);

    return size;
}


/** III) step in media round:
        ConferenceChannel::put,
        ConferenceMedia::readStreams
        ConferenceChannel::get (this) */
int ConferenceChannel::get(unsigned long long system_ts, unsigned char* buffer,
                           int output_sample_rate, unsigned int nb_samples)
{
    if (!nb_samples || !output_sample_rate)
        return 0;

    AmLock l(mpmixer->mpm_mut);

    unsigned int size = output_sample_rate
            ? PCM16_S2B(nb_samples * mpmixer->GetCurrentSampleRate() / output_sample_rate)
            : 0;
    unsigned int mixer_sample_rate = 0;

    mpmixer->GetChannelPacket(mpmixer_ch_id, system_ts, buffer, size, mixer_sample_rate);
    
    if (mixer_sample_rate != static_cast<typeof mixer_sample_rate>(output_sample_rate))
        size = resampleOutput(buffer, size, mixer_sample_rate, output_sample_rate);

    return size;
}
