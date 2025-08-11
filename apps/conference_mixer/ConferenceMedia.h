#pragma once

#include "AmMediaProcessor.h"
#include "AmAudio.h"
#include "ampi/MixerAPI.h"
#include "Mixer.h"


class ConferenceMedia : public atomic_ref_cnt, public AmMediaSession, public AmMediaTailHandler {
    friend class AmMediaProcessor;
    friend class AmMediaProcessorThread;
    friend class ConferenceChannel;

    enum ResamplingImplementationType { LIBSAMPLERATE, INTERNAL_RESAMPLER, UNAVAILABLE };

    int run_from, run_to;
    /** Sample buffer. */
    DblBuffer                     samples;
    unique_ptr<AmResamplingState> input_resampling_state;

    TxRing tx_ring;

    unsigned int resample(AmResamplingState &rstate, unsigned char *buffer, unsigned int size, int input_sample_rate,
                          int output_sample_rate);
    unsigned int resampleInput(unsigned char *buffer, unsigned int s, int input_sample_rate, int output_sample_rate);

  protected:
    void onMediaTailProcessingTerminated() override;
    int  processMediaTail(unsigned long long ts) override;
    // Fake implement AmAudio's pure virtual methods
    // this avoids to copy the samples locally by implementing only get/put
    int read(unsigned int user_ts, unsigned int size) { return -1; }
    int write(unsigned int user_ts, unsigned int size) { return -1; }

  public:
    ConferenceMedia(Mixer *dispatcher, int num, int sd);
    ~ConferenceMedia();

    /* ----------------- media processing interface ------------------- */
    int readStreams(unsigned long long ts, unsigned char *buffer) override;
    int writeStreams(unsigned long long ts, unsigned char *buffer) override;

    void processDtmfEvents() override {}
    void clearAudio() override {}
    void clearRTPTimeout() override {}
    void onMediaProcessingTerminated() override { dec_ref(this); }
};
