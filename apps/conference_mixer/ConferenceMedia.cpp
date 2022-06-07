#include "AmThread.h"
#include "AmLcConfig.h"
#include "ConferenceChannel.h"
#include "ConferenceMedia.h"


ConferenceMedia::ConferenceMedia(Mixer *dispatcher, int num_cnt, int sd)
    : input_resampling_state(nullptr), tx_ring(sd, dispatcher->getNeighbors())
{
    /** calculate range for garbage collection in different threads */
    run_to = MAX_CHANNEL_CTX / AmConfig.media_proc_threads;
    run_from  = run_to * num_cnt;
    /** the last one takes rest */
    if (AmConfig.media_proc_threads == num_cnt + 1)
        run_to = MAX_CHANNEL_CTX - run_from;
    run_to += run_from;

    INFO("%d) gc %d-%d", num_cnt, run_from, run_to);
}


ConferenceMedia::~ConferenceMedia()
{
    INFO("%s", __func__);
}


/** call order:
    ConferenceChannel::put
    ConferenceMedia::readStreams
    ConferenceChannel::get
    ConferenceMedia::writeStreams
*/

/** II) step in media round: garbage collector for mixe r cannels
        ConferenceChannel::put
        ConferenceMedia::readStreams(this) */

int ConferenceMedia::readStreams(unsigned long long ts, unsigned char *buffer)
{
    return 0;
}

/**
 * we send out mixer data every media round
*/
/** IV) step in media round:
            ConferenceChannel::put,
            ConferenceMedia::readStreams
            ConferenceChannel::get
            ConferenceMedia::writeStreams (this)
*/
int ConferenceMedia::writeStreams(unsigned long long ts, unsigned char *buffer)
{
    return 0;
}


void ConferenceMedia::onMediaTailProcessingTerminated()
{
    AmMediaTailHandler::onMediaTailProcessingTerminated();

    dec_ref(this);
}


int ConferenceMedia::processMediaTail(unsigned long long ts)
{
    unsigned char buffer[AUDIO_BUFFER_SIZE];

    for (int i=run_from; i<run_to; ++i) {

        if (!test_bit(i, Mixer::backlog_map))
            continue;

        mixer_ptr mixer = get_backlog(i)->mixer;

        if (!mixer)
            continue;

        AmLock l(mixer->mpm_mut);

        unsigned output_sample_rate;

        int got = mixer->GetExtChannelPacket(ts, buffer, output_sample_rate);

        if (got > 0)
            tx_ring.put(ts, mixer->ext_id, output_sample_rate, buffer, got);
    }

    return 0;
}
