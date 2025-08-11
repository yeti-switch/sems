#include "AmAudioFileRecorderStereo.h"
#include "AmSessionContainer.h"
#include "ampi/HttpClientAPI.h"

#define SCALE_TS(file_sp, system_ts) ((system_ts) * (file_sp / 100) / (WALLCLOCK_RATE / 100))
#define SCALED_DIFF(fsr, lts, rts)   (SCALE_TS(fsr, ((lts > rts) ? (lts - rts) : (rts - lts))))

#define MAX_TS_DIFF 160

AmAudioFileRecorderStereo::file_data::file_data(const std::string &path)
    : path(path)
    , fp(nullptr)
    , stopped(false)
{
    open();
}

AmAudioFileRecorderStereo::file_data::~file_data()
{
    close();
}

void AmAudioFileRecorderStereo::file_data::open()
{
    // open file
    fp = fopen(path.c_str(), "w+");
    if (!fp) {
        throw AmAudioFileRecorderException("could not create/overwrite file", errno);
    }
    fseek(fp, 0L, SEEK_SET);
}

void AmAudioFileRecorderStereo::file_data::close()
{
    if (!fp)
        return;
    fclose(fp);
    fp = nullptr;
}

bool AmAudioFileRecorderStereo::file_data::operator==(const string &new_path)
{
    return path == new_path;
}

AmAudioFileRecorderStereo::AmAudioFileRecorderStereo(StereoRecorderType type, unsigned int file_samplerate,
                                                     const string &id)
    : AmAudioFileRecorder(stereoRecorderTypeToRecorderType(type), id)
    , ts_l(0)
    , ts_r(0)
    , file_sp(file_samplerate)
{
}

AmAudioFileRecorderStereo::~AmAudioFileRecorderStereo()
{
    auto files_count = files.size();

    for (auto file : files)
        delete file;

    if (!sync_ctx_id.empty()) {
        if (!AmSessionContainer::instance()->postEvent(HTTP_EVENT_QUEUE,
                                                       new HttpTriggerSyncContext(sync_ctx_id, files_count)))
        {
            ERROR("AmAudioFileRecorderStereo: can't post HttpTriggerSyncContext event");
        }
    }
}

int AmAudioFileRecorderStereo::init(const string &path, const string &sync_ctx)
{
    sync_ctx_id = sync_ctx;
    return add_file(path);
}

int AmAudioFileRecorderStereo::add_file(const string &path)
{
    // DBG("    %s(%s)",FUNC_NAME,path.c_str());
    for (auto &f : files) {
        if (f == path) {
            ERROR("attempt to add the same file to the recorder: %s", path.c_str());
            return 1;
        }
    }

    try {
        files.push_back(create_file_data(path));
    } catch (const AmAudioFileRecorderException &ex) {
        ex.log();
        return -1;
    }

    return 0;
}

int AmAudioFileRecorderStereo::put(unsigned char *lbuf, unsigned char *rbuf, size_t l)
{
    // DBG("    %s(%p,%p,%ld)",FUNC_NAME,lbuf,rbuf,l);
    for (auto &f : files) {
        if (!f->is_stopped())
            f->put(out, lbuf, rbuf, l);
    }
    return 0;
}

#define match_buffers(lts, lsize, rts, rsize)                                                                          \
    (((lts == rts) || (SCALED_DIFF(file_sp, lts, rts) <= MAX_TS_DIFF)) ? ((lsize) < (rsize) ? (lsize) : (rsize)) : 0)

void AmAudioFileRecorderStereo::markRecordStopped(const string &file_path)
{
    int l = match_buffers(ts_l, size_l, ts_r, size_r);
    if (l) {
        put(samples_l, samples_r, l);
        ts_l = 0;
        ts_r = 0;
    }
    for (auto &f : files) {
        if (file_path.empty() || file_path == f->get_path())
            f->mark_stopped();
    }
}

unsigned int AmAudioFileRecorderStereo::resample(AmAudioFileRecorderStereo::ResamplingStatePtr &state,
                                                 unsigned char *samples, unsigned int size, int input_sample_rate)
{

    if (!state.get()) {
#ifdef USE_INTERNAL_RESAMPLER
        if (AmConfig.resampling_implementation_type == AmAudio::INTERNAL_RESAMPLER) {
            state.reset(new AmInternalResamplerState());
        } else
#endif
#ifdef USE_LIBSAMPLERATE
            if (AmConfig.resampling_implementation_type == AmAudio::LIBSAMPLERATE)
        {
            state.reset(new AmLibSamplerateResamplingState());
        } else
#endif
        {
            WARN("no available resamplers for MP3 stereo recorder. skip audio writing");
            return 0;
        }
    }
    return state->resample(samples, size, ((double)file_sp) / ((double)input_sample_rate));
}

#define clear_left()                                                                                                   \
    /*DBG("    clear_left()");*/                                                                                       \
    ts_l = 0;

#define clear_right()                                                                                                  \
    /*DBG("    clear_right()");*/                                                                                      \
    ts_r = 0;

#define save_left()                                                                                                    \
    /*DBG("    save_left()");*/                                                                                        \
    memcpy(samples_l, samples, size);                                                                                  \
    ts_l   = ts;                                                                                                       \
    size_l = size;

#define save_right()                                                                                                   \
    /*DBG("    save_right()");*/                                                                                       \
    memcpy(samples_r, samples, size);                                                                                  \
    ts_r   = ts;                                                                                                       \
    size_r = size;

#define zero_left()                                                                                                    \
    /*DBG("    zero_left()");*/                                                                                        \
    bzero(samples_l, size_r);                                                                                          \
    size_l = size_r;

#define zero_right()                                                                                                   \
    /*DBG("    zero_right()");*/                                                                                       \
    bzero(samples_r, size_l);                                                                                          \
    size_r = size_l;

#define put_buffers(_lbuf, _rbuf, _size)                                                                               \
    /*DBG("    put_buffers(" #_lbuf "," #_rbuf "," #_size ")");*/                                                      \
    put(_lbuf, _rbuf, _size);

void AmAudioFileRecorderStereo::writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size,
                                                   int input_sample_rate, int channel_id)
{
    size_t l;

    /*DBG("%s %llu %p %ld %d %d%c",FUNC_NAME,ts,samples,size, input_sample_rate,channel_id,
        channel_id ? 'R' : 'L');*/
    // DBG("    >>> %llu l%llu(%ld) r%llu(%ld)",ts,ts_l,size_l,ts_r,size_r);

    switch (channel_id) {
    case AudioRecorderChannelLeft:
        if ((unsigned int)input_sample_rate != file_sp) {
            size = resample(resampling_state_l, samples, size, input_sample_rate);
        }
        if (ts_r) {
            if (ts_l) { //+L +R nL
                l = match_buffers(ts, size, ts_r, size_r);
                if (l) {
                    put_buffers(samples, samples_r, l);
                    clear_left();
                    clear_right();
                } else {
                    save_left();
                }
            } else { //-L +R nL
                l = match_buffers(ts, size, ts_r, size_r);
                if (l) {
                    put_buffers(samples, samples_r, l);
                    clear_right();
                } else {
                    zero_left();
                    put_buffers(samples_l, samples_r, size_r);
                    save_left();
                    clear_right();
                }
            }
        } else {
            if (ts_l) { //+L -R, nL
                zero_right();
                put_buffers(samples_l, samples_r, size_l);
                save_left();
            } else { //-L -R, nL
                save_left();
            }
        }
        break;
    case AudioRecorderChannelRight:
        if ((unsigned int)input_sample_rate != file_sp) {
            size = resample(resampling_state_r, samples, size, input_sample_rate);
        }
        if (ts_r) {
            if (ts_l) { //+L +R nR
                l = match_buffers(ts_l, size_l, ts, size);
                if (l) {
                    put_buffers(samples_l, samples, l);
                    clear_left();
                    clear_right();
                } else {
                    save_right();
                }
            } else { //-L +R nR
                zero_left();
                put_buffers(samples_l, samples_r, size_r);
                save_right();
            }
        } else {
            if (ts_l) { //+L -R, nR
                l = match_buffers(ts, size, ts_l, size_l);
                if (l) {
                    put_buffers(samples_l, samples, l);
                    clear_left();
                } else {
                    zero_right();
                    put_buffers(samples_l, samples_r, size_l);
                    clear_left();
                    save_right();
                }
            } else { //-L -R, nR
                save_right();
            }
        }
        break;
    }

    // DBG("    <<< %llu l%llu(%ld) r%llu(%ld)",ts,ts_l,size_l,ts_r,size_r);
}

#undef match_buffers
#undef clear_left
#undef clear_right
#undef save_left
#undef save_right
#undef zero_left
#undef zero_right
#undef put_buffers
