#include "AmAudioFileRecorderStereoMP3.h"
#include "AmEventDispatcher.h"
#include "AmUtils.h"
#include "AmConfig.h"

#include <cstdio>

#define MP3_FILE_SAMPLERATE 8000
#define MP3_FILE_BITRATE 16

#define MP3_FLUSH_BUFFER_SIZE 7200


AmAudioFileRecorderStereoMP3::file_data::file_data(FILE* fp, lame_global_flags* gfp, const string &path)
  : fp(fp),
    gfp(gfp),
    path(path)
{ }

AmAudioFileRecorderStereoMP3::file_data::~file_data()
{ }

void AmAudioFileRecorderStereoMP3::file_data::close()
{
    int final_samples;
    unsigned char  mp3buffer[MP3_FLUSH_BUFFER_SIZE];

    if((final_samples = lame_encode_flush(gfp,mp3buffer, MP3_FLUSH_BUFFER_SIZE)) > 0) {
        //DBG("MP3: flushing %d bytes from MP3 encoder", final_samples);
        fwrite(mp3buffer, 1, final_samples, fp);
    }
    lame_mp3_tags_fid(gfp,fp);
    free(gfp);
    fclose(fp);
}

bool AmAudioFileRecorderStereoMP3::file_data::operator ==(const string &new_path)
{
    return path==new_path;
}

int AmAudioFileRecorderStereoMP3::file_data::put(unsigned char *out,unsigned char *lbuf, unsigned char *rbuf, size_t l)
{
    //DBG("    %s(%p,%p,%ld)",FUNC_NAME,lbuf,rbuf,l);

    int ret =  lame_encode_buffer(
                  gfp,
                  (const short int *)lbuf,   // left channel
                  (const short int *)rbuf,   // right channel
                  l / 2 ,                    // no of samples (size is in bytes!)
                  out,
                  MP3_OUT_BUF_SIZE);

    // 0 is valid: if not enough samples for an mp3
    //frame lame will not return anything
    switch(ret){
    case  0: /*DBG("lame_encode_buffer returned 0\n");*/ break;
    case -1: ERROR("mp3buf was too small\n"); break;
    case -2: ERROR("malloc() problem\n"); break;
    case -3: ERROR("lame_init_params() not called\n"); break;
    case -4: ERROR("psycho acoustic problems. uh!\n"); break;
    }

    if(ret > 0) {
        //write encoded frames
        fwrite(out,ret,1,fp);
        if(ferror(fp)) {
            ERROR("error writing to file %s",path.c_str());
        }
    }

    return ret;
}

AmAudioFileRecorderStereoMP3::AmAudioFileRecorderStereoMP3()
  : AmAudioFileRecorder(RecorderStereoMP3Internal),
    ts_l(0),
    ts_r(0)
{ }

AmAudioFileRecorderStereoMP3::~AmAudioFileRecorderStereoMP3()
{
    for(auto &f: files)
        f.close();
}

int AmAudioFileRecorderStereoMP3::init(const string &path)
{
    return add_file(path);
}

void no_output(const char *format, va_list ap)
{ }

int AmAudioFileRecorderStereoMP3::open(const string& filename)
{
    FILE* fp;
    lame_global_flags* gfp;
    timeval tv;

    //open file
    fp = fopen(filename.c_str(),"w+");
    if(!fp) {
        ERROR("could not create/overwrite file: %s",filename.c_str());
        return -1;
    }
    fseek(fp,0L,SEEK_SET);

    //init codec
    gfp = lame_init();

    lame_set_errorf(gfp, &no_output);
    lame_set_debugf(gfp, &no_output);
    lame_set_msgf(gfp, &no_output);

    lame_set_num_channels(gfp,2);
    lame_set_in_samplerate(gfp,MP3_FILE_SAMPLERATE);
    lame_set_brate(gfp,MP3_FILE_BITRATE);
    lame_set_mode(gfp,STEREO);
    lame_set_quality(gfp,2);   /* 2=high  5 = medium  7=low */

    id3tag_init(gfp);

    gettimeofday(&tv,NULL);
    id3tag_set_title(gfp,timeval2str(tv).c_str());
    id3tag_set_comment(gfp, "recorded call");

    int ret_code = lame_init_params(gfp);
    if(ret_code < 0) {
        ERROR("lame encoder init failed: return code is %d", ret_code);
        free(gfp);
        return -1;
    }

    files.emplace_back(fp,gfp,filename);

    return 0;
}

int AmAudioFileRecorderStereoMP3::add_file(const string &path)
{
    //DBG("    %s(%s)",FUNC_NAME,path.c_str());
    for(auto &f: files) {
        if(f==path) {
            ERROR("attempt to add the same file to the recorder: %s",
                  path.c_str());
            return 1;
        }
    }
    return open(path);
}

int AmAudioFileRecorderStereoMP3::put(unsigned char *lbuf, unsigned char *rbuf, size_t l)
{
    //DBG("    %s(%p,%p,%ld)",FUNC_NAME,lbuf,rbuf,l);
    for(auto &f: files) {
        f.put(out,lbuf,rbuf,l);
    }
    return 0;
}

inline unsigned int resample(
    AmAudioFileRecorderStereoMP3::ResamplingStatePtr &state,
    unsigned char *samples, unsigned int size,
    int input_sample_rate)
{
    if(!state.get()) {
#ifdef USE_INTERNAL_RESAMPLER
        if (AmConfig::ResamplingImplementationType == AmAudio::INTERNAL_RESAMPLER) {
            state.reset(new AmInternalResamplerState());
        } else
#endif
#ifdef USE_LIBSAMPLERATE
        if (AmConfig::ResamplingImplementationType == AmAudio::LIBSAMPLERATE) {
            state.reset(new AmLibSamplerateResamplingState());
        } else
#endif
        {
            WARN("no available resamplers for MP3 stereo recorder. skip audio writing");
            return 0;
        }
        DBG("resampler inited with %p",state.get());
    }
    return state->resample(
        samples, size,
        ((double)MP3_FILE_SAMPLERATE) / ((double)input_sample_rate));
}

#define match_buffers(lts,lsize,rts,rsize) \
(\
    lts==rts \
    ? ((lsize) < (rsize) ? (lsize) : (rsize)) \
    : 0 \
)

#define clear_left() \
    /*DBG("    clear_left()");*/\
    ts_l = 0;

#define clear_right() \
    /*DBG("    clear_right()");*/\
    ts_r = 0;

#define save_left() \
    /*DBG("    save_left()");*/\
    memcpy(samples_l,samples,size);\
    ts_l = ts; \
    size_l = size; \

#define save_right() \
    /*DBG("    save_right()");*/ \
    memcpy(samples_r,samples,size);\
    ts_r = ts;\
    size_r = size;\

#define zero_left() \
    /*DBG("    zero_left()");*/\
    bzero(samples_l,size_r);\
    size_l = size_r;

#define zero_right() \
    /*DBG("    zero_right()");*/\
    bzero(samples_r,size_l);\
    size_r = size_l;

#define put_buffers(_lbuf,_rbuf,_size) \
    /*DBG("    put_buffers(" #_lbuf "," #_rbuf "," #_size ")");*/\
    put(_lbuf,_rbuf,_size);

void AmAudioFileRecorderStereoMP3::writeStereoSamples(unsigned long long ts,
                                                      unsigned char *samples, size_t size,
                                                      int input_sample_rate, int channel_id)
{
    size_t l;

    /*DBG("%s %llu %p %ld %d %d%c",FUNC_NAME,ts,samples,size, input_sample_rate,channel_id,
        channel_id ? 'R' : 'L');*/
    //DBG("    >>> %llu l%llu(%ld) r%llu(%ld)",ts,ts_l,size_l,ts_r,size_r);

    switch(channel_id) {
    case AudioRecorderChannelLeft:
        if(input_sample_rate!=MP3_FILE_SAMPLERATE) {
            size = resample(resampling_state_l,
                            samples,size,
                            input_sample_rate);
        }
        if(ts_r) {
            if(ts_l) { //+L +R nL
                l = match_buffers(ts,size,ts_r,size_r);
                if(l) {
                    put_buffers(samples,samples_r,l);
                    clear_left();
                    clear_right();
                } else {
                    save_left();
                }
            } else { //-L +R nL
                l = match_buffers(ts,size,ts_r,size_r);
                if(l) {
                    put_buffers(samples,samples_r,l);
                    clear_right();
                } else {
                    zero_left();
                    put_buffers(samples_l,samples_r,size_r);
                    save_left();
                    clear_right();
                }
            }
        } else {
            if(ts_l) { //+L -R, nL
                zero_right();
                put_buffers(samples_l,samples_r,size_l);
                save_left();
            } else { //-L -R, nL
                save_left();
            }
        }
        break;
    case AudioRecorderChannelRight:
        if(input_sample_rate!=MP3_FILE_SAMPLERATE) {
            size = resample(resampling_state_r,
                            samples,size,
                            input_sample_rate);
        }
        if(ts_r) {
            if(ts_l) { //+L +R nR
                l = match_buffers(ts_l,size_l,ts,size);
                if(l) {
                    put_buffers(samples_l,samples,l);
                    clear_left();
                    clear_right();
                } else {
                    save_right();
                }
            } else { //-L +R nR
                zero_left();
                put_buffers(samples_l,samples_r,size_r);
                save_right();
            }
        } else {
            if(ts_l) { //+L -R, nR
                l = match_buffers(ts,size,ts_l,size_l);
                if(l) {
                    put_buffers(samples_l,samples,l);
                    clear_left();
                } else {
                    zero_right();
                    put_buffers(samples_l,samples_r,size_l);
                    clear_left();
                    save_right();
                }
            } else { //-L -R, nR
                save_right();
            }
        }
        break;
    }

    //DBG("    <<< %llu l%llu(%ld) r%llu(%ld)",ts,ts_l,size_l,ts_r,size_r);
}

#undef match_buffers
#undef clear_left
#undef clear_right
#undef save_left
#undef save_right
#undef zero_left
#undef zero_right
#undef put_buffers

