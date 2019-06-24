#include "AmAudioFileRecorderStereoMP3.h"
#include "AmEventDispatcher.h"
#include "AmSessionContainer.h"
#include "AmUtils.h"
#include "ampi/HttpClientAPI.h"

#include <cstdio>

#define MP3_FILE_SAMPLERATE 8000
#define MP3_FILE_BITRATE 16

#define MP3_FLUSH_BUFFER_SIZE 7200

void no_output(const char *, va_list )
{ }

AmAudioFileRecorderStereoMP3::mp3_file_data::mp3_file_data(const string &path)
  : AmAudioFileRecorderStereo::file_data(path)
{
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

    timeval tv;
    gettimeofday(&tv,NULL);
    id3tag_set_title(gfp,timeval2str(tv).c_str());
    id3tag_set_comment(gfp, "recorded call");

    int ret_code = lame_init_params(gfp);
    if(ret_code < 0) {
        free(gfp);
        throw AmAudioFileRecorderException("lame encoder init failed", ret_code);
    }

}

AmAudioFileRecorderStereoMP3::mp3_file_data::~mp3_file_data()
{ 
    int final_samples;
    unsigned char  mp3buffer[MP3_FLUSH_BUFFER_SIZE];

    if(!fp) return;

    if((final_samples = lame_encode_flush(gfp,mp3buffer, MP3_FLUSH_BUFFER_SIZE)) > 0) {
        DBG("MP3: flushing %d bytes from MP3 encoder", final_samples);
        fwrite(mp3buffer, 1, final_samples, fp);
    }
    lame_mp3_tags_fid(gfp,fp);
    free(gfp);
    fflush(fp);
}

int AmAudioFileRecorderStereoMP3::mp3_file_data::put(unsigned char *out,unsigned char *lbuf, unsigned char *rbuf, size_t l)
{
    //DBG("    %s(%p,%p,%ld)",FUNC_NAME,lbuf,rbuf,l);
    if(!fp)
        return -5;

    int ret =  lame_encode_buffer(
                  gfp,
                  (const short int *)lbuf,   // left channel
                  (const short int *)rbuf,   // right channel
                  l / 2 ,                    // no of samples (size is in bytes!)
                  out,
                  OUT_BUF_SIZE);

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
            ERROR("error %d on writing to file %s.",errno,path.c_str());
            free(gfp);
            close();
        }
    }

    return ret;
}

AmAudioFileRecorderStereoMP3::AmAudioFileRecorderStereoMP3(const string& id)
  : AmAudioFileRecorderStereo(StereoMP3Internal, MP3_FILE_SAMPLERATE, id)
{ }

AmAudioFileRecorderStereoMP3::~AmAudioFileRecorderStereoMP3()
{ }

AmAudioFileRecorderStereo::file_data* AmAudioFileRecorderStereoMP3::create_file_data(const string &path)
{
    return new mp3_file_data(path);
}

