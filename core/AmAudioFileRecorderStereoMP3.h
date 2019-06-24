#pragma once

#include "AmAudioFileRecorderStereo.h"

#include <lame/lame.h>

class AmAudioFileRecorderStereoMP3
  : public AmAudioFileRecorderStereo
{
  public:

  private:
    class mp3_file_data : public AmAudioFileRecorderStereo::file_data {
        lame_global_flags* gfp;
      public:
        mp3_file_data(const string &path);
        ~mp3_file_data();

        int put(unsigned char *out, unsigned char *lbuf, unsigned char *rbuf, size_t l);
    };

    file_data* create_file_data(const string &path);

  public:
    AmAudioFileRecorderStereoMP3(const string& id);
    ~AmAudioFileRecorderStereoMP3();
};

