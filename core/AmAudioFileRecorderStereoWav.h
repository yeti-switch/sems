#pragma once

#include "AmAudioFileRecorderStereo.h"
#include "AmAudioFile.h"

class AmAudioFileRecorderStereoWav : public AmAudioFileRecorderStereo {
  public:
  private:
    class wav_file_data : public AmAudioFileRecorderStereo::file_data {
        AmAudioFile *audioFile;

      public:
        wav_file_data(const string &path);
        ~wav_file_data();

        int put(unsigned char *out, unsigned char *lbuf, unsigned char *rbuf, size_t l);
    };

    file_data *create_file_data(const string &path);

  public:
    AmAudioFileRecorderStereoWav(const string &id);
    ~AmAudioFileRecorderStereoWav();
};
