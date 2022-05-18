#include "AmAudioFileRecorderStereoWav.h"
#include "plug-in/wav/wav_hdr.h"

#define WAV_FILE_SAMPLERATE 8000

AmAudioFileRecorderStereoWav::wav_file_data::wav_file_data(const std::string& path)
: AmAudioFileRecorderStereo::file_data(path)
{
    audioFile = new AmAudioFile();
    if(audioFile->fpopen(path + "|Pcm16_2", AmAudioFile::Write, fp) < 0) {
        fp = 0;
        audioFile = 0;
    }
}

AmAudioFileRecorderStereoWav::wav_file_data::~wav_file_data()
{
    if(audioFile) {
        audioFile->close();
        fp = 0;
        delete audioFile;
        audioFile = 0;
    }
}

int AmAudioFileRecorderStereoWav::wav_file_data::put(unsigned char* out, unsigned char* lbuf, unsigned char* rbuf, size_t l)
{
    if(l*2 > OUT_BUF_SIZE) {
        ERROR("buffer was too small");
        return -1;
    }

    for(size_t i = 0, j = 0; i < l/2; i++, j+=2) {
        ((unsigned short*)out)[j] = ((unsigned short*)lbuf)[i];
        ((unsigned short*)out)[j+1] = ((unsigned short*)rbuf)[i];
    }
    audioFile->put(0,out,WAV_FILE_SAMPLERATE,l*2);
    return 0;
}

AmAudioFileRecorderStereoWav::AmAudioFileRecorderStereoWav(const string& id)
  : AmAudioFileRecorderStereo(StereoWavInternal, WAV_FILE_SAMPLERATE, id)
{ }

AmAudioFileRecorderStereoWav::~AmAudioFileRecorderStereoWav()
{ }

AmAudioFileRecorderStereo::file_data * AmAudioFileRecorderStereoWav::create_file_data(const std::string& path)
{
    return new wav_file_data(path);
}
