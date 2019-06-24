#include "AmAudioFileRecorderStereoRaw.h"
#include "AmLcConfig.h"
#include "rsr.h"

AmAudioFileRecorderStereoRaw::AmAudioFileRecorderStereoRaw(const string& id)
: AmAudioFileRecorder(RecorderStereoRaw, id)
{
    string filePath(AmConfig.rsr_path);
    filePath = "/" + id + ".rsr";
    fp = fopen(filePath.c_str(),"w+");
    if(!fp) {
        ERROR("could not create/overwrite file: %s",filePath.c_str());
        return;
    }
    fseek(fp,0L,SEEK_SET);
}

AmAudioFileRecorderStereoRaw::~AmAudioFileRecorderStereoRaw()
{
    if(!fp) return;

    for(auto& file : files) {
        chunk data;
        data.data.file.offset = file.second;
        data.header.type = DATA_META;
        data.header.size = file.first.size() + sizeof(file_metadata);
        fwrite(&data, 1, sizeof(data_chunk) + sizeof(file_metadata), fp);
        fwrite(file.first.c_str(), 1, file.first.size(), fp);
    }

    fflush(fp);
    fclose(fp);
}

int AmAudioFileRecorderStereoRaw::init(const string &path, const string &sync_ctx)
{
    sync_ctx_id = sync_ctx;
    return add_file(path);
}

int AmAudioFileRecorderStereoRaw::add_file(const string &path)
{
    unsigned long long ts = 0;
    for(auto& i : last_ts) {
        if(ts < i.second) {
            ts = i.second;
        }
    }

    files.emplace(path, ts);
    return 0;
}

void AmAudioFileRecorderStereoRaw::writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size, int input_sample_rate, int channel_id)
{
    last_ts[channel_id] = ts;
    if(!fp) return;

    chunk data;
    data.data.samples.channel_id = channel_id;
    data.data.samples.sample_rate = input_sample_rate;
    data.data.samples.ts = ts;
    data.header.type = DATA_SAMPLES;
    data.header.size = size + sizeof(samples_data);
    fwrite(&data, 1, sizeof(data_chunk) + sizeof(samples_data), fp);
    fwrite(samples, 1, size, fp);
}
