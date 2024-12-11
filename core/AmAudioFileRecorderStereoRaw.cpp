#include "AmAudioFileRecorderStereoRaw.h"
#include "AmLcConfig.h"
#include "rsr.h"
#include "AmSessionContainer.h"
#include "ampi/HttpClientAPI.h"
#include <filesystem>

using namespace RSR;

AmAudioFileRecorderStereoRaw::AmAudioFileRecorderStereoRaw(const string& id)
  : AmAudioFileRecorder(RecorderStereoRaw, id),
    fp(nullptr),
    max_sample_rate(0),
    wait_for_initial_samples(false)
{}

AmAudioFileRecorderStereoRaw::~AmAudioFileRecorderStereoRaw()
{
    struct timeval tm;
    long int meta_offset;
    chunk data;

    if(!fp) return;

    meta_offset = static_cast<int>(ftell(fp));

    for(auto& file : files) {
        DBG("~AmAudioFileRecorderStereoRaw(): file %s, offsets %llu-%llu",
            file.first.c_str(), file.second.begin, file.second.end);

        data.header.type = DATA_META_V2;
        data.data.file_v2.offset = file.second.begin;
        data.data.file_v2.offset_end =
            file.second.end ? file.second.end : get_last_ts();

        data.header.size = static_cast<unsigned int >(
            file.first.size() + sizeof(file_metadata_v2));
        fwrite(&data, 1, sizeof(data_chunk) + sizeof(file_metadata_v2), fp);
        fwrite(file.first.c_str(), 1, file.first.size(), fp);
    }

    gettimeofday(&tm, nullptr);
    data.data.common.timestamp = static_cast<unsigned long long>(tm.tv_sec);
    data.data.common.meta_offset = static_cast<unsigned long long>(meta_offset);
    data.data.common.output_sample_rate = static_cast<unsigned int>(max_sample_rate);

    fseek(fp, sizeof(data_chunk), SEEK_SET);
    fwrite(&data.data, 1, sizeof(common_data), fp);

    fflush(fp);
    fclose(fp);

    if(!sync_ctx_id.empty()) {
        if(!AmSessionContainer::instance()->postEvent(
           HTTP_EVENT_QUEUE,
           new HttpTriggerSyncContext(sync_ctx_id,1)))
        {
            ERROR("AmAudioFileRecorderStereo: can't post HttpTriggerSyncContext event");
        }
    }
}

int AmAudioFileRecorderStereoRaw::init(const string &path, const string &sync_ctx)
{
    sync_ctx_id = sync_ctx;

    string filePath(AmConfig.rsr_path + "/" + recorder_id + ".rsr");

    if(std::filesystem::exists(filePath)) {
        WARN("file: %s already exists",filePath.c_str());
        return -1;
    }

    fp = fopen(filePath.c_str(),"w+");
    if(nullptr==fp) {
        ERROR("could not create/overwrite file: %s: %d",filePath.c_str(),errno);
        return -1;
    }

    if(0!=fseek(fp,0L,SEEK_SET)) {
        ERROR("fseek for file: %s: %d",filePath.c_str(), errno);
        fclose(fp);
        fp = nullptr;
        return -1;
    }

    chunk data;
    data.header.type = DATA_COMMON;
    data.header.size = sizeof(common_data);
    memset(&data.data, 0, sizeof(common_data));
    fwrite(&data, 1, sizeof(data_chunk) + sizeof(common_data), fp);

    return add_file(path);
}

int AmAudioFileRecorderStereoRaw::add_file(const string &path)
{
    files.try_emplace(path);
    wait_for_initial_samples = true;
    return 0;
}

void AmAudioFileRecorderStereoRaw::writeStereoSamples(unsigned long long ts, unsigned char *samples, size_t size, int input_sample_rate, int channel_id)
{
    if(wait_for_initial_samples) {
        for(auto &file : files) {
            if(file.second.wait_for_initial_samples) {
                //set initial ts for the newly added files
                file.second.begin = ts;
                file.second.wait_for_initial_samples = false;
            }
        }
        wait_for_initial_samples = false;
    }

    last_ts[channel_id] = ts;
    if(!fp) return;

    if(max_sample_rate < input_sample_rate) {
        max_sample_rate = input_sample_rate;
    }

    chunk data;
    data.data.samples.channel_id = channel_id;
    data.data.samples.sample_rate = input_sample_rate;
    data.data.samples.ts = ts;
    data.header.type = DATA_SAMPLES;
    data.header.size = size + sizeof(samples_data);
    fwrite(&data, 1, sizeof(data_chunk) + sizeof(samples_data), fp);
    fwrite(samples, 1, size, fp);
}


void AmAudioFileRecorderStereoRaw::setTag(unsigned int channel_id, unsigned int tag)
{
    chunk data;
    data.data.tag.channel_id = channel_id;
    data.data.tag.val = tag;
    data.header.type = DATA_TAG;
    data.header.size = sizeof(tag_data);
    fwrite(&data, 1, sizeof(data_chunk) + sizeof(tag_data), fp);
}


void AmAudioFileRecorderStereoRaw::markRecordStopped(const string& file_path)
{
    for(auto &file : files) {
        if(file_path.empty() || file_path == file.first) {
            if(!file.second.end) file.second.end = get_last_ts();
            DBG("mark end of file %s on timestamp %llu", file_path.c_str(), file.second.end);
        }
    }
}

unsigned long long AmAudioFileRecorderStereoRaw::get_last_ts()
{
    unsigned long long ts = 0;
    for(auto& i : last_ts) {
        if(ts < i.second) {
            ts = i.second;
        }
    }
    return ts;
}
