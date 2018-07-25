#include "AmAudioFileRecorderMono.h"
#include "AmSessionContainer.h"
#include "ampi/HttpClientAPI.h"

AmAudioFileRecorderMono::AmAudioFileRecorderMono()
  : AmAudioFileRecorder(RecorderMonoAmAudioFile)
{ }

AmAudioFileRecorderMono::~AmAudioFileRecorderMono()
{
    if(!sync_ctx_id.empty()) {
        if(!AmSessionContainer::instance()->postEvent(
           HTTP_EVENT_QUEUE,
           new HttpTriggerSyncContext(sync_ctx_id,files.size())))
        {
            ERROR("AmAudioFileRecorderMono: can't post HttpTriggerSyncContext event");
        }
    }

    for(vector<AmAudioFile *>::iterator it = files.begin();
        it!=files.end(); ++it)
    {
        delete *it;
    }
}

int AmAudioFileRecorderMono::init(const string &path, const string &sync_ctx)
{
    sync_ctx_id = sync_ctx;
    files.push_back(new AmAudioFile());
    return files.back()->open(path,AmAudioFile::Write);
}

int AmAudioFileRecorderMono::add_file(const string &path)
{
    for(vector<AmAudioFile *>::const_iterator it = files.begin();
        it!=files.end(); ++it)
    {
            if((*it)->getFileName()==path) {
                ERROR("attempt to add the same file to the recorder: %s",
                    path.c_str());
                return 1;
            }
    }
    AmAudioFile *f = new AmAudioFile();
    if(0!=f->open(path,AmAudioFile::Write)) {
        ERROR("failed to open: %s", path.c_str());
        delete f;
        return 1;
    }
    files.push_back(f);
    DBG("recorder has %zd opened files",  files.size());
    return 0;
}

void AmAudioFileRecorderMono::writeSamples(unsigned char *samples, size_t size, int input_sample_rate)
{
    for(vector<AmAudioFile *>::iterator it = files.begin();
        it!=files.end(); ++it)
    {
        (*it)->put(0,samples,input_sample_rate,size);
    }
}

