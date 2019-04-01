#pragma once
#include <cstdint>

#include "AmEventFdQueue.h"
#include "AmSession.h"
#include "RpcTreeHandler.h"

#include <atomic>
#include <memory>
#include <functional>
#include <map>
#include <unordered_map>
#include <set>
#include <string>
#include <sstream>
#include <vector>

using std::deque;
using std::map;
using std::string;
using std::vector;
using std::unordered_map;

class ConferenceMedia;
class MultiPartyMixer;
class RxRing;

#ifndef MAX_RTP_SESSIONS
#define MAX_RTP_SESSIONS 2048
#endif

#define MAX_CHANNEL_CTX MAX_RTP_SESSIONS
#define CONFERENCE_NAMESPACE_ID	100

#define MIXER_BACKLOG_ORDER     3
#define MIXER_BACKLOG_SIZE      (1<<MIXER_BACKLOG_ORDER)
#define MIXER_BACKLOG_MASK      (MIXER_BACKLOG_SIZE-1)


#pragma pack (1)
typedef struct {
    uint64_t            id;
    int                 sample_rate;
    unsigned            length;
} MixerFrameHdr;
#pragma pack ()


typedef struct {
    union {
        MixerFrameHdr       hdr;
        unsigned char       *data;
    };
} MixerFrame;


typedef struct {
    int             neighbor_id;
    union {
        MixerFrameHdr   *hdr;
        unsigned char   *data;
    };
} RxFrame;


using mixer_ptr = std::shared_ptr<MultiPartyMixer>;

struct backlog {
    int64_t     id;
    mixer_ptr   mixer;

    atomic_int  start; /** if start == end => frame queue is empty */
    atomic_int  end;
    RxFrame     frame[MIXER_BACKLOG_SIZE];
};


/** must be inherited from AmAudio for DSMConfChannel */
class ConferenceChannel
        : public AmAudio
{
    int64_t                 ext_id;
    int                     sample_rate,
                            mpmixer_ch_id;
    mixer_ptr               mpmixer;

    void put_external(int neighbor_idx, unsigned long long ts, unsigned char *buffer,
                        int sample_rate, int size);

    void            run_backlog(unsigned long long ts, unsigned char* buffer);
public:
    ConferenceChannel() = delete;
    ConferenceChannel(int mpmixer_ch_id, int64_t ext_id, mixer_ptr mpmixer);
    ~ConferenceChannel() = default;

    // Mixer interface
    long            use_count()         { return mpmixer.use_count(); }
    MultiPartyMixer *get_mpmixer()         { return mpmixer.get(); }

    int             get_ext_id()        { return ext_id; }
    int             get_mpmixer_ch_id() { return mpmixer_ch_id; }

    //AmAudio interface
    int read(unsigned int user_ts, unsigned int size){ return -1; }
    int write(unsigned int user_ts, unsigned int size){ return -1; }

    int get(unsigned long long system_ts, unsigned char* buffer,
            int output_sample_rate, unsigned int nb_samples);
    int put(unsigned long long system_ts, unsigned char* buffer,
            int input_sample_rate, unsigned int size);
};


using channel_ptr       = std::unique_ptr<ConferenceChannel,std::function<void(ConferenceChannel *)>>;


class Mixer :
        public AmDynInvokeFactory,
        public AmConfigFactory,
        public RpcTreeHandler<Mixer>,
        public AmThread,
        public AmEventFdQueue,
        public AmEventHandler
{
    typedef unordered_map<string,set<string>> ChannelId2ParticipantsMap;

public:

    struct MixerEvent {
        int             event_id;
        string          channel_id,
        from_tag;

        MixerEvent(const string &channel_id, unsigned int event_id, const string &from_tag)
            : channel_id(channel_id), event_id(event_id), from_tag(from_tag)  {}
    };

private:
    static unsigned long            backlog_map[MAX_CHANNEL_CTX/(sizeof(long)*8)];
    static struct backlog           backlog_data[MAX_CHANNEL_CTX];
    static vector<sockaddr_storage> neighbor_saddr;
    static  int                     neighbors_num;
    AmMutex                         backlog_mut;

    static Mixer*                   _instance;
    static RxRing                   rx_ring;

    AmEventFd                       event;
    bool                            running;
    AmCondition<bool>               stopped;
    int                             epoll_fd;
    int                             socket_fd;
    sockaddr_storage                l_saddr;


    /** AmMediaProcessorThread[n] -> ConferenceMedia */
    int                             num_media_threads;
    ConferenceMedia**               conference_media2media_threads;

    AmMutex                         queue_mtx;
    deque<MixerEvent *>             pending_queue;

    // карта имен каналов в наборы local_tag участников
    AmMutex                         channels_participants_mut;
    ChannelId2ParticipantsMap       channels_participants;

    Mixer();
    ~Mixer();

    int     configure(const std::string& config);
    bool    resolve_name(const string &address, sockaddr_storage &_sa);
    int     bind_socket();
    int     init();
    void    reload(const AmArg& args, AmArg& ret);
    void    processRequests();
    int    read_neighbor(cfg_t* cfg);

    void    addParticipant(const string& channel_id,const string& local_tag);
    void    removeParticipant(const string& channel_id,const string& local_tag);

    void    AttachConferenceMediaToMediaProcessorThreads();
    void    DetachConferenceMediaFromMediaProcessorThreads();
    void    processEvent(MixerEvent *ev);

public:
    Mixer(const string& name);

    AmDynInvoke* getInstance() { return instance(); }
    static  Mixer *instance();

    virtual void init_rpc_tree();

    const vector<sockaddr_storage>&
    getNeighbors() { return neighbor_saddr; }

    RxRing*     getRxRing() { return &rx_ring; }
    void        postRequest(MixerEvent *ev);

    channel_ptr getConferenceChannel(const string &channel_id, int64_t channel_ext_id, const string &local_tag, int sample_rate);
    void        releaseConferenceChannel(const channel_ptr &p, const string &local_tag);


    int         onLoad();
    void        process(AmEvent* ev);
    void        run();
    void        on_stop();

    friend      class ConferenceMedia;
    friend      class RxRing;
    friend      int             getNeighbors_num();
    friend      bool            isNeighbor(const sockaddr_storage &from, int &idx);
    friend      struct backlog* get_backlog(unsigned nr);
    friend      struct backlog* find_backlog_by_id(uint64_t id);
    friend      void            clear_backlog(unsigned nr);

};



inline int  getNeighbors_num()
{
    return Mixer::neighbors_num;
}

inline struct backlog* get_backlog(unsigned nr)
{
    return nr < MAX_CHANNEL_CTX
            ? &Mixer::backlog_data[nr]
              : nullptr;
}

extern bool             isNeighbor(const sockaddr_storage &from, int &idx);

extern struct backlog   *find_backlog_by_id(uint64_t id);

extern void             clear_backlog(unsigned nr);
