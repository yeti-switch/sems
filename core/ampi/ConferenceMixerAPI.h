#pragma once
#include "AmEventFdQueue.h"
#include "AmSession.h"

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

#define IS_VALID_MIXER_DESCRIPTOR(d) (d.raw!=-1 && d.ctx_idx < MAX_CHANNEL_CTX)

typedef union {
        int64_t         raw;
        struct {
            uint64_t    ctx_idx:32,
                        seq:32;
        };
} mixer_descriptor_t;

struct mixer_ctx : public atomic_ref_cnt
{
    int64_t             id;
    MultiPartyMixer*    mpmixer;
    string              channel_id;
    int                 backlog;

    mixer_ctx(int64_t id, MultiPartyMixer* mpmixer, const string &channel_id)
     : id(id), mpmixer(mpmixer), channel_id(channel_id)
    {}

    void on_destroy();
};

struct ChannelCtx {
    int64_t             id;
    pthread_t           cur_pthread;
    mixer_ctx           *mixer;
    volatile int        usage;
    int                 sample_rate,
                        mpmixer_ch_id;
    uint32_t            seq;
    string              channel_id,
                        local_tag;
};

class ConferenceMixer :
        public AmPluginFactory,
        public AmThread,
        public AmEventFdQueue,
        public AmEventHandler
{
    friend class ConferenceMedia;

    typedef unordered_map<string,set<string>>
                        ChannelId2ParticipantsMap;
public:

    enum { EMPTY=0, READY, GARBAGE, PURGE };

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
        static ChannelCtx               channel_ctx[MAX_CHANNEL_CTX];
        static vector<sockaddr_storage> neighbor_saddr;
        static  int                     neighbors_num;

        static ConferenceMixer*         _instance;
        static RxRing                   rx_ring;

        AmMutex                         channel_mut;

        uint32_t                        ctx_seq;

        // AmTimerFd                       timer;
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
        ChannelId2ParticipantsMap       channels_participants;

        ConferenceMixer();
        ~ConferenceMixer();

        int     configure();
        bool    resolve_name(const string &address, sockaddr_storage &_sa);
        int     bind_socket();
        int     init();
        void    processRequests();
        void    read_neighbor(AmConfigReader &cfg, const string &n_name);
        bool    read_neighbors(AmConfigReader &cfg);

        void    addParticipant(const string &channel_id,const string& local_tag);
        void    removeParticipant(const string &channel_id,const string& local_tag);

        void    AttachConferenceMediaToMediaProcessorThreads();
        void    DetachConferenceMediaFromMediaProcessorThreads();
        void    processEvent(MixerEvent *ev);

public:
        ConferenceMixer(const string& name);

        static  ConferenceMixer *instance();

        const vector<sockaddr_storage>&
                    getNeighbors() { return neighbor_saddr; }



        RxRing*     getRxRing() { return &rx_ring; }
        // int         getFD() { return socket_fd; }

        void        postRequest(MixerEvent *ev);

        mixer_descriptor_t
                    getMixerDescriptor(const string &channel_id, const string& local_tag, int sample_rate);
        void        releaseChannelDescriptor(mixer_descriptor_t  md);

        void        init_backlog(int num);
        void        release_backlog();

        int         onLoad();
        void        process(AmEvent* ev);
        void        run();
        void        on_stop();

        friend      int             getNeighbors_num();
        friend      ChannelCtx*     GetChannelCtx(mixer_descriptor_t md);
        friend      bool            isNeighbor(const sockaddr_storage &from, int &idx);
        friend      struct backlog* get_backlog(unsigned nr);
        friend      ChannelCtx*     get_channel_ctx(unsigned nr);
        friend      uint64_t*       find_backlog_by_id(int64_t id);
        friend      void            clear_backlog(unsigned nr);

};


/** must be inherited from AmAudio for DSMConfChannel */
class ConferenceChannel
  : public AmAudio
{
    mixer_descriptor_t      md;

    void run_backlog(unsigned long long system_ts, unsigned char* buffer, MultiPartyMixer *mixer);
    void put_external(MultiPartyMixer *mixer,
                             int neighbor_idx,
                             unsigned long long ts,
                             unsigned char *buffer,
                             int sample_rate,
                             int size);
  public:
    ConferenceChannel(mixer_descriptor_t md);
    ~ConferenceChannel();

    //AmAudio interface
    int read(unsigned int user_ts, unsigned int size){ return -1; }
    int write(unsigned int user_ts, unsigned int size){ return -1; }

    int get(unsigned long long system_ts, unsigned char* buffer,
                int output_sample_rate, unsigned int nb_samples);
    int put(unsigned long long system_ts, unsigned char* buffer,
                int input_sample_rate, unsigned int size);
};

struct backlog {
        int64_t             id;
        uint64_t            *status;
        mixer_ctx           *mixer;
};


extern ChannelCtx*  GetChannelCtx(mixer_descriptor_t md);
extern bool         isNeighbor(const sockaddr_storage &from, int &idx);
extern uint64_t*    find_backlog_by_id(int64_t id);
extern void         clear_backlog(unsigned nr);

inline int  getNeighbors_num()
{
    return ConferenceMixer::neighbors_num;
}

inline struct backlog* get_backlog(unsigned nr)
{
    return nr < MAX_CHANNEL_CTX
            ? &ConferenceMixer::backlog_data[nr]
            : nullptr;
}


inline ChannelCtx* get_channel_ctx(unsigned nr)
{
    return nr < MAX_CHANNEL_CTX
            ? &ConferenceMixer::channel_ctx[nr]
            : nullptr;
}
