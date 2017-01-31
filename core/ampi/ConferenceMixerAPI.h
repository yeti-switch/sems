#pragma once

#include "AmThread.h"
#include "atomic_types.h"
#include <sip/resolver.h>
#include "SampleArray.h"
#include "AmEventFdQueue.h"
#include "AmEventQueue.h"
#include "AmAudio.h"
#include "AmRtpStream.h"
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

using std::string;
using std::unordered_map;
using std::shared_ptr;


template<typename Target, typename Source>
Target lexical_cast(Source arg)
{
  std::stringstream interpreter;
  Target result;
  if(!(interpreter << arg) ||
     !(interpreter >> result) ||
     !(interpreter >> std::ws).eof())
        throw std::bad_cast();
  return result;
}


#define CONFERENCE_MIXER_EVENT_QUEUE                 "conference_mixer"
#define CONFERENCE_MIXER_DEFAULT_LISTEN_ADDRESS      "localhost"
#define CONFERENCE_MIXER_DEFAULT_PORT                5002
#define CONFERENCE_MIXER_DISPATCHER_MAX_EPOLL_EVENT  256
#define TIMER_INTERVAL_SEC                           1

#ifndef MAX_RTP_SESSIONS
#define MAX_RTP_SESSIONS 2048
#endif

//#define RORPP_PLC

#ifdef RORPP_PLC
#include "LowcFE.h"
#endif

#define MIXER_EVENT_QUEUE "conference_mixer"


#define likely(x)       __builtin_expect(!!(x),1)
#define unlikely(x)     __builtin_expect(!!(x),0)


struct ExternalChannelKey
{
    sockaddr_storage    saddr;
    uint64_t            id;

    ExternalChannelKey(const sockaddr_storage &saddr, uint64_t id) : saddr(saddr), id(id) {}

    bool operator==(const ExternalChannelKey &other) const
    {
        // TODO:
        // if (from.ss_family == other.from.ss_family
        return  id == other.id;
    }
};


struct ExternalChannelKeyHasher
{
    std::size_t operator()(const ExternalChannelKey& k) const
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&k.saddr;
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&k.saddr;

        size_t  hash = k.id >>32 ^ k.id;

        switch (k.saddr.ss_family) {
        case AF_INET:
            return hash ^ sin->sin_addr.s_addr;
        case AF_INET6: {
            const __be32 *a = (const __be32 *)&sin6->sin6_addr;
            return hash ^ a[0] ^ a[1] ^ a[2] ^ a[3];
        }
        default:
            return hash;
        }
  }
};


#define UDP_MESSAGE_MAX 65508

// 20*rate/1000 = frames
// 1MB ~500 каналов по 44100
#define TX_RING_MMAP_ORDER 20
#define TX_RING_MMAP_SIZE  (1<<TX_RING_MMAP_ORDER)
#define TX_RING_MMAP_MASK  (TX_RING_MMAP_SIZE-1)
// 8192
#define TX_RING_RX_ORDER   13
#define TX_RING_RX_SIZE    (1<<TX_RING_RX_ORDER)
#define TX_RING_RX_MASK    (TX_RING_RX_SIZE-1)

// 2MB
#define RX_RING_MMAP_ORDER 21
#define RX_RING_MMAP_SIZE  (1<<RX_RING_MMAP_ORDER)
#define RX_RING_MMAP_MASK  (RX_RING_MMAP_SIZE-1)

// 8192
#define RX_RING_RX_ORDER   13
#define RX_RING_RX_SIZE    (1<<RX_RING_RX_ORDER)
#define RX_RING_RX_MASK    (RX_RING_RX_SIZE-1)

#pragma pack (1)
typedef struct {
    uint64_t            id;
    int                 sample_rate;
    int                 length;
    unsigned char       payload[];
} MixerFrameHdr;
#pragma pack ()


typedef struct {
    sockaddr_storage    saddr;
    union {
        MixerFrameHdr       hdr;
        unsigned char       *data;
    };
} RingFrame;


class TxRing {
    const vector<sockaddr_storage>& neighbor_saddr;
    int                             sockfd,
                                    offset;

    unsigned int                    last_tx,
                                    pending;

    unsigned char                   *buffer;
    RingFrame                       tx[TX_RING_RX_SIZE];

    void    send(struct iovec *iov, int iov_len);

public:
    TxRing(int sd, const vector<sockaddr_storage>& neighbor_saddr);
    ~TxRing();

    void    put(unsigned long long ts,
                ExternalChannelKey &key,
                int output_sample_rate,
                unsigned char *data,
                int size);

    void    done();
};


class RxRing {
    unsigned char       *buffer;
    int                 offset;
    atomic_int          last_rx;

    RingFrame           *next_rx_frame;
    RingFrame           rx[RX_RING_RX_SIZE];

    inline  void        turn_ring(ssize_t length);

public:
    RxRing();
    ~RxRing();

    void                handler(uint32_t ev, int fd);

    inline RingFrame    *get(int req_rx_frame)
    {
        return (req_rx_frame == last_rx.get())
                ? NULL
                : &rx[req_rx_frame & RX_RING_RX_MASK];
    }
};


/** \brief event in a conference*/
struct ConferenceEvent: public AmEvent
{
    unsigned int participants;
    string       conf_id;
    string       sess_id;

    ConferenceEvent(int event_id,
		  unsigned int participants,
		  const string& conf_id,
		  const string& sess_id)
            : AmEvent(event_id),
                participants(participants),
                conf_id(conf_id),
                sess_id(sess_id)
    {}
};


class ConferenceMedia;
class ConferenceStatus;
class ConferenceExtChannel;


class ConferenceChannel :
        public AmAudio,
        public std::enable_shared_from_this<ConferenceChannel>
{
    friend class ConferenceMedia;
    friend class ConferenceStatus;

    shared_ptr<ConferenceStatus>    status;
    string                          channel_id,local_tag;
    unsigned int                    sample_rate;
    int                             mixer_channel_id;
    ConferenceChannel() {}

protected:
  // Fake implement AmAudio's pure virtual methods
  // this avoids to copy the samples locally by implementing only get/put
    int read(unsigned int user_ts, unsigned int size){ return -1; }
    int write(unsigned int user_ts, unsigned int size){ return -1; }

    // override AmAudio
    int get(unsigned long long system_ts, unsigned char* buffer,
                unsigned int &output_sample_rate);

    int get(unsigned long long system_ts, unsigned char* buffer,
                int output_sample_rate, unsigned int nb_samples);
    int put(unsigned long long system_ts, unsigned char* buffer,
                int input_sample_rate, unsigned int size);
public:
    ConferenceChannel(const string &channel_id, const string& local_tag, int sample_rate);
    ~ConferenceChannel();

    string          getChannelID()  { return channel_id; }
    int             get_ch_id()     { return mixer_channel_id; }
    unsigned int    getSampleRate() { return sample_rate; }
    const string&   getLocalTag()   { return local_tag; }
    void            reset_status(shared_ptr<ConferenceStatus> &ptr);
};


class ConferenceMixer :
        public AmPluginFactory,
        public AmThread,
        public AmEventFdQueue,
        public AmEventHandler
{
public:
    typedef shared_ptr<ConferenceChannel>           channel_ptr;
    typedef shared_ptr<ConferenceStatus>            status_ptr;
    typedef unordered_map<string,status_ptr>        ChannelId2StatusMap;
    typedef map<uint64_t,ConferenceChannel *>       conf_id2node_channel_t;

    typedef unordered_map<ExternalChannelKey, ConferenceExtChannel*, ExternalChannelKeyHasher>
                External2LocalChanelMap;

    enum    request_t { addChannel, removeChannel, Event };

    struct MixerEvent {
        request_t       ev;
        channel_ptr     ch_ptr;
        int             event_id;
        string          channel_id,
                        from_tag;

        MixerEvent(request_t ev, channel_ptr &ch_ptr) : ev(ev), ch_ptr(ch_ptr) {}

        MixerEvent(request_t ev, const string &channel_id, unsigned int event_id, const string &from_tag)
            : ev(ev), channel_id(channel_id), event_id(event_id), from_tag(from_tag)  {}
    };

private:
    static ConferenceMixer*         _instance;

    // AmTimerFd                       timer;
    AmEventFd                       event;
    bool                            running;
    AmCondition<bool>               stopped;
    int                             epoll_fd;
    int                             socket_fd;

    sockaddr_storage                l_saddr;

    // sockaddr_storage**              neighbor_saddr;
    vector<sockaddr_storage>        neighbor_saddr;


    /** AmMediaProcessorThread[n] -> ConferenceMedia */
        int                         num_media_threads;
        ConferenceMedia**           conference_media2media_threads;

        vector<conf_id2node_channel_t> conf_id2node_channel;

        ChannelId2StatusMap         chann_id2status;

        AmMutex                     queue_mtx;
        deque<MixerEvent *>         pending_queue;

        RxRing                      rx_ring;

        AmMutex                     external_channels_mut;
        External2LocalChanelMap     external_channels;

        ConferenceMixer();
        ~ConferenceMixer();

        int     configure();
        bool    resolve_name(const string &address, sockaddr_storage &_sa);
        int     bind_socket();
        int     init();
        void    processRequests();
        void    read_neighbor(AmConfigReader &cfg, const string &n_name);
        bool    read_neighbors(AmConfigReader &cfg);

        void    AttachConferenceMediaToMediaProcessorThreads();
        void    DetachConferenceMediaFromMediaProcessorThreads();

        void    AppendExternalChannels(status_ptr &ptr);
        void    ReleaseExternalChannels(status_ptr &ptr);

        void    AddChannel(channel_ptr &ptr);
        void    RemoveChannel(channel_ptr &ptr);
        void    postConferenceEvent(MixerEvent  *req);

public:
        ConferenceMixer(const string& name);
        static  ConferenceMixer *instance();

        void        postRequest(MixerEvent *req);

        RxRing*     getRxRing() { return &rx_ring; }
        ConferenceExtChannel *findExtChannel(const ExternalChannelKey &key);

        const vector<sockaddr_storage>&getNeighbors() { return neighbor_saddr; }

        inline void external_lock() { external_channels_mut.lock(); }
        inline void external_unlock() { external_channels_mut.unlock(); }
        External2LocalChanelMap& GetExternalChannels() { return external_channels; }

        int         onLoad();
        void        process(AmEvent* ev);
        void        run();
        void        on_stop();
};
