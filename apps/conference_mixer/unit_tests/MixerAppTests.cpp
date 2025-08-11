#include "MixerTest.h"
#include "log.h"
#include "../Mixer.h"

using std::array;
using std::mutex;
using std::thread;
using std::unique_ptr;
using std::vector;

#define PACKET_SIZE                       255
#define NON_PERSISTENT_EXT_CHANNELS_COUNT 100 // channels wich dynamicly added or removed by SessionThread
#define PERSISTENT_EXT_CHANNELS_COUNT     100
#define REPEAT_COUNT                      10'000 // general value for each thread in sress test

/* Func utils */

vector<int> make_sequence(size_t size)
{
    vector<int> tmp(size);
    int         count{};
    for (auto it = tmp.begin(); it != tmp.end(); ++it)
        *it = count++;
    return tmp;
}

/* Global vars */

array<string, 6>    ch_ids                    = { "0", "1" };
vector<int>         non_persistent_ext_ch_ids = make_sequence(NON_PERSISTENT_EXT_CHANNELS_COUNT);
vector<channel_ptr> non_persistent_channels;

/* ThreadBase */

struct ThreadBase {
    int                repeat_count{ 1 };
    unique_ptr<thread> m_thread;
    ThreadBase() { m_thread.reset(new thread(&ThreadBase::thread_func, this)); }
    virtual ~ThreadBase() {}
    virtual void thread_func()
    {
        for (int i{}; i < repeat_count; ++i)
            do_run();
    }
    virtual void do_run() { DBG("do_run"); }
    void         join()
    {
        if (m_thread->joinable())
            m_thread->join();
    }
};

/* SessionThread */

struct SessionThread : ThreadBase {
    enum State { Add, Del } state{ Add };

    int sample_rate{ 8000 };

    void do_run() override
    {
        if (state == State::Add) {
            add_conf_channel();
            state = State::Del;
        } else if (state == State::Del) {
            del_conf_channel();
            state = State::Add;
        }

        usleep(1);
    }

    void add_conf_channel()
    {
        for (auto &ch_id : ch_ids) {
            for (auto &ext_ch_id : non_persistent_ext_ch_ids) {
                auto ch_ptr = Mixer::instance()->getConferenceChannel(ch_id, ext_ch_id, "local_tag", sample_rate);
                non_persistent_channels.push_back(std::move(ch_ptr));
                usleep(1);
            }
        }
    }

    void del_conf_channel()
    {
        auto it = non_persistent_channels.begin();
        while (it != non_persistent_channels.end()) {
            it = non_persistent_channels.erase(it);
            usleep(1);
        }
    }
};

/* MixerThread */

struct MixerThread : ThreadBase {
    int    ext_ch_id{ 1 }, sample_rate{ 8000 };
    string host{ "127.0.0.1" };
    int    port{ 5002 };

    void do_run() override
    {
        send_data();
        usleep(1);
    }

    void send_data()
    {
        int                sock_fd, snd{};
        struct timeval     rcv_timeout;
        struct sockaddr_in si_serv;
        unsigned char      buffer[PACKET_SIZE]{};

        // create socket
        if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
            DBG("create socket error");
            return;
        }

        // set timeout options
        memset(&rcv_timeout, 0, sizeof(timeval));
        rcv_timeout.tv_sec = 10;

        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(timeval)) == -1) {
            DBG("set RCVTIMEO error=%s", strerror(errno));
            return;
        }

        // send data
        memset(&si_serv, 0, sizeof(si_serv));
        si_serv.sin_family      = AF_INET;
        si_serv.sin_port        = htons(port);
        si_serv.sin_addr.s_addr = inet_addr(host.c_str());

        memset(&buffer, 255, PACKET_SIZE); // 0xff

        MixerFrameHdr *hdr = (MixerFrameHdr *)buffer;
        hdr->id            = ext_ch_id;
        hdr->sample_rate   = sample_rate;
        hdr->length        = PACKET_SIZE - sizeof(MixerFrameHdr);

        snd = sendto(sock_fd, buffer, PACKET_SIZE, 0, (struct sockaddr *)&si_serv, sizeof(si_serv));

        if (snd < 0)
            DBG("SENDTO error=%s", strerror(errno));

        shutdown(sock_fd, SHUT_RDWR);
        close(sock_fd);
    }
};

/* MediaThread */

struct MediaThread : ThreadBase {
    channel_ptr        ch_ptr;
    unsigned char      data[AUDIO_BUFFER_SIZE]{};
    unsigned long long ts{};
    int                sample_rate{ 8000 };

    void do_run() override
    {
        put_data();
        usleep(5);
    }

    void put_data()
    {
        memset(&data, 170, PACKET_SIZE); // 0xaa
        ch_ptr->put(ts, data, sample_rate, PACKET_SIZE);
        ts = (ts + WC_INC) & WALLCLOCK_MASK;
    }
};

/* Tests  */

TEST_F(MixerTest, DISABLED_RingRxBacklogOverflowTest)
{
    auto ch_ptr = Mixer::instance()->getConferenceChannel("0", 1, "local_tag", 8000);

    // fill backlog
    MixerThread media_thread;
    media_thread.ext_ch_id    = ch_ptr->get_ext_id();
    media_thread.repeat_count = 8;
    media_thread.join();

    // check 'start', 'end' values
    struct backlog *bl = find_backlog_by_id(ch_ptr->get_ext_id());
    GTEST_ASSERT_EQ(bl->position.start, 0);
    GTEST_ASSERT_EQ(bl->position.end, 7);
}

TEST_F(MixerTest, DISABLED_RunBacklogTest)
{
    auto ch_ptr = Mixer::instance()->getConferenceChannel("0", 1, "local_tag", 8000);

    // fill backlog
    MixerThread mixer_thread;
    mixer_thread.ext_ch_id    = ch_ptr->get_ext_id();
    mixer_thread.repeat_count = 3;
    mixer_thread.join();

    // run backlog
    MediaThread media_thread;
    media_thread.ch_ptr       = std::move(ch_ptr);
    media_thread.repeat_count = 1;
    media_thread.join();

    // check 'start', 'end' values
    struct backlog *bl = find_backlog_by_id(1);
    GTEST_ASSERT_EQ(bl->position.start, 3);
    GTEST_ASSERT_EQ(bl->position.end, 3);
}

TEST_F(MixerTest, DISABLED_MultipleConfChStressTest)
{
    vector<unique_ptr<ThreadBase>> threads;

    // add/del non persistent channels
    {
        SessionThread *session_thread = new SessionThread();
        session_thread->repeat_count  = REPEAT_COUNT;
        threads.emplace_back(session_thread);
    }

    // create persistent channels, Mixer and Media threads
    for (int i{}; i < PERSISTENT_EXT_CHANNELS_COUNT; ++i) {
        for (auto &ch_id : ch_ids) {
            auto ch_ptr = Mixer::instance()->getConferenceChannel(ch_id, NON_PERSISTENT_EXT_CHANNELS_COUNT + i,
                                                                  "local_tag", 8000);

            MixerThread *mixer_thread = new MixerThread();
            mixer_thread->ext_ch_id   = ch_ptr->get_ext_id();
            ;
            mixer_thread->repeat_count = REPEAT_COUNT;
            threads.emplace_back(mixer_thread);

            MediaThread *media_thread  = new MediaThread();
            media_thread->ch_ptr       = std::move(ch_ptr);
            media_thread->repeat_count = REPEAT_COUNT;
            threads.emplace_back(media_thread);
        }
    }

    for (auto &thread : threads)
        thread->join();
}
