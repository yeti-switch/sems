#include <sys/epoll.h>
#include <netdb.h>
#include <memory>

#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "AmConferenceStatus.h"
#include "log.h"
#include "Mixer.h"
#include "bitops.h"

#define MOD_NAME "conference_mixer"

EXPORT_PLUGIN_CLASS_FACTORY(Mixer);
EXPORT_PLUGIN_CONF_FACTORY(Mixer);

struct ReloadEvent : public AmEvent {
    ReloadEvent()
        : AmEvent(0)
    {
    }
};

RxRing Mixer::rx_ring;

backlog Mixer::backlog_data[MAX_CHANNEL_CTX];

/** карта backlog внешних каналов */
DECLARE_BITMAP_ALIGNED(Mixer::backlog_map, MAX_CHANNEL_CTX);

vector<sockaddr_storage> Mixer::neighbor_saddr;
int                      Mixer::neighbors_num = 0;

Mixer *Mixer::_instance = nullptr;

Mixer *Mixer::instance()
{
    if (_instance == nullptr)
        _instance = new Mixer(MOD_NAME);

    return _instance;
}

Mixer::Mixer()
    : AmDynInvokeFactory(MOD_NAME)
    , AmConfigFactory(MOD_NAME)
    , RpcTreeHandler(true)
    , AmEventFdQueue(this)
    , running(true)
    , stopped(false)
    , epoll_fd(-1)
{
    _instance = this;
}


Mixer::Mixer(const string &name)
    : AmDynInvokeFactory(name)
    , AmConfigFactory(MOD_NAME)
    , RpcTreeHandler(true)
    , AmEventFdQueue(this)
    , running(true)
    , stopped(false)
    , epoll_fd(-1)
{
    _instance = this;
}


Mixer::~Mixer()
{
    ::close(socket_fd);
    ::close(epoll_fd);
}


void Mixer::init_rpc_tree()
{
    reg_method(root, "reload", "", "", &Mixer::reload, this);
}

int Mixer::bind_socket()
{
    if ((socket_fd = ::socket(l_saddr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1) {
        ERROR("socket(): %m");
        return -1;
    }

    if (::bind(socket_fd, reinterpret_cast<sockaddr *>(&l_saddr), SA_len(&l_saddr)) == -1) {
        ERROR("bind(): %m");
        ::close(socket_fd);
        return -1;
    }

    struct epoll_event ev = { 0 };

    ev.events  = EPOLLIN | EPOLLERR;
    ev.data.fd = socket_fd;

    if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &ev) == -1) {
        ERROR("epoll_ctl(): %m");
        return -1;
    }
    return 0;
}


bool Mixer::resolve_name(const string &address, sockaddr_storage &_sa)
{
    dns_handle _dh;
    bool       res = resolver::instance()->resolve_name(address.c_str(), &_dh, &_sa, IPv4_only) != -1;

    if (!res)
        ERROR("can't resolve destination: '%s'", address.c_str());

    return res;
}


#define SECTION_LISTEN_NAME     "listen"
#define SECTION_NEIGHBOURS_NAME "neighbours"
#define SECTION_NEIGHBOUR_NAME  "neighbour"
#define PARAM_PORT_NAME         "port"
#define PARAM_ADDRESS_NAME      "address"

#define checkMandatoryParameter(cfg, ifname)                                                                           \
    if (!cfg_size(cfg, ifname)) {                                                                                      \
        ERROR("absent mandatory parameter %s in section %s", ifname, cfg->name);                                       \
        return -1;                                                                                                     \
    }
static void cfg_error_callback(cfg_t *cfg, const char *fmt, va_list ap)
{
    char  buf[2048];
    char *s = buf;
    char *e = s + sizeof(buf);

    if (cfg->title) {
        s += snprintf(s, e - s, "%s:%d [%s/%s]: ", cfg->filename, cfg->line, cfg->name, cfg->title);
    } else {
        s += snprintf(s, e - s, "%s:%d [%s]: ", cfg->filename, cfg->line, cfg->name);
    }
    s += vsnprintf(s, e - s, fmt, ap);

    ERROR("%.*s", (int)(s - buf), buf);
}

int Mixer::read_neighbor(cfg_t *cfg)
{
    string neighbor_address;
    int    neighbor_port;

    checkMandatoryParameter(cfg, PARAM_ADDRESS_NAME);
    neighbor_address = cfg_getstr(cfg, PARAM_ADDRESS_NAME);
    neighbor_port    = cfg_getint(cfg, PARAM_PORT_NAME);

    sockaddr_storage saddr;
    if (resolve_name(neighbor_address, saddr)) {
        am_set_port(&saddr, neighbor_port);
        neighbor_saddr.push_back(saddr);
        neighbors_num++;
    }
    return 0;
}

int Mixer::configure(const std::string &config)
{
    cfg_opt_t listen[] = { CFG_INT(PARAM_PORT_NAME, MIXER_DEFAULT_PORT, CFGF_NONE),
                           CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT), CFG_END() };

    cfg_opt_t neighbour[] = { CFG_INT(PARAM_PORT_NAME, MIXER_DEFAULT_PORT, CFGF_NONE),
                              CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT), CFG_END() };

    cfg_opt_t neighbours[] = { CFG_SEC(SECTION_NEIGHBOUR_NAME, neighbour, CFGF_MULTI | CFGF_TITLE), CFG_END() };

    cfg_opt_t opt[] = { CFG_SEC(SECTION_LISTEN_NAME, listen, CFGF_NODEFAULT),
                        CFG_SEC(SECTION_NEIGHBOURS_NAME, neighbours, CFGF_NODEFAULT), CFG_END() };
    cfg_t    *cfg   = cfg_init(opt, 0);
    if (!cfg)
        return -1;
    cfg_set_error_function(cfg, cfg_error_callback);

    switch (cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS: break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error", MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing", MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    checkMandatoryParameter(cfg, SECTION_LISTEN_NAME);
    cfg_t *lcfg = cfg_getsec(cfg, SECTION_LISTEN_NAME);
    int    port = cfg_getint(lcfg, PARAM_PORT_NAME);
    checkMandatoryParameter(lcfg, PARAM_ADDRESS_NAME);
    string address = cfg_getstr(lcfg, PARAM_ADDRESS_NAME);
    if (!resolve_name(address, l_saddr)) {
        cfg_free(cfg);
        return -1;
    }
    am_set_port(&l_saddr, port);

    checkMandatoryParameter(cfg, SECTION_NEIGHBOURS_NAME);
    cfg_t *nodes = cfg_getsec(cfg, SECTION_NEIGHBOURS_NAME);
    for (unsigned int i = 0; i < cfg_size(nodes, SECTION_NEIGHBOUR_NAME); i++) {
        if (read_neighbor(cfg_getnsec(nodes, SECTION_NEIGHBOUR_NAME, i)) < 0) {
            cfg_free(cfg);
            return -1;
        }
    }

    cfg_free(cfg);
    return 0;
}

int Mixer::reconfigure(const std::string &config)
{
    return 0;
}

int Mixer::init()
{
    if ((epoll_fd = epoll_create1(0)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    if (bind_socket() == -1)
        return -1;

    epoll_link(epoll_fd);
    event.link(epoll_fd);

    // timer.set(TIMER_INTERVAL);
    // timer.link(epoll_fd);

    INFO("Mixer initialized");
    return 0;
}

void Mixer::reload(const AmArg &args, AmArg &ret)
{
    AmSessionContainer::instance()->postEvent(MIXER_EVENT_QUEUE, new ReloadEvent());
}

int Mixer::onLoad()
{
    init_rpc();

    if (init()) {
        ERROR("initialization error");
        return -1;
    }

    start();
    return 0;
}


void Mixer::process(AmEvent *ev)
{
    if (ev->event_id == E_SYSTEM) {
        AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(ev);
        if (sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
            running = false;
            event.fire();
        }
    } else if (dynamic_cast<ReloadEvent *>(ev)) {
        neighbors_num = 0;
        neighbor_saddr.clear();

        ConfigContainer config;
        if (AmLcConfig::instance().readConfiguration(&config) || configure(config.module_config[MOD_NAME])) {
            ERROR("configuration error");
            return;
        }

        ::close(socket_fd);
        ::close(epoll_fd);

        if (init()) {
            ERROR("initialization error");
            return;
        }

        DetachConferenceMediaFromMediaProcessorThreads();
        AttachConferenceMediaToMediaProcessorThreads();

    } else
        WARN("unknown event received");
}


void Mixer::on_stop()
{
    running = false;
    event.fire();
    stopped.wait_for();
}


void Mixer::AttachConferenceMediaToMediaProcessorThreads()
{
    num_media_threads = AmConfig.media_proc_threads;

    DBG("Attach MixerMedia to %u threads", num_media_threads);

    conference_media2media_threads = new ConferenceMedia *[num_media_threads];

    for (int i = 0; i < num_media_threads; ++i) {
        ConferenceMedia *m                = new ConferenceMedia(this, i, socket_fd);
        conference_media2media_threads[i] = m;
        inc_ref(m);
        AmMediaProcessor::instance()->addTailHandler(m, i);
    }
}


void Mixer::DetachConferenceMediaFromMediaProcessorThreads()
{
    DBG("Detach MixerMedia from threads");

    for (int i = 0; i < num_media_threads; ++i)
        AmMediaProcessor::instance()->removeTailHandler(conference_media2media_threads[i], i);

    delete[] conference_media2media_threads;
    conference_media2media_threads = nullptr;
}


inline void clear_backlog(unsigned nr)
{
    if (nr < MAX_CHANNEL_CTX)
        clear_bit(nr, Mixer::backlog_map);
}


void Mixer::run()
{
    setThreadName("mixer");

    AmEventDispatcher::instance()->addEventQueue(MIXER_EVENT_QUEUE, this);

    AttachConferenceMediaToMediaProcessorThreads();

    do {
        struct epoll_event events[MIXER_DISPATCHER_MAX_EPOLL_EVENT];

        int ret = epoll_wait(epoll_fd, events, MIXER_DISPATCHER_MAX_EPOLL_EVENT, -1);

        if (ret == -1 && errno != EINTR)
            ERROR("epoll_wait(): %m");

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            uint32_t ev      = events[n].events;
            int      ev_info = events[n].data.fd;

            // if (ev_info == timer)
            if (ev_info == -queue_fd()) {
                clear_pending();
                processEvents();
            } else if (ev_info == event) {
                event.read();
                processRequests();
                break;
            } else
                rx_ring.handler(ev, ev_info);
        }

    } while (running);

    epoll_unlink(epoll_fd);
    AmEventDispatcher::instance()->delEventQueue(MIXER_EVENT_QUEUE);

    DetachConferenceMediaFromMediaProcessorThreads();
    stopped.set(true);
    DBG("Mixer stopped");
}


void Mixer::addParticipant(const string &channel_id, const string &local_tag)
{
    AmLock l(channels_participants_mut);

    auto it = channels_participants.find(channel_id);

    if (it == channels_participants.end()) {
        set<string> set{ local_tag };
        channels_participants.insert(std::make_pair(channel_id, set));
    } else
        it->second.insert(local_tag);

    postRequest(new Mixer::MixerEvent(channel_id, ConfNewParticipant, local_tag));
}


void Mixer::removeParticipant(const string &channel_id, const string &local_tag)
{
    AmLock l(channels_participants_mut);

    auto it = channels_participants.find(channel_id);

    if (it != channels_participants.end() && it->second.erase(local_tag))
        postRequest(new Mixer::MixerEvent(channel_id, ConfParticipantLeft, local_tag));
}


struct backlog *find_backlog_by_id(uint64_t id)
{
    int i;

    foreach_set(i, Mixer::backlog_map,
                MAX_CHANNEL_CTX) if (Mixer::backlog_data[i].id == id) return &Mixer::backlog_data[i];

    return nullptr;
}


static inline bool saddr_match(const sockaddr_storage &a0, const sockaddr_storage &a1)
{
    if (a0.ss_family != a1.ss_family)
        return false;

    switch (a0.ss_family) {
    case AF_INET:
        return !(((const struct sockaddr_in *)&a0)->sin_addr.s_addr ^
                 ((const struct sockaddr_in *)&a1)->sin_addr.s_addr);
    case AF_INET6:
    {
        const __be64 *_a0 = (const __be64 *)&((const struct sockaddr_in6 *)&a0)->sin6_addr;
        const __be64 *_a1 = (const __be64 *)&((const struct sockaddr_in6 *)&a1)->sin6_addr;
        return !((_a0[0] ^ _a1[0]) | (_a0[1] ^ _a1[1]));
    }
    }

    return false;
}


bool isNeighbor(const sockaddr_storage &from, int &idx)
{
    idx = 0;

    for (const auto &saddr : Mixer::neighbor_saddr) {
        if (saddr_match(saddr, from))
            return true;
        ++idx;
    }

    // DBG("drop from %s", am_inet_ntop(&from).c_str());
    return false;
}


channel_ptr Mixer::getConferenceChannel(const string &channel_id, uint64_t channel_ext_id, const string &local_tag,
                                        int sample_rate)
{
    // INFO("=> ext_id %ld channel_id='%s' { %ld }", channel_ext_id, channel_id.c_str(), backlog_data[0].id);

    mixer_ptr mixer;
    int       i;
    int       backlog_id    = -1;
    int       mpmixer_ch_id = -1;

    /**
        set/clear_bit - atomic with LOCK_PREFIX
        foreach_set - not atomic
        find_unset - not atomic
    */

    AmLock l(backlog_mut);

    foreach_set(i, backlog_map, MAX_CHANNEL_CTX)
    {

        mixer = backlog_data[i].mixer; /// take reference to the backlog_data[i].mixer

        if (backlog_data[i].id == channel_ext_id)
            break;
    }

    if (mixer && mixer->ext_id == channel_ext_id) {
        backlog_id = mixer->get_backlog_id();

        AmLock l(mixer->mpm_mut);
        mpmixer_ch_id = mixer->addChannel(sample_rate);

    } else {

        backlog_id = find_unset(backlog_map, MAX_CHANNEL_CTX);

        if (backlog_id == MAX_CHANNEL_CTX)
            throw string("Mixer: failed to get mixer channel"); // throw std::bad_alloc();

        mixer = std::make_shared<MultiPartyMixer>(channel_ext_id, backlog_id, neighbor_saddr.size(), sample_rate);

        mpmixer_ch_id = mixer->addChannel(sample_rate);

        backlog_data[backlog_id].id    = channel_ext_id;
        backlog_data[backlog_id].mixer = mixer;
        set_bit(backlog_id, backlog_map);
    }

    addParticipant(channel_id, local_tag);

    return channel_ptr(new ConferenceChannel(mpmixer_ch_id, channel_ext_id, std::move(mixer)),
                       [=, this](ConferenceChannel *p) -> void {
                           backlog_mut.lock(); /// fetched by reference

                           mixer_ptr _mixer = get_backlog(backlog_id)->mixer;

                           if (p->use_count() != 3) { /// 3 -> _mixer, *p and backlog.mixer refs
                               AmLock l(_mixer->mpm_mut);
                               _mixer->removeChannel(mpmixer_ch_id);
                           } else {
                               /// last channel released, release backlog mixer refs
                               backlog_data[backlog_id].mixer.reset();
                               backlog_data[backlog_id].position.pair = 0;
                               clear_bit(backlog_id, backlog_map);
                           }

                           backlog_mut.unlock();

                           removeParticipant(channel_id, local_tag);

                           delete p;
                       });
}


void Mixer::processEvent(MixerEvent *ev)
{
    AmLock l(channels_participants_mut);

    auto ch_it = channels_participants.find(ev->channel_id);

    if (ch_it != channels_participants.end()) {

        const set<string> &participants = ch_it->second;
        size_t             size         = participants.size();

        for (const auto &local_tag : participants)
            AmSessionContainer::instance()->postEvent(
                local_tag, new ConferenceEvent(ev->event_id, size, ev->channel_id, ev->from_tag));
    }
}


void Mixer::processRequests()
{
    static deque<MixerEvent *> tmp_queue;

    queue_mtx.lock();
    tmp_queue.swap(pending_queue);
    queue_mtx.unlock();

    while (!tmp_queue.empty()) {
        MixerEvent *ev = tmp_queue.front();
        processEvent(ev);
        tmp_queue.pop_front();
        delete ev;
    }
}


void Mixer::postRequest(MixerEvent *ev)
{
    queue_mtx.lock();
    pending_queue.push_back(ev);
    queue_mtx.unlock();

    event.fire();
}
