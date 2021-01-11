#include "OptionsProber.h"
#include "ampi/OptionsProberAPI.h"

#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "sip/parse_via.h"

#define MOD_NAME "options_prober"

#include <unistd.h>

#define CFG_OPT_NAME_EXPORT_METRICS "export_metrics"

#define DEFAULT_EXPIRES 1800

#define TIMEOUT_CHECKING_INTERVAL 1000000 //microseconds
#define EPOLL_MAX_EVENTS    2048

EXPORT_PLUGIN_CLASS_FACTORY(OptionsProber);
EXPORT_PLUGIN_CONF_FACTORY(OptionsProber);

OptionsProber* OptionsProber::instance()
{
    //we have to use new operator because of delete_plugin_factory in AmPlugin.cpp
    static auto _instance = new OptionsProber(MOD_NAME);
    //static SipProber _instance(MOD_NAME);
    return _instance;
}

AmDynInvoke* OptionsProber::getInstance()
{
    return instance();
}

OptionsProber::OptionsProber(const string& name)
  : AmDynInvokeFactory(MOD_NAME),
    AmConfigFactory(MOD_NAME),
    AmEventFdQueue(this),
    uac_auth_i(nullptr),
    stopped(false)
{}

int OptionsProber::configure(const std::string& config)
{
    cfg_opt_t opt[] = {
        CFG_BOOL(CFG_OPT_NAME_EXPORT_METRICS, cfg_false, CFGF_NONE),
        CFG_END()
    };
    cfg_t *cfg = cfg_init(opt, CFGF_NONE);
    if(!cfg) return -1;
    switch(cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error",MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing",MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    if(cfg_true==cfg_getbool(cfg,CFG_OPT_NAME_EXPORT_METRICS))
        statistics::instance()->add_groups_container("options_prober", this);

    cfg_free(cfg);
    return 0;
}

int OptionsProber::reconfigure(const std::string& config)
{
    return configure(config);
}

void OptionsProber::run()
{
    int ret;

    setThreadName("options-prober");

    AmDynInvokeFactory* uac_auth_f = AmPlugIn::instance()->getFactory4Di("uac_auth");
    if (uac_auth_f == nullptr) {
        WARN("unable to get a uac_auth factory. probers will not be able to authenticate");
    } else {
        uac_auth_i = uac_auth_f->getInstance();
    }

    bool running = true;
    struct epoll_event events[EPOLL_MAX_EVENTS];
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int f = e.data.fd;

            if(!(e.events & EPOLLIN)){
                continue;
            }

            if(f==timer){
                checkTimeouts();
                timer.read();
            } else if(f== -queue_fd()){
                clear_pending();
                processEvents();
            } else if(f==stop_event){
                stop_event.read();
                running = false;
                break;
            }
        }
    } while(running);

    AmEventDispatcher::instance()->delEventQueue(OPTIONS_PROBER_QUEUE);
    epoll_unlink(epoll_fd);
    close(epoll_fd);

    onServerShutdown();
    stopped.set(true);
}

void OptionsProber::checkTimeouts()
{
    //DBG("check timeouts");
    SipSingleProbe::timep now(std::chrono::system_clock::now());

    vector<SipSingleProbe *> probers_to_remove;

    AmLock l(probers_mutex);
    for(auto &p : probers_by_id) {
        if(p.second->process(now)) {
            probers_to_remove.push_back(p.second);
        }
    }

    for(auto &p : probers_to_remove) {
        removeProberUnsafe(p);
    }
}

int OptionsProber::onLoad()
{
    if((epoll_fd = epoll_create(3)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd);
    stop_event.link(epoll_fd);

    timer.set(TIMEOUT_CHECKING_INTERVAL);
    timer.link(epoll_fd);

    init_rpc();

    AmEventDispatcher::instance()->addEventQueue(OPTIONS_PROBER_QUEUE, this);

    start();

    return 0;
}

void OptionsProber::onServerShutdown()
{
    DBG("shutdown SIP prober client");
}

void OptionsProber::addProberUnsafe(SipSingleProbe *p)
{
    probers_by_id.emplace(p->getId(), p);
    probers_by_tag.emplace(p->getTag(), p);

    AmEventDispatcher::instance()->addEventQueue(p->getTag(), this);

    DBG("added sip prober: %i %s",p->getId(), p->getName().data());
}

void OptionsProber::removeProberUnsafe(SipSingleProbe *p)
{
    DBG("remove sip prober: %i %s",p->getId(), p->getName().data());

    probers_by_id.erase(p->getId());
    probers_by_tag.erase(p->getTag());

    AmEventDispatcher::instance()->delEventQueue(p->getTag());

    delete p;
}

void OptionsProber::processCtlEvent(OptionsProberCtlEvent &e)
{
    switch(e.action) {
    case OptionsProberCtlEvent::Flush: {
        AmLock l(probers_mutex);
        while(!probers_by_id.empty()) {
            removeProberUnsafe(probers_by_id.begin()->second);
        }
        assert(probers_by_tag.empty());
        DBG("all probers flushed");
    } break; //SipProbesCtlEvent::Flush

    case OptionsProberCtlEvent::Add: {
        if(!isArgArray(e.probers_list)) {
            ERROR("expected probes array in the add event. got: %s",
                  AmArg::print(e.probers_list).data());
        }

        AmLock l(probers_mutex);

        for(size_t i = 0; i < e.probers_list.size(); i++) {
            auto &probe_arg = e.probers_list.get(i);
            auto p = new SipSingleProbe();
            if(!p->initFromAmArg(probe_arg)) {
                ERROR("failed to init prober %lu with data: %s",
                    i, AmArg::print(probe_arg).data());
                delete p;
                continue;
            }
            addProberUnsafe(p);
        }
    } break; //SipProbesCtlEvent::Add
    case OptionsProberCtlEvent::Remove: {
        if(!isArgArray(e.probers_list)) {
            ERROR("expected probes ids array in the remove event. got: %s",
                  AmArg::print(e.probers_list).data());
        }

        AmLock l(probers_mutex);
        for(size_t i = 0; i < e.probers_list.size(); i++) {
            AmArg &a = e.probers_list[i];
            if(!isArgInt(a)) {
                ERROR("expected integer arg as probe id. got: %s", AmArg::print(a).data());
                continue;
            }
            auto it = probers_by_id.find(a.asInt());
            if(it == probers_by_id.end()) {
                ERROR("no prober with id: %d", a.asInt());
                continue;
            }
            removeProberUnsafe(it->second);
        }

    } break; //SipProbesCtlEvent::Remove
    default:
        ERROR("got ctl event with unexpected action: %d", e.action);
    }
}

void OptionsProber::process(AmEvent* ev)
{
    if (ev->event_id == E_SYSTEM) {
        auto sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev) {
            DBG("received system event");
            if (sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
                stop_event.fire();
            }
            return;
        }
    }

    auto reply = dynamic_cast<AmSipReplyEvent*>(ev);
    if(reply) {
        onSipReplyEvent(reply);
        return;
    }

    auto ctl_event = dynamic_cast<OptionsProberCtlEvent*>(ev);
    if(ctl_event) {
        processCtlEvent(*ctl_event);
        return;
    }

    DBG("got unknown event. ignore");
}

void OptionsProber::onSipReplyEvent(AmSipReplyEvent* ev)
{
    AmLock l(probers_mutex);

    DBG("got reply with from tag: %s", ev->reply.from_tag.data());

    auto it = probers_by_tag.find(ev->reply.from_tag);
    if(it == probers_by_tag.end()) {
        DBG("no prober with tag: %s. ignore it", ev->reply.from_tag.data());
        return;
    }

    it->second->getDlg()->onRxReply(ev->reply);
}

void OptionsProber::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void OptionsProber::init_rpc_tree()
{
    AmArg &show = reg_leaf(root,"show");
        reg_method(show,"probers","",&OptionsProber::ShowProbers);
}

void OptionsProber::ShowProbers(const AmArg &args, AmArg &ret)
{
    ret.assertArray();
    AmLock l(probers_mutex);
    for(auto p: probers_by_id) {
        ret.push(AmArg());
        p.second->getInfo(ret.back());
    }
}

struct ProbersMetricGroup
  : public StatCountersGroupsInterface
{
    static vector<string> metrics_keys_names;
    static vector<string> metrics_help_strings;

    enum metric_keys_idx {
        PROBE_VALUE_LAST_REPLY_CODE = 0,
        PROBE_VALUE_MAX
    };
    struct reg_info {
        map<string, string> labels;
        unsigned long long values[PROBE_VALUE_MAX];
    };
    vector<reg_info> data;
    int idx;

    ProbersMetricGroup()
      : StatCountersGroupsInterface(Gauge)
    {}

    void add_reg(SipSingleProbe *p)
    {
        data.emplace_back();
        p->serializeStats(data.back().labels, data.back().values);
    }

    void serialize(StatsCountersGroupsContainerInterface::iterate_groups_callback_type callback)
    {
        for(int i = 0; i < PROBE_VALUE_MAX; i++) {
            idx = i;
            //setHelp(metrics_help_strings[idx]);
            callback(metrics_keys_names[idx], *this);
        }
    }

    void iterate_counters(iterate_counters_callback_type callback) override
    {
        for (size_t i = 0; i < data.size(); i++) {
            auto &reg = data[i];
            callback(reg.values[idx], 0, reg.labels);
        }
    }
};

vector<string> ProbersMetricGroup::metrics_keys_names = {
    "options_probe_last_reply_code",
};

/*vector<string> ProbersMetricGroup::metrics_help_strings = {
    ""
};*/

void OptionsProber::operator ()(const string &name, iterate_groups_callback_type callback)
{
    ProbersMetricGroup g;
    {
        AmLock l(probers_mutex);
        g.data.reserve(probers_by_id.size());
        for(const auto &p: probers_by_id) {
            g.add_reg(p.second);
        }
    }
    g.serialize(callback);
}
