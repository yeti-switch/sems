#include "OptionsProber.h"
#include "ampi/OptionsProberAPI.h"

#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "sip/parse_via.h"

#define MOD_NAME "options_prober"

#include <unistd.h>

#define CFG_OPT_NAME_EXPORT_METRICS               "export_metrics"
#define CFG_OPT_NAME_MIN_INTERVAL_MSEC            "min_interval_msec"
#define CFG_OPT_NAME_MIN_INTERVAL_PER_DOMAIN_MSEC "min_interval_per_domain_msec"
#define CFG_SEC_NAME_DOMAIN                       "domain"

#define DEFAULT_EXPIRES 1800

#define TIMEOUT_CHECKING_INTERVAL 1000000 // microseconds
#define EPOLL_MAX_EVENTS          2048

EXPORT_PLUGIN_CLASS_FACTORY(OptionsProber);
EXPORT_PLUGIN_CONF_FACTORY(OptionsProber);

OptionsProber *OptionsProber::instance()
{
    // we have to use new operator because of delete_plugin_factory in AmPlugin.cpp
    static auto _instance = new OptionsProber(MOD_NAME);
    // static SipProber _instance(MOD_NAME);
    return _instance;
}

AmDynInvoke *OptionsProber::getInstance()
{
    return instance();
}

OptionsProber::OptionsProber(const string &name)
    : AmDynInvokeFactory(MOD_NAME)
    , AmConfigFactory(MOD_NAME)
    , AmEventFdQueue(this)
    , min_interval_per_domain(0)
    , uac_auth_i(nullptr)
{
}

int OptionsProber::configure(const std::string &config)
{
    cfg_opt_t domain_opt[] = { CFG_INT(CFG_OPT_NAME_MIN_INTERVAL_MSEC, 0, CFGF_NODEFAULT), CFG_END() };
    cfg_opt_t opt[]        = { CFG_BOOL(CFG_OPT_NAME_EXPORT_METRICS, cfg_false, CFGF_NONE),
                               CFG_SEC(CFG_SEC_NAME_DOMAIN, domain_opt, CFGF_TITLE | CFGF_MULTI),
                               CFG_INT(CFG_OPT_NAME_MIN_INTERVAL_PER_DOMAIN_MSEC, 0, CFGF_NODEFAULT),
                               CFG_INT(CFG_OPT_NAME_MIN_INTERVAL_MSEC, 0, CFGF_NODEFAULT), CFG_END() };
    cfg_t    *cfg          = cfg_init(opt, CFGF_NONE);
    if (!cfg)
        return -1;
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

    if (cfg_size(cfg, CFG_OPT_NAME_MIN_INTERVAL_MSEC)) {
        int i = cfg_getint(cfg, CFG_OPT_NAME_MIN_INTERVAL_MSEC);
        if (i) {
            DBG("set shaper global min interval to %dmsec", i);
            shaper.set_min_interval(i);
        }
    }
    if (cfg_size(cfg, CFG_OPT_NAME_MIN_INTERVAL_PER_DOMAIN_MSEC)) {
        int i = cfg_getint(cfg, CFG_OPT_NAME_MIN_INTERVAL_PER_DOMAIN_MSEC);
        if (i) {
            DBG("set shaper min interval per domain to %dmsec", i);
            min_interval_per_domain = i;
        }
    }
    for (int i = 0; i < cfg_size(cfg, CFG_SEC_NAME_DOMAIN); i++) {
        cfg_t *domain = cfg_getnsec(cfg, CFG_SEC_NAME_DOMAIN, i);
        domain_intervals.emplace(domain->title, cfg_getint(domain, CFG_OPT_NAME_MIN_INTERVAL_MSEC));
    }
    if (cfg_true == cfg_getbool(cfg, CFG_OPT_NAME_EXPORT_METRICS))
        statistics::instance()->add_groups_container("options_prober", this, false);

    cfg_free(cfg);
    return 0;
}

int OptionsProber::reconfigure(const std::string &config)
{
    domain_intervals.clear();
    return configure(config);
}

void OptionsProber::run()
{
    int ret;

    setThreadName("options-prober");

    AmDynInvokeFactory *uac_auth_f = AmPlugIn::instance()->getFactory4Di("uac_auth");
    if (uac_auth_f == nullptr) {
        WARN("unable to get a uac_auth factory. probers will not be able to authenticate");
    } else {
        uac_auth_i = uac_auth_f->getInstance();
    }

    bool               running = true;
    struct epoll_event events[EPOLL_MAX_EVENTS];
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if (ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s", strerror(errno));
        }

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int                 f = e.data.fd;

            if (!(e.events & EPOLLIN)) {
                continue;
            }

            if (f == timer) {
                checkTimeouts();
                timer.read();
            } else if (f == postponed_timer) {
                checkPostponed();
                postponed_timer.read();
            } else if (f == -queue_fd()) {
                clear_pending();
                processEvents();
            } else if (f == stop_event) {
                stop_event.read();
                running = false;
                break;
            }
        }
    } while (running);

    AmEventDispatcher::instance()->delEventQueue(OPTIONS_PROBER_QUEUE);
    epoll_unlink(epoll_fd);
    close(epoll_fd);

    onServerShutdown();
}

void OptionsProber::checkTimeouts()
{
    // DBG("check timeouts");
    SipSingleProbe::timep    now(std::chrono::system_clock::now());
    bool                     is_postponed_req_exists = false;
    vector<SipSingleProbe *> probers_to_remove;

    AmLock l(probers_mutex);
    for (auto &p : probers_by_id) {
        if (p.second->postponed) {
            // ignore postponed: it will be handled in checkPostponed()
        } else if (p.second->needProcess(now) && processWithShaper(p.second, now)) {
            probers_to_remove.push_back(p.second);
        }
        is_postponed_req_exists = is_postponed_req_exists || p.second->postponed;
    }

    for (auto &p : probers_to_remove) {
        removeProberUnsafe(p);
    }

    // reset postponed_timer if needed
    if (is_postponed_req_exists) {
        if (postponed_timer.is_active() == false) {
            postponed_timer.set(shaper.get_postponed_timer_interval_ms() * 1000);
        }
    } else {
        if (postponed_timer.is_active()) {
            postponed_timer.set(0, false);
        }
    }
}

int OptionsProber::onLoad()
{
    if ((epoll_fd = epoll_create(3)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd);
    stop_event.link(epoll_fd);

    timer.set(TIMEOUT_CHECKING_INTERVAL);
    timer.link(epoll_fd);
    postponed_timer.set(0, false);
    postponed_timer.link(epoll_fd);

    init_rpc();

    AmEventDispatcher::instance()->addEventQueue(OPTIONS_PROBER_QUEUE, this);

    start();

    return 0;
}

void OptionsProber::onServerShutdown()
{
    DBG3("shutdown SIP prober client");
}

void OptionsProber::addProberUnsafe(SipSingleProbe *p)
{
    probers_by_id.emplace(p->getId(), p);
    probers_by_tag.emplace(p->getTag(), p);

    AmEventDispatcher::instance()->addEventQueue(p->getTag(), this);

    DBG("added sip prober: %i %s", p->getId(), p->getName().data());
}

void OptionsProber::removeProberUnsafe(SipSingleProbe *p)
{
    DBG("remove sip prober: %i %s", p->getId(), p->getName().data());

    probers_by_id.erase(p->getId());
    probers_by_tag.erase(p->getTag());

    AmEventDispatcher::instance()->delEventQueue(p->getTag());

    delete p;
}

void OptionsProber::processCtlEvent(OptionsProberCtlEvent &e)
{
    switch (e.action) {
    case OptionsProberCtlEvent::Flush:
    {
        AmLock l(probers_mutex);
        while (!probers_by_id.empty()) {
            removeProberUnsafe(probers_by_id.begin()->second);
        }
        assert(probers_by_tag.empty());
        DBG("all probers flushed");
    } break; // SipProbesCtlEvent::Flush

    case OptionsProberCtlEvent::Add:
    {
        if (!isArgArray(e.probers_list)) {
            ERROR("expected probes array in the add event. got: %s", AmArg::print(e.probers_list).data());
        }

        AmLock l(probers_mutex);

        for (size_t i = 0; i < e.probers_list.size(); i++) {
            auto &probe_arg = e.probers_list.get(i);
            auto  p         = new SipSingleProbe();
            if (!p->initFromAmArg(probe_arg)) {
                ERROR("failed to init prober %lu with data: %s", i, AmArg::print(probe_arg).data());
                delete p;
                continue;
            }
            uint32_t interval  = min_interval_per_domain;
            auto     domain_it = domain_intervals.find(p->ruri_domain);
            if (domain_it != domain_intervals.end())
                interval = domain_it->second;
            if (interval)
                shaper.set_key_min_interval(p->ruri_domain, interval);
            addProberUnsafe(p);
        }
    } break; // SipProbesCtlEvent::Add
    case OptionsProberCtlEvent::Remove:
    {
        if (!isArgArray(e.probers_list)) {
            ERROR("expected probes ids array in the remove event. got: %s", AmArg::print(e.probers_list).data());
        }

        AmLock l(probers_mutex);
        for (size_t i = 0; i < e.probers_list.size(); i++) {
            AmArg &a = e.probers_list[i];
            if (!isArgInt(a)) {
                ERROR("expected integer arg as probe id. got: %s", AmArg::print(a).data());
                continue;
            }
            auto it = probers_by_id.find(a.asInt());
            if (it == probers_by_id.end()) {
                ERROR("no prober with id: %d", a.asInt());
                continue;
            }
            removeProberUnsafe(it->second);
        }

    } break; // SipProbesCtlEvent::Remove
    default: ERROR("got ctl event with unexpected action: %d", e.action);
    }
}

void OptionsProber::checkPostponed()
{
    RequestShaper::timep     now_point(std::chrono::system_clock::now());
    vector<SipSingleProbe *> probers_to_remove;

    AmLock l(probers_mutex);
    for (auto &p : probers_by_id) {
        if (!p.second->postponed || now_point < p.second->postponed_next_attempt)
            continue;

        DBG("%s(%u) postponing timeout. Do OPTIONS.", p.second->getTag().c_str(), p.second->getId());

        p.second->postponed = false;

        if (p.second->process(now_point)) {
            probers_to_remove.push_back(p.second);
        }
    }
    for (auto &p : probers_to_remove) {
        removeProberUnsafe(p);
    }
}

bool OptionsProber::processWithShaper(SipSingleProbe *p, SipSingleProbe::timep now)
{
    if (shaper.check_rate_limit(p->ruri_domain, now, p->postponed_next_attempt)) {
        DBG("%s(%u): rate limit reached for %s. postpone sending request", p->getTag().c_str(), p->getId(),
            p->ruri_domain.c_str());
        p->postponed = true;
        return false;
    }

    return p->process(now);
}

void OptionsProber::process(AmEvent *ev)
{
    if (ev->event_id == E_SYSTEM) {
        auto sys_ev = dynamic_cast<AmSystemEvent *>(ev);
        if (sys_ev) {
            DBG3("received system event");
            if (sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
                stop_event.fire();
            }
            return;
        }
    }

    auto reply = dynamic_cast<AmSipReplyEvent *>(ev);
    if (reply) {
        onSipReplyEvent(reply);
        return;
    }

    auto ctl_event = dynamic_cast<OptionsProberCtlEvent *>(ev);
    if (ctl_event) {
        processCtlEvent(*ctl_event);
        return;
    }

    DBG("got unknown event. ignore");
}

void OptionsProber::onSipReplyEvent(AmSipReplyEvent *ev)
{
    AmLock l(probers_mutex);

    DBG("got reply with from tag: %s", ev->reply.from_tag.data());

    auto it = probers_by_tag.find(ev->reply.from_tag);
    if (it == probers_by_tag.end()) {
        DBG("no prober with tag: %s. ignore it", ev->reply.from_tag.data());
        return;
    }

    it->second->getDlg()->onRxReply(ev->reply);
}

void OptionsProber::on_stop()
{
    stop_event.fire();
    join();
}

void OptionsProber::init_rpc_tree()
{
    auto &show = reg_leaf(root, "show");
    reg_method(show, "probers", "", "", &OptionsProber::ShowProbers, this);
}

void OptionsProber::ShowProbers(const AmArg &args, AmArg &ret)
{
    ret.assertArray();
    AmLock               l(probers_mutex);
    RequestShaper::timep now(std::chrono::system_clock::now());
    if (isArgArray(args) && args.size()) {
        // show probers from id list
        for (size_t i = 0; i < args.size(); i++) {
            if (!isArgInt(args[i]))
                continue;
            auto p = probers_by_id.find(args[i].asInt());
            if (p == probers_by_id.end())
                continue;
            ret.push(AmArg());
            p->second->getInfo(ret.back(), now);
        }
    } else {
        // show all probers
        for (auto p : probers_by_id) {
            ret.push(AmArg());
            p.second->getInfo(ret.back(), now);
        }
    }
}

void OptionsProber::operator()(const string &name, iterate_groups_callback_type callback)
{
    ProbersMetricGroup g;
    {
        AmLock l(probers_mutex);
        g.data.reserve(probers_by_id.size());
        for (const auto &p : probers_by_id) {
            g.add_reg(p.second);
        }
    }
    g.serialize(callback);
}
