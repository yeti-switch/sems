#include "IdentityValidator.h"
#include "log.h"
#include "format_helper.h"

#include <AmEventDispatcher.h>

#include <botan/x509path.h>
#include <botan/x509_ext.h>

#include <unordered_set>
using std::unordered_set;

#define EPOLL_MAX_EVENTS 2048

#define session_container      AmSessionContainer::instance()
#define identity_validator_app IdentityValidator::instance()
#define event_dispatcher       AmEventDispatcher::instance()

const string pg_worker         = "identity_validator";
const string trusted_certs_key = "trusted_certs";
const string trusted_repos_key = "trusted_repos";
const string crl_token_prefix  = "crl:";

enum RpcMethodId { ValidateIdentity, CheckCertificate };

static string bytes2HexStr(const std::vector<uint8_t> &bytes)
{
    auto res = Botan::hex_encode(bytes);
    return string(res.begin(), res.end());
}

/* IdentityValidatorEntry */

void IdentityValidatorEntry::getInfo(AmArg &a, const std::chrono::system_clock::time_point &now) const
{
    a["state"] = IdentityValidatorEntry::to_string(state);

    if (state == LOADING)
        return;

    a["ttl"]        = std::chrono::duration_cast<std::chrono::seconds>(expire_time - now).count();
    a["error_str"]  = error_str;
    a["error_code"] = error_code;
    a["error_type"] = error_type ? Botan::to_string((Botan::ErrorType)error_type) : "";
    a["state"]      = IdentityValidatorEntry::to_string(state);

    a["valid"]             = validation_sucessfull;
    a["validation_result"] = validation_result;
    a["trust_root"]        = trust_root_cert;

    auto &cert_chain_amarg = a["cert_chain"];
    cert_chain_amarg.assertArray();
    for (const auto &cert : cert_chain) {
        cert_chain_amarg.push(AmArg());
        IdentityValidator::serializeCert2AmArg(cert, cert_chain_amarg.back());
    }
}

/* CrlEntry */

void CrlEntry::getInfo(AmArg &a, const std::chrono::system_clock::time_point &now) const
{
    a["state"] = CrlEntry::to_string(state);

    if (state == LOADING)
        return;

    a["ttl"]        = std::chrono::duration_cast<std::chrono::seconds>(expire_time - now).count();
    a["idle"]       = std::chrono::duration_cast<std::chrono::seconds>(now - last_use_time).count();
    a["error_str"]  = error_str;
    a["error_code"] = error_code;
    a["error_type"] = error_type ? Botan::to_string((Botan::ErrorType)error_type) : "";
    a["state"]      = CrlEntry::to_string(state);

    a["valid"]             = validation_sucessfull;
    a["validation_result"] = validation_result;
    a["trust_root"]        = trust_root_cert;

    auto &crl_amarg = a["crl"];
    crl_amarg.assertArray();
    if (crl) {
        crl_amarg.push(AmArg());
        IdentityValidator::serializeCrl2AmArg(*crl, crl_amarg.back());
    }
}

bool CrlEntry::isRevoked(const Botan::X509_Certificate &cert)
{
    if (!validation_sucessfull)
        return false;
    last_use_time = std::chrono::system_clock::now();
    return crl->is_revoked(cert);
}

/* Statistics */

IdentityValidator::Counters::Counters()
    : identity_success(stat_group(Counter, MOD_NAME, "identity_headers_success").addAtomicCounter())
    , identity_failed_parse(stat_group(Counter, MOD_NAME, "identity_headers_failed")
                                .addAtomicCounter()
                                .addLabel("reason", "parse_failed"))
    , identity_failed_verify_expired(
          stat_group(Counter, MOD_NAME, "identity_headers_failed").addAtomicCounter().addLabel("reason", "iat_expired"))
    , identity_failed_verify_signature(stat_group(Counter, MOD_NAME, "identity_headers_failed")
                                           .addAtomicCounter()
                                           .addLabel("reason", "wrong_signature"))
    , identity_failed_x5u_not_trusted(stat_group(Counter, MOD_NAME, "identity_headers_failed")
                                          .addAtomicCounter()
                                          .addLabel("reason", "x5u_not_trusted"))
    , identity_failed_cert_invalid(stat_group(Counter, MOD_NAME, "identity_headers_failed")
                                       .addAtomicCounter()
                                       .addLabel("reason", "cert_invalid"))
    , identity_failed_cert_not_available(stat_group(Counter, MOD_NAME, "identity_headers_failed")
                                             .addAtomicCounter()
                                             .addLabel("reason", "cert_not_available"))
{
}

/* PGPoolCfg */

void IdentityValidator::PGPoolCfg::parse(cfg_t *cfg)
{
    host               = cfg_getstr(cfg, CFG_PARAM_HOST);
    port               = cfg_getint(cfg, CFG_PARAM_PORT);
    name               = cfg_getstr(cfg, CFG_PARAM_NAME);
    user               = cfg_getstr(cfg, CFG_PARAM_USER);
    pass               = cfg_getstr(cfg, CFG_PARAM_PASS);
    statement_timeout  = cfg_getint(cfg, CFG_PARAM_STATEMENT_TIMEOUT);
    keepalive_interval = cfg_getint(cfg, CFG_PARAM_KEEPALIVE_INTERVAL);
}

bool IdentityValidator::PGPoolCfg::create_pg_pool_worker(PGWorkerPoolCreate::PoolType type)
{
    PGPool pg_pool(host, port, name, user, pass);
    pg_pool.pool_size           = 1;
    pg_pool.keepalives_interval = keepalive_interval;

    return event_dispatcher->post(POSTGRESQL_QUEUE, new PGWorkerPoolCreate(pg_worker, type, pg_pool));
}

/* IdentityValidatorFactory */

class IdentityValidatorFactory : public AmConfigFactory, public AmDynInvokeFactory {
  private:
    IdentityValidatorFactory(const string &name)
        : AmConfigFactory(name)
        , AmDynInvokeFactory(name)
    {
        identity_validator_app;
    }
    ~IdentityValidatorFactory() { IdentityValidator::dispose(); }

  public:
    DECLARE_FACTORY_INSTANCE(IdentityValidatorFactory)

    AmDynInvoke *getInstance() { return identity_validator_app; }

    int  onLoad() { return identity_validator_app->onLoad(); }
    void on_destroy() { identity_validator_app->stop(); }

    /* AmConfigFactory */
    int configure(const string &config) { return IdentityValidatorConfig::parse(config, identity_validator_app); }
    int reconfigure(const string &config) { return configure(config); }
};

EXPORT_PLUGIN_CLASS_FACTORY(IdentityValidatorFactory)
EXPORT_PLUGIN_CONF_FACTORY(IdentityValidatorFactory)
DEFINE_FACTORY_INSTANCE(IdentityValidatorFactory, MOD_NAME)

/* IdentityValidator */

IdentityValidator *IdentityValidator::_instance = NULL;

IdentityValidator *IdentityValidator::instance()
{
    if (_instance == nullptr)
        _instance = new IdentityValidator();

    return _instance;
}

void IdentityValidator::dispose()
{
    if (_instance != nullptr)
        delete _instance;

    _instance = nullptr;
}

IdentityValidator::IdentityValidator()
    : AmEventFdQueue(this)
    , epoll_fd(-1)
    , name("identity")
    , queue_name(IDENTITY_VALIDATOR_APP_QUEUE)
{
    event_dispatcher->addEventQueue(queue_name, this);
}

IdentityValidator::~IdentityValidator()
{
    CLASS_DBG("IdentityValidator::~IdentityValidator()");
    event_dispatcher->delEventQueue(queue_name);
}

int IdentityValidator::init()
{
    if ((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    stop_event.link(epoll_fd, true);
    epoll_link(epoll_fd, true);

    init_rpc();

    each_second_timer.link(epoll_fd);
    each_second_timer.set(1e6 /* 1 second */, true);

    return 0;
}

int IdentityValidator::onLoad()
{
    if (init()) {
        ERROR("initialization error");
        return -1;
    }
    start();

    // create master worker pool
    if (!db_cfg.create_pg_pool_worker(PGWorkerPoolCreate::Master)) {
        ERROR("missed required postgresql module");
        return -1;
    }

    // configure master worker pool
    PGWorkerConfig *pg_config = new PGWorkerConfig(pg_worker,                /* name */
                                                   false,                    /* failover_to_slave */
                                                   false,                    /* retransmit_enable */
                                                   false,                    /* use pipeline */
                                                   db_cfg.statement_timeout, /* transaction timeout */
                                                   0,                        /* retransmit_interval */
                                                   0 /* reconnect_interval */);

    if (!schema.empty())
        pg_config->addSearchPath(schema);

    event_dispatcher->post(POSTGRESQL_QUEUE, pg_config);
    return 0;
}

void IdentityValidator::run()
{
    int                ret;
    void              *p;
    bool               running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName(name);

    DBG("start async '%s'", name);

    auto self_queue_ptr = dynamic_cast<AmEventFdQueue *>(this);
    running             = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if (ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s", strerror(errno));
        }

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p                     = e.data.ptr;
            if (p == &stop_event) {
                stop_event.read();
                running = false;
                break;
            } else if (p == self_queue_ptr) {
                processEvents();
            } else {
                if (!p) {
                    CLASS_ERROR("got event on null async_context. ignore");
                    continue;
                }
            }

            if (e.data.fd == each_second_timer) {
                const auto now(std::chrono::system_clock::now());
                onTimer(now);
                each_second_timer.read();
            }
        }
    } while (running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("async '%s' stopped", name);
}

void IdentityValidator::on_stop()
{
    stop_event.fire();
    join();
}

void IdentityValidator::onTimer(const std::chrono::system_clock::time_point &now)
{
    std::unique_lock lock(certificates_mutex);

    auto it = certificates.begin();
    while (it != certificates.end()) {
        if (it->second.state == IdentityValidatorEntry::LOADING) {
            it++;
            continue;
        }
        if (isTrustedRepository(it->first)) {
            if (now > it->second.expire_time) {
                renewCertEntry(*it);
            }
            it++;
        } else {
            it = certificates.erase(it);
        }
    }

    if (crl_processing) {
        auto it = crls.begin();
        while (it != crls.end()) {
            if (it->second.state == CrlEntry::LOADING) {
                it++;
                continue;
            }

            if (now - it->second.last_use_time > crl_cache_idle_timeout) {
                it = crls.erase(it);
                continue;
            }

            if (now > it->second.expire_time) {
                renewCrl(it->first);
            }
            it++;
        }
    }
}

/* AmEventHandler */

void IdentityValidator::process(AmEvent *event)
{
    switch (event->event_id) {
    case E_SYSTEM:
    {
        AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(event);
        if (sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
            stop_event.fire();
            return;
        }
        break;
    }
    }

    /* handle IdentityValidatorRequest */

    switch (event->event_id) {
    case IdentityValidatorRequest::LoadTrustedCerts:
        if (dynamic_cast<LoadTrustedCertsRequest *>(event) != nullptr) {
            postDbQuery(trusted_certs_req, trusted_certs_key);
            return;
        }
        break;

    case IdentityValidatorRequest::LoadTrustedRepos:
        if (dynamic_cast<LoadTrustedReposRequest *>(event) != nullptr) {
            postDbQuery(trusted_repos_req, trusted_repos_key);
            return;
        }
        break;

    case IdentityValidatorRequest::ValidateIdentities:
        if (auto *e = dynamic_cast<ValidateIdentitiesRequest *>(event)) {
            addIdentities(e->identities, e->session_id);
            return;
        }
        break;
    }

    /* handle HttpGetResponseEvent */

    if (auto *e = dynamic_cast<HttpGetResponseEvent *>(event)) {
        processHttpReply(*e);
        return;
    }

    /* handle PGResponse */

    if (auto *e = dynamic_cast<PGResponse *>(event)) {
        if (e->token == trusted_certs_key) {
            reloadTrustedCertificates(e->result);
        } else if (e->token == trusted_repos_key) {
            reloadTrustedRepositories(e->result);
        }
        return;
    }

    /* handle JsonRpcRequestEvent */

    if (auto *e = dynamic_cast<JsonRpcRequestEvent *>(event)) {
        processJsonRpcRequestEvent(e);
        return;
    }
}

void IdentityValidator::reloadTrustedCertificates(const AmArg &data)
{
    std::unique_lock lock(certificates_mutex);

    trusted_certs.clear();
    if (!isArgArray(data))
        return;
    for (size_t i = 0; i < data.size(); i++) {
        AmArg &a = data[i];
        trusted_certs.emplace_back(a["id"].asInt(), a["name"].asCStr());
        auto  &cert_entry = trusted_certs.back();
        string cert_data  = a["certificate"].asCStr();
        // split and parse certificates
        Botan::DataSource_Memory in(cert_data);
        while (!in.end_of_data()) {
            try {
                cert_entry.certs.emplace_back(new Botan::X509_Certificate(in));
                trusted_certs_store.add_certificate(*cert_entry.certs.back().get());
            } catch (Botan::Exception &e) {
                ERROR("IdentityValidator trusted entry %lu '%s' Botan::exception: %s", cert_entry.id,
                      cert_entry.name.data(), e.what());
            }
        }
    }
}

void IdentityValidator::reloadTrustedRepositories(const AmArg &data)
{
    std::unique_lock lock(certificates_mutex);

    trusted_repositories.clear();
    if (!isArgArray(data))
        return;
    for (size_t i = 0; i < data.size(); i++) {
        AmArg &a = data[i];
        try {
            trusted_repositories.emplace_back(a["id"].asInt(), a["url_pattern"].asCStr(),
                                              a["validate_https_certificate"].asBool());
        } catch (std::regex_error &e) {
            ERROR("IdentityValidator row regex_error: %s", e.what());
        }
    }
}

void IdentityValidator::addIdentities(const vector<string> &value, const string &id, const string &rpc_conn_id)
{
    auto *ctx = new SessionCtx(id, rpc_conn_id);

    for (auto &e : value) {
        auto &ident_entry = ctx->identities.emplace_back(new IdentityEntry(e));

        // parse
        ident_entry->isParsed = ident_entry->identity.parse(e);
        if (!ident_entry->isParsed) {
            counters.identity_failed_parse.inc();
            string last_error;
            auto   last_errcode = ident_entry->identity.get_last_error(last_error);
            ERROR("[%s] failed to parse identity header: '%s', error:%d(%s)", ctx->id.data(), ident_entry->value.data(),
                  last_errcode, last_error.data());
            continue;
        }

        auto &cert_url = ident_entry->identity.get_x5u_url();
        if (cert_url.empty()) {
            counters.identity_failed_parse.inc();
            ERROR("[%s] empty x5u in identity header: '%s'", ctx->id.data(), ident_entry->value.data());
            continue;
        }

        // check is trusted
        if (!isTrustedRepository(cert_url)) {
            DBG("cert for '%s' not trusted", cert_url.data());

            // remove cached entries from non-trusted repositories
            std::unique_lock lock(certificates_mutex);
            auto             cert_it = certificates.find(cert_url);
            if (cert_it != certificates.end() && cert_it->second.state != IdentityValidatorEntry::LOADING) {
                certificates.erase(cert_it);
            }

            continue;
        }

        // find cert and renew if need
        {
            std::unique_lock lock(certificates_mutex);
            auto             cert_it = certificates.find(cert_url);
            if (cert_it == certificates.end()) {
                auto  ret        = certificates.emplace(cert_url, IdentityValidatorEntry{});
                auto &cert_entry = ret.first;

                cert_entry->second.defer_sessions.emplace(ctx);
                ident_entry->isWaitedForCert = true;
                DBG("wait for '%s' cert", cert_url.data());
                renewCertEntry(*cert_entry);
                continue;
            }

            DBG("cert for '%s' has already in cache", cert_url.data());

            if (cert_it->second.state == IdentityValidatorEntry::LOADING) {
                cert_it->second.defer_sessions.emplace(ctx);
                ident_entry->isWaitedForCert = true;
                DBG("wait for '%s' cert", cert_url.data());
                continue;
            }
        }
    }

    if (ctx->isReady()) {
        postResult(ctx);
        delete ctx;
        ctx = nullptr;
    }
}

optional<string> IdentityValidator::crlUrl(const Botan::X509_Certificate &cert)
{
    // is crl distribution points exist
    auto crl_dps = cert.crl_distribution_points();
    if (crl_dps.empty())
        return std::nullopt;

    // parse crl distribution points
    vector<string> parsed_crl_dps;
    IdentityValidator::parse_crl_dist_points(crl_dps, parsed_crl_dps);
    if (parsed_crl_dps.empty())
        return std::nullopt;

    return parsed_crl_dps.front();
}

void IdentityValidator::renewCrl(const string &url, const string &defer_cert_url)
{
    bool res = session_container->postEvent(HTTP_EVENT_QUEUE,
                                            new HttpGetEvent(http_destination,               // destination
                                                             url,                            // url
                                                             crl_token_prefix + url,         // token
                                                             IDENTITY_VALIDATOR_APP_QUEUE)); // session_id

    auto it = crls.find(url);
    if (it == crls.end())
        it = crls.emplace(url, CrlEntry{}).first;

    it->second.reset();

    if (res) {
        if (!defer_cert_url.empty())
            it->second.defer_cert_urls.emplace_back(defer_cert_url);
    } else {
        it->second.state = CrlEntry::UNAVAILABLE;
    }
}

void IdentityValidator::onCertRevoked(IdentityValidatorEntry &cert_entry, const string &cert_url,
                                      const string &subject_dn)
{
    DBG("cert '%s' is revoked in chain '%s'", subject_dn.c_str(), cert_url.c_str());
    cert_entry.state                 = IdentityValidatorEntry::REVOKED;
    cert_entry.validation_sucessfull = false;
    cert_entry.validation_result     = format("Certificate {} is revoked", subject_dn);
    cert_entry.expire_time           = std::chrono::system_clock::now() + identity_validator_failed_verify_ttl;
}

void IdentityValidator::validateCrl(CrlEntry &crl_entry)
{
    if (!crl_entry.crl)
        return;

    crl_entry.validation_result.clear();
    crl_entry.validation_sucessfull = false;
    crl_entry.trust_root_cert.clear();

    // check this_update
    auto &this_updatet = crl_entry.crl->this_update();
    if (this_updatet.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) >= 0) {
        crl_entry.validation_result = "incorrect this_update";
        return;
    }

    // check next_update
    auto &next_update = crl_entry.crl->next_update();
    if (next_update.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) <= 0) {
        crl_entry.validation_result = "expired by next_update";
        return;
    }

    // validate
    if (auto ca_cert = trusted_certs_store.find_cert(crl_entry.crl->issuer_dn(), {})) {
        if (auto pub_key = ca_cert->subject_public_key()) {
            crl_entry.validation_sucessfull = crl_entry.crl->check_signature(*pub_key);
            crl_entry.trust_root_cert       = ca_cert->subject_dn().to_string();

            if (!crl_entry.validation_sucessfull) {
                crl_entry.validation_result = "signature verification failed";
            }
        } else {
            crl_entry.validation_result = "trusted cert's public key is unavailable";
        }
    } else {
        crl_entry.validation_result = "trusted cert is unavailable";
    }
}

void IdentityValidator::processCrl(const string &crl_url, const string &data)
{
    DBG("processCrl '%s'", crl_url.c_str());

    auto it = crls.find(crl_url);
    if (it == crls.end()) {
        ERROR("processCrl: absent crl entry %s", crl_url.c_str());
        return;
    }

    auto &crl_entry = it->second;

    // store
    try {
        Botan::DataSource_Memory src(data);
        crl_entry.crl.reset(new Botan::X509_CRL(src));
        crl_entry.state = CrlEntry::LOADED;
    } catch (const Botan::Exception &e) {
        DBG("store crl error: '%s', code: %d, type %d", e.what(), e.error_code(), e.error_type());
        crl_entry.state      = CrlEntry::UNAVAILABLE;
        crl_entry.error_str  = e.what();
        crl_entry.error_code = e.error_code();
        crl_entry.error_type = (int)e.error_type();
    }

    if (crl_entry.state == CrlEntry::LOADED)
        validateCrl(crl_entry);

    crl_entry.last_use_time = std::chrono::system_clock::now();
    crl_entry.expire_time   = crl_entry.last_use_time + crl_cache_renew_timeout;

    for (auto cert_url : crl_entry.defer_cert_urls) {
        auto it = certificates.find(cert_url);
        if (it == certificates.end())
            continue;

        auto &cert_entry    = it->second;
        bool  wait_for_crls = false;

        // check each certificate in the chain: is it revoked
        // if CRL is not loaded set flag wait_for_crls to true
        for (auto &cert : cert_entry.cert_chain) {
            auto cert_crl_url = crlUrl(cert);
            if (!cert_crl_url)
                continue;

            if (cert_crl_url == crl_url) {
                if (crl_entry.state == CrlEntry::LOADED) {
                    if (crl_entry.isRevoked(cert)) {
                        onCertRevoked(cert_entry, cert_url, cert.subject_dn().to_string());
                        wait_for_crls = false;
                        break;
                    }

                    DBG("cert '%s' is good in chain '%s'", cert.subject_dn().to_string().c_str(), cert_url.c_str());
                }

                continue;
            }

            // check is need to wait for other CRLs
            if (wait_for_crls == false) {
                auto it       = crls.find(cert_crl_url.value());
                wait_for_crls = (it != crls.end() && it->second.state == CrlEntry::LOADING);
            }
        }

        if (wait_for_crls == false)
            postResult(cert_entry, cert_url);
    }

    crl_entry.defer_cert_urls.clear();
}

void IdentityValidator::processHttpReply(const HttpGetResponseEvent &resp)
{
    std::unique_lock lock(certificates_mutex);

    if (crl_processing) {
        if (resp.token.starts_with(crl_token_prefix)) {
            const string crl_url = resp.token.substr(crl_token_prefix.length());
            processCrl(crl_url, resp.data);
            return;
        }
    }

    const string &cert_url = resp.token;
    auto          cert_it  = certificates.find(cert_url);
    if (cert_it == certificates.end()) {
        ERROR("processHttpReply: absent cache entry %s", cert_url.c_str());
        return;
    }

    auto &cert_entry = cert_it->second;

    try {
        // fill cert_chain and check "not_after" expiration time for each cert
        Botan::DataSource_Memory in(resp.data);
        while (!in.end_of_data()) {
            try {
                cert_entry.cert_chain.emplace_back(in);
                auto &t = cert_entry.cert_chain.back().not_after();
                if (t.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) < 0)
                    throw Botan::Exception("certificate expired");
            } catch (...) {
                // ignore additional certs parsing exceptions
                if (cert_entry.cert_chain.empty())
                    throw;
            }
        }

        // validation
        static Botan::Path_Validation_Restrictions restrictions;
        auto validation_result = Botan::x509_path_validate(cert_entry.cert_chain, restrictions, trusted_certs_store);
        cert_entry.validation_sucessfull = validation_result.successful_validation();
        cert_entry.validation_result     = validation_result.result_string();
        if (cert_entry.validation_sucessfull) {
            cert_entry.trust_root_cert = validation_result.trust_root().subject_dn().to_string();
        }

        if (cert_entry.cert_chain.size())
            cert_entry.state = IdentityValidatorEntry::LOADED;

    } catch (const Botan::Exception &e) {
        cert_entry.state      = IdentityValidatorEntry::UNAVAILABLE;
        cert_entry.error_str  = e.what();
        cert_entry.error_code = e.error_code();
        cert_entry.error_type = (int)e.error_type();
    }

    unordered_set<string> crl_urls_for_renew{};

    if (cert_entry.state == IdentityValidatorEntry::LOADED) {
        if (cert_entry.validation_sucessfull) {
            cert_entry.expire_time = std::chrono::system_clock::now() + identity_validator_ttl;

            if (crl_processing) {
                // check each certificate in the chain: is it revoked
                // if CRL is not loaded fill crl urls for renew
                for (auto &cert : cert_entry.cert_chain) {
                    auto crl_url = crlUrl(cert);
                    if (!crl_url)
                        continue;

                    auto it = crls.find(*crl_url);
                    if (it != crls.end()) {
                        auto &crl_entry = it->second;
                        if (crl_entry.state == CrlEntry::LOADED) {
                            if (crl_entry.isRevoked(cert)) {
                                onCertRevoked(cert_entry, cert_url, cert.subject_dn().to_string());
                                crl_urls_for_renew.clear();
                                break;
                            }

                            DBG("cert '%s' is good in chain '%s'", cert.subject_dn().to_string().c_str(),
                                cert_url.c_str());
                        }
                    } else {
                        crl_urls_for_renew.emplace(std::move(*crl_url));
                        std::exchange(crl_url, std::nullopt);
                    }
                }
            }
        } else {
            cert_entry.expire_time = std::chrono::system_clock::now() + identity_validator_failed_verify_ttl;
        }
    } else {
        cert_entry.expire_time = std::chrono::system_clock::now() + identity_validator_failed_ttl;
    }

    if (crl_processing && !crl_urls_for_renew.empty()) {
        // renew CRLs
        for (auto &url : crl_urls_for_renew)
            renewCrl(url, cert_url);

        return;
    }

    postResult(cert_entry, cert_url);
}

void IdentityValidator::processJsonRpcRequestEvent(JsonRpcRequestEvent *ev)
{
    AmArg ret;
    switch (ev->method_id) {
    case RpcMethodId::ValidateIdentity: handleValidateIdentityRpcRequest(ev); break;
    case RpcMethodId::CheckCertificate: handleCheckCertificateRpcRequest(ev); break;
    }
}

void IdentityValidator::handleValidateIdentityRpcRequest(JsonRpcRequestEvent *ev)
{
    auto &params = ev->params;

    try {
        params.assertArray();
    } catch (...) {
        AmArg ret;
        ret["message"] = "invalid argument";
        ret["code"]    = 500;
        postJsonRpcReply(*ev, ret, true);
        return;
    }

    if (params.size() == 0) {
        AmArg ret;
        ret["message"] = "empty arguments";
        ret["code"]    = 500;
        postJsonRpcReply(*ev, ret, true);
        return;
    }

    vector<string> idents{};
    for (unsigned int i = 0; i < params.size(); ++i) {
        idents.emplace_back(params[i].asCStr());
    }

    addIdentities(idents, ev->id.asCStr(), ev->connection_id);
}

void IdentityValidator::handleCheckCertificateRpcRequest(JsonRpcRequestEvent *ev)
{
    auto &params = ev->params;

    try {
        params.assertArray();
    } catch (...) {
        AmArg ret;
        ret["message"] = "invalid argument";
        ret["code"]    = 500;
        postJsonRpcReply(*ev, ret, true);
        return;
    }

    if (params.size() == 0) {
        AmArg ret;
        ret["message"] = "empty arguments";
        ret["code"]    = 500;
        postJsonRpcReply(*ev, ret, true);
        return;
    }

    vector<string> certs{};
    for (unsigned int i = 0; i < params.size(); ++i) {
        certs.emplace_back(params[i].asCStr());
    }

    AmArg ret = "Not implemented yet";
    postJsonRpcReply(*ev, ret, false);
}

void IdentityValidator::makeIdentityData(SessionCtx *ctx, AmArg &identity_data)
{
    string error_reason;

    identity_data.assertArray();

    for (auto &e : ctx->identities) {
        identity_data.push(AmArg());
        AmArg &a = identity_data.back();

        a["parsed"] = e->isParsed;

        if (!e->isParsed) {
            a["parsed"]       = false;
            a["error_code"]   = e->identity.get_last_error(error_reason);
            a["error_reason"] = error_reason;
            a["verified"]     = false;
            a["raw"]          = e->value;
            continue;
        }

        a["header"]  = e->identity.get_header();
        a["payload"] = e->identity.get_payload();

        bool                               cert_is_valid;
        IdentityValidatorEntry::cert_state cert_state;
        auto                               key(getPubKey(e->identity.get_x5u_url(), cert_is_valid, cert_state));
        if (key.get()) {
            if (cert_is_valid) {
                bool verified = e->identity.verify(key.get(), expires);
                if (!verified) {
                    auto error_code = e->identity.get_last_error(error_reason);
                    switch (error_code) {
                    case ERR_EXPIRE_TIMEOUT: counters.identity_failed_verify_expired.inc(); break;
                    case ERR_VERIFICATION:   counters.identity_failed_verify_signature.inc(); break;
                    }
                    a["error_code"]   = error_code;
                    a["error_reason"] = error_reason;
                    ERROR("[%s] identity '%s' verification failed: %d/%s", ctx->id.data(), e->value.data(), error_code,
                          error_reason.data());
                } else {
                    counters.identity_success.inc();
                }
                a["verified"] = verified;
            } else {
                counters.identity_failed_cert_invalid.inc();
                a["error_code"] = -1;
                if (cert_state == IdentityValidatorEntry::REVOKED)
                    a["error_reason"] = "certificate is revoked";
                else
                    a["error_reason"] = "certificate is not valid";
                a["verified"] = false;
            }
        } else if (!isTrustedRepository(e->identity.get_x5u_url())) {
            counters.identity_failed_x5u_not_trusted.inc();
            a["error_code"]   = -1;
            a["error_reason"] = "x5u is not in trusted repositories";
            a["verified"]     = false;
        } else {
            counters.identity_failed_cert_not_available.inc();
            a["error_code"]   = -1;
            a["error_reason"] = "certificate is not available";
            a["verified"]     = false;
        }
    }
}

bool IdentityValidator::isTrustedRepository(const string &url) const
{
    for (const auto &r : trusted_repositories) {
        if (std::regex_match(url, r.regex))
            return true;
    }
    return false;
}

void IdentityValidator::renewCertEntry(CertHash::value_type &entry)
{
    entry.second.reset();
    session_container->postEvent(HTTP_EVENT_QUEUE,
                                 new HttpGetEvent(http_destination,               // destination
                                                  entry.first,                    // url
                                                  entry.first,                    // token
                                                  IDENTITY_VALIDATOR_APP_QUEUE)); // session_id
}

PublicKey IdentityValidator::getPubKey(const string &cert_url, bool &cert_is_valid,
                                       IdentityValidatorEntry::cert_state &cert_state) const
{
    auto it = certificates.find(cert_url);
    if (it == certificates.end()) {
        return nullptr;
    }

    if (it->second.state != IdentityValidatorEntry::LOADED && it->second.state != IdentityValidatorEntry::REVOKED) {
        return nullptr;
    }

    cert_is_valid = it->second.validation_sucessfull;
    cert_state    = it->second.state;

    return it->second.cert_chain[0].subject_public_key();
}

void IdentityValidator::postDbQuery(const string &query, const string &token)
{
    if (!session_container->postEvent(POSTGRESQL_QUEUE, new PGExecute(PGQueryData(pg_worker, query, true, /* single */
                                                                                  IDENTITY_VALIDATOR_APP_QUEUE, token),
                                                                      PGTransactionData())))
    {
        ERROR("failed to post PGExecute for %s", token.c_str());
    }
}

void IdentityValidator::postResult(IdentityValidatorEntry &cert_entry, const string &url)
{
    for (auto *ctx : cert_entry.defer_sessions) {
        ctx->onCertAvailable(url);

        if (ctx->isReady()) {
            postResult(ctx);
            delete ctx;
        }
    }

    cert_entry.defer_sessions.clear();
}

void IdentityValidator::postResult(SessionCtx *ctx)
{
    AmArg identity_data;
    makeIdentityData(ctx, identity_data);

    if (ctx->rpc_conn_id.empty() == false) {
        postJsonRpcReply(ctx->rpc_conn_id, ctx->id, identity_data);
        return;
    }

    if (!session_container->postEvent(ctx->id, new ValidateIdentitiesResponse(identity_data))) {
        ERROR("failed to post ValidateIdentitiesResponse for session %s", ctx->id.c_str());
    }
}

void IdentityValidator::serializeCertTNAuthList2AmArg(const Botan::X509_Certificate &cert, AmArg &a)
{
    if (const Botan::Cert_Extension::TNAuthList *tn_auth_list =
            cert.v3_extensions().get_extension_object_as<Botan::Cert_Extension::TNAuthList>())
    {
        AmArg &tn_list = a["tn_auth_list"];
        tn_list.assertArray();
        for (const auto &e : tn_auth_list->entries()) {
            tn_list.push(AmArg());
            auto &tn = tn_list.back();
            tn.assertStruct();
            switch (e.type()) {
            case Botan::Cert_Extension::TNAuthList::Entry::ServiceProviderCode:
                tn["spc"] = e.service_provider_code();
                break;
            case Botan::Cert_Extension::TNAuthList::Entry::TelephoneNumberRange:
            {
                auto &ranges = tn["range"];
                ranges.assertArray();
                for (auto &range : e.telephone_number_range()) {
                    ranges.push(AmArg());
                    auto &r    = ranges.back();
                    r["start"] = range.start.value();
                    r["count"] = range.count;
                }
            } break;
            case Botan::Cert_Extension::TNAuthList::Entry::TelephoneNumber: tn["one"] = e.telephone_number(); break;
            }
        }
    }
}

void IdentityValidator::serializeCert2AmArg(const Botan::X509_Certificate &cert, AmArg &a)
{
    a["serial_num"]       = bytes2HexStr(cert.serial_number());
    a["not_after"]        = cert.not_after().readable_string();
    a["not_before"]       = cert.not_before().readable_string();
    a["subject"]          = cert.subject_dn().to_string();
    a["issuer"]           = cert.issuer_dn().to_string();
    a["fingerprint_sha1"] = cert.fingerprint("SHA-1");
    auto info_vector      = cert.subject_info("X509.Certificate.serial");
    if (!info_vector.empty()) {
        a["serial"] = *info_vector.begin();
    }
    info_vector = cert.subject_info("X509v3.SubjectKeyIdentifier");
    if (!info_vector.empty()) {
        a["subject_key_identifier"] = *info_vector.begin();
    }
    info_vector = cert.issuer_info("X509v3.AuthorityKeyIdentifier");
    if (!info_vector.empty()) {
        a["authority_key_identifier"] = *info_vector.begin();
    }

    // crl distribution points
    auto &crl_dps_arg = a["crl_dps"];
    crl_dps_arg.assertArray();
    vector<string> parsed_crl_urls;
    IdentityValidator::parse_crl_dist_points(cert.crl_distribution_points(), parsed_crl_urls);
    for (auto &crl_url : parsed_crl_urls) {
        crl_dps_arg.push(AmArg());
        crl_dps_arg.back() = crl_url;
    }

    serializeCertTNAuthList2AmArg(cert, a);
}

void IdentityValidator::serializeCrl2AmArg(const Botan::X509_CRL &crl, AmArg &a)
{
    a["issuer"]      = crl.issuer_dn().to_string();
    a["crl_number"]  = crl.crl_number();
    a["this_update"] = crl.this_update().readable_string();
    a["next_update"] = crl.next_update().readable_string();
}

void IdentityValidator::parse_crl_dist_points(const vector<string> in, vector<string> &out, const string proto)
{
    const string      _proto{ proto + "://" };
    string::size_type pos{};

    out.clear();

    for (auto uri : in) {
        do {
            pos = uri.find(_proto);
            if (pos == string::npos)
                break;

            uri = uri.substr(pos);
            pos = uri.find(' ');

            if (pos == string::npos) {
                out.emplace_back(uri);
                break;
            }

            out.emplace_back(uri.substr(0, pos));
            uri = uri.substr(pos + 1);
        } while (pos != string::npos);
    }
}

/* RpcTreeHandler */

void IdentityValidator::init_rpc_tree()
{
    auto &show = reg_leaf(root, "show");
    reg_method(show, "cached_certificates", "show cached certificates", "", &IdentityValidator::showCerts, this);
    reg_method(show, "cached_crls", "show cached crls", "", &IdentityValidator::showCrls, this);
    reg_method(show, "trusted_certificates", "show trusted certificates", "", &IdentityValidator::showTrustedCerts,
               this);
    reg_method(show, "trusted_repositories", "show trusted repositories", "",
               &IdentityValidator::showTrustedRepositories, this);

    auto &request = reg_leaf(root, "request");
    reg_method(request, "validate_identity", "", "", &IdentityValidator::validateIdentity, this);
    reg_method(request, "check_certificate", "", "", &IdentityValidator::checkCert, this);

    auto &cached_certificates = reg_leaf(request, "cached_certificates", "Cached Certificates");
    reg_method_arg(cached_certificates, "clear", "", "", "<x5url>...", "clear certificates in cache",
                   &IdentityValidator::clearCerts, this);
    reg_method_arg(cached_certificates, "renew", "", "", "<x5url>...", "renew certificates in cache",
                   &IdentityValidator::renewCerts, this);

    auto &cached_crls = reg_leaf(request, "cached_crls", "Cached CRLs");
    reg_method_arg(cached_crls, "clear", "", "", "", "clear crls in cache", &IdentityValidator::clearCrls, this);
    reg_method_arg(cached_crls, "renew", "", "", "", "renew crls in cache", &IdentityValidator::renewCrls, this);

    auto &set = reg_leaf(root, "set");
    reg_method(set, "crl_processing", "", "", &IdentityValidator::setCrlProcessing, this);
}

void IdentityValidator::showTrustedCerts(const AmArg &, AmArg &ret)
{
    std::shared_lock lock(certificates_mutex);

    if (trusted_certs.empty())
        return;

    auto &entries = ret["entries"];
    for (const auto &cert_entry : trusted_certs) {
        entries.push(AmArg());
        auto &a = entries.back();

        a["id"]   = cert_entry.id;
        a["name"] = cert_entry.name;

        auto &certs = a["certs"];
        certs.assertArray();
        for (const auto &cert : cert_entry.certs) {
            certs.push(AmArg());
            IdentityValidator::serializeCert2AmArg(*cert, certs.back());
        }
    }

    auto &store = ret["store"];
    for (const auto &dn : trusted_certs_store.all_subjects()) {
        store.push(AmArg());
        auto &a = store.back();
        for (const auto &c : dn.contents()) {
            a[c.first] = c.second;
        }
    }
}

void IdentityValidator::showTrustedRepositories(const AmArg &, AmArg &ret)
{
    ret.assertArray();

    std::shared_lock lock(certificates_mutex);

    for (const auto &r : trusted_repositories) {
        ret.push(AmArg());
        auto &a                         = ret.back();
        a["id"]                         = r.id;
        a["url_pattern"]                = r.url_pattern;
        a["validate_https_certificate"] = r.validate_https_certificate;
    }
}

void IdentityValidator::showCerts(const AmArg &, AmArg &ret)
{
    auto now = std::chrono::system_clock::now();
    ret.assertArray();
    std::shared_lock lock(certificates_mutex);

    for (auto &pair : certificates) {
        ret.push(AmArg());
        auto &entry  = ret.back();
        entry["url"] = pair.first;
        pair.second.getInfo(entry, now);
    }
}

void IdentityValidator::clearCerts(const AmArg &args, AmArg &ret)
{
    int iret = 0;
    args.assertArray();

    std::unique_lock lock(certificates_mutex);

    if (args.size() == 0) {
        ret = certificates.size();
        certificates.clear();
        ret = iret;
        return;
    }
    for (unsigned int i = 0; i < args.size(); i++) {
        AmArg &x5urlarg = args[i];
        auto   it       = certificates.find(x5urlarg.asCStr());
        if (it != certificates.end()) {
            certificates.erase(it);
            iret++;
        }
    }
    ret = iret;
}

void IdentityValidator::renewCerts(const AmArg &args, AmArg &ret)
{
    args.assertArray();

    std::unique_lock lock(certificates_mutex);

    if (args.size() == 0) {
        auto it = certificates.begin();
        while (it != certificates.end()) {
            if (isTrustedRepository(it->first)) {
                ret[it->first] = "renew";
                renewCertEntry(*it);
                it++;
            } else {
                ret[it->first] = "removed";
                it             = certificates.erase(it);
            }
        }
        return;
    }

    for (unsigned int i = 0; i < args.size(); i++) {
        string cert_url(args[i].asCStr());
        bool   repository_is_trusted = isTrustedRepository(cert_url);
        auto   it                    = certificates.find(cert_url);
        if (it != certificates.end()) {
            if (!repository_is_trusted) {
                ret[cert_url] = "removed";
                certificates.erase(it);
                continue;
            }
            ret[cert_url] = "renew";
            renewCertEntry(*it);
        } else {
            if (!repository_is_trusted) {
                ret[cert_url] = "repo is not trusted";
                continue;
            }
            auto it       = certificates.emplace(cert_url, IdentityValidatorEntry{});
            ret[cert_url] = "renew";
            renewCertEntry(*it.first);
        }
    }
}

void IdentityValidator::setCrlProcessing(const AmArg &args, AmArg &ret)
{
    args.assertArray();

    if (args.size() != 1) {
        ret = "argument expected";
        return;
    }

    bool new_value;
    if (!str2bool(arg2str(args[0]), new_value)) {
        ret = format("failed to convert '{}' to bool", arg2str(args[0]));
        return;
    }

    crl_processing = new_value;

    ret = AmArg{
        { "crl_processing", crl_processing }
    };
}

void IdentityValidator::showCrls(const AmArg &, AmArg &ret)
{
    if (!crl_processing) {
        ret["message"] = "crl_processing option is disabled";
        ret["code"]    = 500;
        return;
    }

    auto now = std::chrono::system_clock::now();
    ret.assertArray();
    std::shared_lock lock(certificates_mutex);

    for (auto &pair : crls) {
        ret.push(AmArg());
        auto &entry  = ret.back();
        entry["url"] = pair.first;
        pair.second.getInfo(entry, now);
    }
}

void IdentityValidator::clearCrls(const AmArg &args, AmArg &ret)
{
    if (!crl_processing) {
        ret["message"] = "crl_processing option is disabled";
        ret["code"]    = 500;
        return;
    }

    int iret = 0;
    args.assertArray();

    std::unique_lock lock(certificates_mutex);

    if (args.size() == 0) {
        ret = crls.size();
        crls.clear();
        ret = iret;
        return;
    }

    for (unsigned int i = 0; i < args.size(); ++i) {
        AmArg &url = args[i];
        auto   it  = crls.find(url.asCStr());
        if (it != crls.end()) {
            crls.erase(it);
            ++iret;
        }
    }
    ret = iret;
}

void IdentityValidator::renewCrls(const AmArg &args, AmArg &ret)
{
    if (!crl_processing) {
        ret["message"] = "crl_processing option is disabled";
        ret["code"]    = 500;
        return;
    }

    args.assertArray();

    std::unique_lock lock(certificates_mutex);

    if (args.size() == 0) {
        auto it = crls.begin();
        while (it != crls.end()) {
            ret[it->first] = "renew";
            renewCrl(it->first);
            it++;
        }
        return;
    }

    for (unsigned int i = 0; i < args.size(); i++) {
        string crl_url(args[i].asCStr());
        ret[crl_url] = "renew";
        auto it      = crls.find(crl_url);
        if (it != crls.end()) {
            renewCrl(it->first);
        } else {
            renewCrl(crl_url);
        }
    }
}

bool IdentityValidator::validateIdentity(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, ValidateIdentity, params));
    return true;
}

bool IdentityValidator::checkCert(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, CheckCertificate, params));
    return true;
}

/* Configurable */

int IdentityValidator::configure(cfg_t *cfg)
{
    expires                = cfg_getint(cfg, CFG_PARAM_EXPIRES);
    identity_validator_ttl = std::chrono::seconds(cfg_getint(cfg, CFG_PARAM_CERTS_CACHE_TTL));

    if (cfg_size(cfg, CFG_PARAM_CERTS_CACHE_FAILED_TTL)) {
        identity_validator_failed_ttl = std::chrono::seconds(cfg_getint(cfg, CFG_PARAM_CERTS_CACHE_FAILED_TTL));
    } else {
        identity_validator_failed_ttl = identity_validator_ttl;
    }

    if (cfg_size(cfg, CFG_PARAM_CERTS_CACHE_FAILED_VERIFY_TTL)) {
        identity_validator_failed_verify_ttl =
            std::chrono::seconds(cfg_getint(cfg, CFG_PARAM_CERTS_CACHE_FAILED_VERIFY_TTL));
    } else {
        identity_validator_failed_verify_ttl = identity_validator_failed_ttl;
    }

    crl_cache_renew_timeout = std::chrono::seconds(cfg_getint(cfg, CFG_PARAM_CRL_CACHE_RENEW_TIMEOUT));
    crl_cache_idle_timeout  = std::chrono::seconds(cfg_getint(cfg, CFG_PARAM_CRL_CACHE_IDLE_TIMEOUT));
    crl_processing          = cfg_getbool(cfg, CFG_PARAM_CRL_PROCRSSING);

    http_destination  = cfg_getstr(cfg, CFG_PARAM_HTTP_DESTINATIION);
    schema            = cfg_getstr(cfg, CFG_PARAM_PG_SCHEMA_NAME);
    trusted_certs_req = cfg_getstr(cfg, CFG_PARAM_TRUSTED_CERTS_REQ);
    trusted_repos_req = cfg_getstr(cfg, CFG_PARAM_TRUSTED_REPOS_REQ);

    db_cfg.parse(cfg_getsec(cfg, CFG_SECTION_DB));

    return 0;
}
