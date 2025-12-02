#include "IdentityValidatorApp.h"
#include "log.h"
#include "format_helper.h"

#include <AmEventDispatcher.h>

#include <botan/x509path.h>
#include <botan/x509_ext.h>

#define EPOLL_MAX_EVENTS 2048

#define session_container      AmSessionContainer::instance()
#define identity_validator_app IdentityValidatorApp::instance()
#define event_dispatcher       AmEventDispatcher::instance()

const string pg_worker         = "identity_validator";
const string trusted_certs_key = "trusted_certs";
const string trusted_repos_key = "trusted_repos";

enum RpcMethodId { ValidateIdentity };

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
        IdentityValidatorApp::serializeCert2AmArg(cert, cert_chain_amarg.back());
    }
}

/* Statistics */

IdentityValidatorApp::Counters::Counters()
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

void IdentityValidatorApp::PGPoolCfg::parse(cfg_t *cfg)
{
    host               = cfg_getstr(cfg, CFG_PARAM_HOST);
    port               = cfg_getint(cfg, CFG_PARAM_PORT);
    name               = cfg_getstr(cfg, CFG_PARAM_NAME);
    user               = cfg_getstr(cfg, CFG_PARAM_USER);
    pass               = cfg_getstr(cfg, CFG_PARAM_PASS);
    statement_timeout  = cfg_getint(cfg, CFG_PARAM_STATEMENT_TIMEOUT);
    keepalive_interval = cfg_getint(cfg, CFG_PARAM_KEEPALIVE_INTERVAL);
}

bool IdentityValidatorApp::PGPoolCfg::create_pg_pool_worker(PGWorkerPoolCreate::PoolType type)
{
    PGPool pg_pool(host, port, name, user, pass);
    pg_pool.pool_size           = 1;
    pg_pool.keepalives_interval = keepalive_interval;

    return event_dispatcher->post(POSTGRESQL_QUEUE, new PGWorkerPoolCreate(pg_worker, type, pg_pool));
}

/* IdentityValidatorAppFactory */

class IdentityValidatorAppFactory : public AmConfigFactory, public AmDynInvokeFactory {
  private:
    IdentityValidatorAppFactory(const string &name)
        : AmConfigFactory(name)
        , AmDynInvokeFactory(name)
    {
        identity_validator_app;
    }
    ~IdentityValidatorAppFactory() { IdentityValidatorApp::dispose(); }

  public:
    DECLARE_FACTORY_INSTANCE(IdentityValidatorAppFactory)

    AmDynInvoke *getInstance() { return identity_validator_app; }

    int  onLoad() { return identity_validator_app->onLoad(); }
    void on_destroy() { identity_validator_app->stop(); }

    /* AmConfigFactory */
    int configure(const string &config) { return IdentityValidatorAppConfig::parse(config, identity_validator_app); }
    int reconfigure(const string &config) { return configure(config); }
};

EXPORT_PLUGIN_CLASS_FACTORY(IdentityValidatorAppFactory)
EXPORT_PLUGIN_CONF_FACTORY(IdentityValidatorAppFactory)
DEFINE_FACTORY_INSTANCE(IdentityValidatorAppFactory, MOD_NAME)

/* IdentityValidatorApp */

IdentityValidatorApp *IdentityValidatorApp::_instance = NULL;

IdentityValidatorApp *IdentityValidatorApp::instance()
{
    if (_instance == nullptr)
        _instance = new IdentityValidatorApp();

    return _instance;
}

void IdentityValidatorApp::dispose()
{
    if (_instance != nullptr)
        delete _instance;

    _instance = nullptr;
}

IdentityValidatorApp::IdentityValidatorApp()
    : AmEventFdQueue(this)
    , RpcTreeHandler(true)
    , epoll_fd(-1)
    , name("identity_validator_app")
    , queue_name(IDENTITY_VALIDATOR_APP_QUEUE)
    , stopped(false)
{
    event_dispatcher->addEventQueue(queue_name, this);
}

IdentityValidatorApp::~IdentityValidatorApp()
{
    CLASS_DBG("IdentityValidatorApp::~IdentityValidatorApp()");
    event_dispatcher->delEventQueue(queue_name);
}

int IdentityValidatorApp::init()
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

int IdentityValidatorApp::onLoad()
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

void IdentityValidatorApp::run()
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

    stopped.set(true);
}

void IdentityValidatorApp::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void IdentityValidatorApp::onTimer(const std::chrono::system_clock::time_point &now)
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
}

/* AmEventHandler */

void IdentityValidatorApp::process(AmEvent *event)
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

    case IdentityValidatorRequest::AddIdentity:
        if (auto *e = dynamic_cast<AddIdentityRequest *>(event)) {
            addIdentity(e->value, e->session_id);
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

void IdentityValidatorApp::reloadTrustedCertificates(const AmArg &data)
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

void IdentityValidatorApp::reloadTrustedRepositories(const AmArg &data)
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

void IdentityValidatorApp::addIdentity(const vector<string> &value, const string &id, const string &rpc_conn_id)
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

void IdentityValidatorApp::processHttpReply(const HttpGetResponseEvent &resp)
{
    std::unique_lock lock(certificates_mutex);

    const string &cert_url = resp.token;
    auto          cert_it  = certificates.find(cert_url);
    if (cert_it == certificates.end()) {
        ERROR("processHttpReply: absent cache entry %s", cert_url.c_str());
        return;
    }

    auto &cert_entry                 = cert_it->second;
    cert_entry.response_data         = resp.data;
    cert_entry.validation_sucessfull = false;
    try {
        // check "not_after" expiration time
        Botan::DataSource_Memory in(cert_entry.response_data);
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

    if (cert_entry.state == IdentityValidatorEntry::LOADED) {
        if (cert_entry.validation_sucessfull) {
            cert_entry.expire_time = std::chrono::system_clock::now() + identity_validator_ttl;
        } else {
            cert_entry.expire_time = std::chrono::system_clock::now() + identity_validator_failed_verify_ttl;
        }
    } else {
        cert_entry.expire_time = std::chrono::system_clock::now() + identity_validator_failed_ttl;
    }

    for (auto *ctx : cert_entry.defer_sessions) {
        ctx->onCertAvailable(cert_url);

        if (ctx->isReady()) {
            postResult(ctx);
            delete ctx;
        }
    }

    cert_entry.defer_sessions.clear();
}

void IdentityValidatorApp::processJsonRpcRequestEvent(JsonRpcRequestEvent *ev)
{
    AmArg ret;
    switch (ev->method_id) {
    case RpcMethodId::ValidateIdentity: handleValidateIdentityRpcRequest(ev); break;
    }
}

void IdentityValidatorApp::handleValidateIdentityRpcRequest(JsonRpcRequestEvent *ev)
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

    addIdentity(idents, ev->id.asCStr(), ev->connection_id);
}

void IdentityValidatorApp::makeIdentityData(SessionCtx *ctx, AmArg &identity_data)
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

        bool cert_is_valid;
        auto key(getPubKey(e->identity.get_x5u_url(), a, cert_is_valid));
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
                a["error_code"]   = -1;
                a["error_reason"] = "certificate is not valid";
                a["verified"]     = false;
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

bool IdentityValidatorApp::isTrustedRepository(const string &url) const
{
    for (const auto &r : trusted_repositories) {
        if (std::regex_match(url, r.regex))
            return true;
    }
    return false;
}

void IdentityValidatorApp::renewCertEntry(CertHash::value_type &entry)
{
    entry.second.reset();
    session_container->postEvent(HTTP_EVENT_QUEUE,
                                 new HttpGetEvent(http_destination,               // destination
                                                  entry.first,                    // url
                                                  entry.first,                    // token
                                                  IDENTITY_VALIDATOR_APP_QUEUE)); // session_id
}

PublicKey IdentityValidatorApp::getPubKey(const string &cert_url, AmArg &info, bool &cert_is_valid) const
{
    auto it = certificates.find(cert_url);
    if (it == certificates.end()) {
        return nullptr;
    }

    if (it->second.state != IdentityValidatorEntry::LOADED) {
        return nullptr;
    }

    cert_is_valid = it->second.validation_sucessfull;

    auto const &cert = it->second.cert_chain[0];

    auto &cert_info               = info["cert"];
    cert_info["fingerprint_sha1"] = cert.fingerprint("SHA-1");
    cert_info["subject"]          = cert.subject_dn().to_string();
    serializeCertTNAuthList2AmArg(cert, cert_info);

    return cert.subject_public_key();
}

void IdentityValidatorApp::postDbQuery(const string &query, const string &token)
{
    if (!session_container->postEvent(POSTGRESQL_QUEUE, new PGExecute(PGQueryData(pg_worker, query, true, /* single */
                                                                                  IDENTITY_VALIDATOR_APP_QUEUE, token),
                                                                      PGTransactionData())))
    {
        ERROR("failed to post PGExecute for %s", token.c_str());
    }
}

void IdentityValidatorApp::postResult(SessionCtx *ctx)
{
    AmArg identity_data;
    makeIdentityData(ctx, identity_data);

    if (ctx->rpc_conn_id.empty() == false) {
        postJsonRpcReply(ctx->rpc_conn_id, ctx->id, identity_data);
        return;
    }

    if (!session_container->postEvent(ctx->id, new IdentityDataResponce(identity_data))) {
        ERROR("failed to post IdentityDataResponce for session %s", ctx->id.c_str());
    }
}

void IdentityValidatorApp::serializeCertTNAuthList2AmArg(const Botan::X509_Certificate &cert, AmArg &a)
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

void IdentityValidatorApp::serializeCert2AmArg(const Botan::X509_Certificate &cert, AmArg &a)
{
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

    serializeCertTNAuthList2AmArg(cert, a);
}

/* RpcTreeHandler */

void IdentityValidatorApp::init_rpc_tree()
{
    auto &show = reg_leaf(root, "show");
    reg_method(show, "cached_certificates", "show cached certificates", "", &IdentityValidatorApp::showCerts, this);
    reg_method(show, "trusted_certificates", "show trusted certificates", "", &IdentityValidatorApp::showTrustedCerts,
               this);
    reg_method(show, "trusted_repositories", "show trusted repositories", "",
               &IdentityValidatorApp::showTrustedRepositories, this);

    auto &request = reg_leaf(root, "request");
    reg_method(request, "validate_identity", "", "", &IdentityValidatorApp::validateIdentity, this);
    auto &cached_certificates = reg_leaf(request, "cached_certificates", "Cached Certificates");
    reg_method_arg(cached_certificates, "clear", "", "", "<x5url>...", "clear certificates in cache",
                   &IdentityValidatorApp::clearCerts, this);
    reg_method_arg(cached_certificates, "renew", "", "", "<x5url>...", "renew certificates in cache",
                   &IdentityValidatorApp::renewCerts, this);
}

void IdentityValidatorApp::showTrustedCerts(const AmArg &, AmArg &ret)
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
            IdentityValidatorApp::serializeCert2AmArg(*cert, certs.back());
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

void IdentityValidatorApp::showTrustedRepositories(const AmArg &, AmArg &ret)
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

void IdentityValidatorApp::showCerts(const AmArg &, AmArg &ret)
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

void IdentityValidatorApp::clearCerts(const AmArg &args, AmArg &ret)
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

void IdentityValidatorApp::renewCerts(const AmArg &args, AmArg &ret)
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

bool IdentityValidatorApp::validateIdentity(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, ValidateIdentity, params));
    return true;
}

/* Configurable */

int IdentityValidatorApp::configure(cfg_t *cfg)
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

    http_destination  = cfg_getstr(cfg, CFG_PARAM_HTTP_DESTINATIION);
    schema            = cfg_getstr(cfg, CFG_PARAM_PG_SCHEMA_NAME);
    trusted_certs_req = cfg_getstr(cfg, CFG_PARAM_TRUSTED_CERTS_REQ);
    trusted_repos_req = cfg_getstr(cfg, CFG_PARAM_TRUSTED_REPOS_REQ);

    db_cfg.parse(cfg_getsec(cfg, CFG_SECTION_DB));

    return 0;
}
