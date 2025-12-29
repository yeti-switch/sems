#pragma once

#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <AmIdentity.h>
#include <AmStatistics.h>
#include <RpcTreeHandler.h>
#include <IdentityValidatorApi.h>
#include <ampi/HttpClientAPI.h>
#include <ampi/PostgreSqlAPI.h>

#include <botan/x509_ca.h>
#include <botan/certstor.h>
#include <botan/pkcs8.h>

#include <unordered_map>
#include <regex>
#include <shared_mutex>

#include "IdentityValidatorConfig.h"

using namespace std;

using PublicKey = std::unique_ptr<Botan::Public_Key>;

struct IdentityEntry {
    AmIdentity identity;
    string     value;
    bool       isParsed;
    bool       isValid;
    bool       isWaitedForCert;
    IdentityEntry(const string &_value)
        : value(_value)
        , isParsed(false)
        , isValid(false)
        , isWaitedForCert(false)
    {
    }
};

struct SessionCtx {
    string                            id;
    string                            rpc_conn_id;
    vector<unique_ptr<IdentityEntry>> identities;

    SessionCtx(const string &_id, const string &_rpc_conn_id = string())
        : id(_id)
        , rpc_conn_id(_rpc_conn_id)
    {
    }

    bool isReady()
    {
        for (auto &e : identities)
            if (e->isWaitedForCert)
                return false;

        return true;
    }

    void onCertAvailable(const string &cert_url)
    {
        for (auto &e : identities)
            if (e->isWaitedForCert && e->identity.get_x5u_url() == cert_url)
                e->isWaitedForCert = false;
    }
};

struct IdentityValidatorEntry {
    enum cert_state { LOADING, LOADED, UNAVAILABLE };

    std::chrono::system_clock::time_point expire_time;
    string                                response_data;
    vector<Botan::X509_Certificate>       cert_chain;
    string                                error_str;
    int                                   error_code;
    int                                   error_type;
    cert_state                            state;

    bool   validation_sucessfull;
    string validation_result;
    string trust_root_cert;

    /* Identities */
    set<SessionCtx *> defer_sessions;

    IdentityValidatorEntry()
        : error_code(0)
        , error_type(0)
        , state(LOADING)
    {
    }

    ~IdentityValidatorEntry() {}

    void reset()
    {
        error_type = 0;
        error_code = 0;
        error_str.clear();
        response_data.clear();
        cert_chain.clear();
        state = LOADING;
    }

    static string to_string(cert_state state)
    {
        switch (state) {
        case LOADING:     return "loading";
        case LOADED:      return "loaded";
        case UNAVAILABLE: return "unavailable";
        }
        return "";
    }

    void getInfo(AmArg &a, const std::chrono::system_clock::time_point &now) const;
};

class IdentityValidator : public AmThread,
                          public AmEventFdQueue,
                          public AmEventHandler,
                          public RpcTreeHandler,
                          public Configurable {
  private:
    static IdentityValidator *_instance;

    int         epoll_fd;
    const char *name;
    string      queue_name;

    AmTimerFd each_second_timer;
    AmEventFd stop_event;

    int                  expires;
    string               http_destination;
    std::chrono::seconds identity_validator_ttl;
    std::chrono::seconds identity_validator_failed_ttl;
    std::chrono::seconds identity_validator_failed_verify_ttl;
    string               schema;
    string               trusted_certs_req;
    string               trusted_repos_req;

    struct PGPoolCfg {
        string host;
        int    port;
        string name;
        string user;
        string pass;
        int    statement_timeout;
        int    keepalive_interval;

        void parse(cfg_t *cfg);
        bool create_pg_pool_worker(PGWorkerPoolCreate::PoolType type);
    };

    PGPoolCfg db_cfg;

    /* Сertificates */
    using CertHash = unordered_map<string, IdentityValidatorEntry>;
    CertHash certificates;

    /* Trusted Certificates */
    struct TrustedCertEntry {
        unsigned long                               id;
        string                                      name;
        vector<shared_ptr<Botan::X509_Certificate>> certs;
        TrustedCertEntry(unsigned long _id, string _name)
            : id(_id)
            , name(_name)
        {
        }
    };
    vector<TrustedCertEntry>           trusted_certs;
    Botan::Certificate_Store_In_Memory trusted_certs_store;

    /* Trusted Repositories */
    struct TrustedRepositoryEntry {
        unsigned long id;
        string        url_pattern;
        bool          validate_https_certificate;
        std::regex    regex;
        TrustedRepositoryEntry(unsigned long _id, string _url_pattern, bool _validate_https_certificate)
            : id(_id)
            , url_pattern(_url_pattern)
            , validate_https_certificate(_validate_https_certificate)
            , regex(_url_pattern)
        {
        }
    };
    vector<TrustedRepositoryEntry> trusted_repositories;

    /* guards:
     *   trusted_certs,
     *   trusted_certs_store,
     *   trusted_repositories
     */
    mutable std::shared_mutex certificates_mutex;


    /* RPC */
    void init_rpc_tree() override;

    rpc_handler showTrustedCerts;
    rpc_handler showTrustedRepositories;

    rpc_handler showCerts;
    rpc_handler clearCerts;
    rpc_handler renewCerts;

    async_rpc_handler validateIdentity;

    /* Statistics */
    struct Counters {
        AtomicCounter &identity_success;
        AtomicCounter &identity_failed_parse;
        AtomicCounter &identity_failed_verify_expired;
        AtomicCounter &identity_failed_verify_signature;
        AtomicCounter &identity_failed_x5u_not_trusted;
        AtomicCounter &identity_failed_cert_invalid;
        AtomicCounter &identity_failed_cert_not_available;
        Counters();
    } counters;

  protected:
    friend class IdentityValidatorFactory;
    int  init();
    int  onLoad();
    void run() override;
    void on_stop() override;
    void process(AmEvent *ev) override;
    int  configure(cfg_t *cfg) override;

    void      onTimer(const std::chrono::system_clock::time_point &now);
    void      reloadTrustedCertificates(const AmArg &data);
    void      reloadTrustedRepositories(const AmArg &data);
    void      addIdentities(const vector<string> &value, const string &id, const string &rpc_conn_id = string());
    void      processHttpReply(const HttpGetResponseEvent &resp);
    void      processJsonRpcRequestEvent(JsonRpcRequestEvent *ev);
    void      handleValidateIdentityRpcRequest(JsonRpcRequestEvent *ev);
    bool      isTrustedRepository(const string &url) const;
    void      renewCertEntry(CertHash::value_type &entry);
    PublicKey getPubKey(const string &cert_url, AmArg &info, bool &cert_is_valid) const;
    void      postDbQuery(const string &query, const string &token);
    void      makeIdentityData(SessionCtx *ctx, AmArg &identity_data);
    void      postResult(SessionCtx *ctx);

  public:
    IdentityValidator();
    virtual ~IdentityValidator();

    static IdentityValidator *instance();
    static void               dispose();

    static void serializeCertTNAuthList2AmArg(const Botan::X509_Certificate &cert, AmArg &a);
    static void serializeCert2AmArg(const Botan::X509_Certificate &cert, AmArg &a);
};
