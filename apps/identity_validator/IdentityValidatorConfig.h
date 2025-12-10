#pragma once

#include <string>
using std::string;

#include <confuse.h>

#define CFG_PARAM_HTTP_DESTINATIION             "http_destination"
#define CFG_PARAM_EXPIRES                       "expires"
#define CFG_PARAM_CERTS_CACHE_TTL               "certs_cache_ttl"
#define CFG_PARAM_CERTS_CACHE_FAILED_TTL        "certs_cache_failed_ttl"
#define CFG_PARAM_CERTS_CACHE_FAILED_VERIFY_TTL "certs_cache_failed_verify_ttl"

#define CFG_PARAM_PG_SCHEMA_NAME    "schema"
#define CFG_PARAM_TRUSTED_CERTS_REQ "trusted_certs_req"
#define CFG_PARAM_TRUSTED_REPOS_REQ "trusted_repos_req"

#define CFG_SECTION_DB               "db"
#define CFG_PARAM_HOST               "host"
#define CFG_PARAM_PORT               "port"
#define CFG_PARAM_NAME               "name"
#define CFG_PARAM_USER               "user"
#define CFG_PARAM_PASS               "pass"
#define CFG_PARAM_KEEPALIVE_INTERVAL "keepalive_interval"
#define CFG_PARAM_STATEMENT_TIMEOUT  "statement_timeout"

#define DEFAULT_EXPIRES                  60
#define DEFAULT_CERTS_CACHE_TTL          86400
#define DEFAULT_CACHE_FAILED_TTL         86400
#define DEFAULT_CACHE_FAILED_VERIFY_TTLS 86400

#define DEFAULT_HTTP_DESTINATIION "identity"
#define DEFAULT_TRUSTED_CERT_REQ  "SELECT * FROM load_stir_shaken_trusted_certificates()"
#define DEFAULT_TRUSTED_REPO_REQ  "SELECT * FROM load_stir_shaken_trusted_repositories()"

class Configurable {
  public:
    virtual int configure(cfg_t *cfg) = 0;
};

class IdentityValidatorConfig {
  public:
    static int parse(const string &config, Configurable *obj);
};
