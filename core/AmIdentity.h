#pragma once

#include <string>
#include <vector>
#include <botan/pk_keys.h>

#include "AmArg.h"

/* related standards:
 * https://tools.ietf.org/html/rfc8224 Authenticated Identity Management in the Session Initiation Protocol (SIP)
 * https://tools.ietf.org/html/rfc8225 PASSporT: Personal Assertion Token
 * https://tools.ietf.org/html/rfc8588 Personal Assertion Token (PaSSporT) Extension for Signature-based Handling of Asserted information using toKENs (SHAKEN)
 * https://tools.ietf.org/html/rfc7515 JSON Web Signature (JWS)
 * https://tools.ietf.org/html/rfc7518 JSON Web Algorithms (JWA)
 */

/* commands to generate testing private key and certificate:
 * openssl genpkey -out test.key.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
 * openssl req -new -x509 -key test.key.pem -out test.pem -days 730 -subj "/C=UA/O=root/CN=sjwttest"
 */

#define ERR_EXPIRE_TIMEOUT      1
#define ERR_VERIFICATION        2
#define ERR_COMPACT_FORM        3
#define ERR_HEADER_VALUE        4
#define ERR_JWT_VALUE           5
#define ERR_EQUAL_X5U           6
#define ERR_UNSUPPORTED         7

struct IdentData
{
    std::vector<std::string> uris;
    std::vector<std::string> tns;
};

class AmIdentity
{
  public:
    enum ident_attest {
        AT_A = 'A',
        AT_B = 'B',
        AT_C = 'C'
    };

    AmIdentity();
    ~AmIdentity();

    bool verify_attestation(Botan::Public_Key* key, unsigned int expire,
               const IdentData& orig, const IdentData& dest);

    bool verify(Botan::Public_Key* key, unsigned int expire);

    std::string generate(Botan::Private_Key* key);

    bool parse(const std::string& value);

    void set_x5u_url(const std::string& val);
    std::string& get_x5u_url();

    void set_attestation(ident_attest val);
    ident_attest get_attestation();

    std::string& get_orig_id();
    time_t get_created();

    void add_orig_tn(const std::string& origtn);
    void add_orig_url(const std::string& origurl);
    IdentData& get_orig();

    void add_dest_tn(const std::string& desttn);
    void add_dest_url(const std::string& desturl);
    IdentData& get_dest();

    int get_last_error(std::string& err);

    const AmArg &get_parsed_header() { return header; }
    const AmArg &get_parsed_payload() { return payload; }

  private:
    std::string sign;
    std::string x5u_url;
    IdentData orig_data;
    IdentData dest_data;
    ident_attest at;
    time_t created;
    std::string orig_id;
    int last_errcode;
    std::string last_errstr;

    std::string jwt_header;
    AmArg header;

    std::string jwt_payload;
    AmArg payload;
};
