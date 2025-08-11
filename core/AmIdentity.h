#pragma once

#include <string>
#include <vector>
#include <botan/pk_keys.h>

#include "AmArg.h"

/* related standards:
 * https://tools.ietf.org/html/rfc8224 Authenticated Identity Management in the Session Initiation Protocol (SIP)
 * https://tools.ietf.org/html/rfc8225 PASSporT: Personal Assertion Token
 * https://tools.ietf.org/html/rfc8588 Personal Assertion Token (PaSSporT) Extension for Signature-based Handling of
 * Asserted information using toKENs (SHAKEN) https://tools.ietf.org/html/rfc7515 JSON Web Signature (JWS)
 * https://tools.ietf.org/html/rfc7518 JSON Web Algorithms (JWA)
 */

/* commands to generate testing private key and certificate:
 * openssl genpkey -out test.key.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
 * openssl req -new -x509 -key test.key.pem -out test.pem -days 730 -subj "/C=UA/O=root/CN=sjwttest"
 */

#define ERR_EXPIRE_TIMEOUT 1
#define ERR_VERIFICATION   2
#define ERR_COMPACT_FORM   3
#define ERR_HEADER_VALUE   4
#define ERR_JWT_VALUE      5
#define ERR_EQUAL_X5U      6
#define ERR_UNSUPPORTED    7

struct IdentData {
    std::vector<std::string> uris;
    std::vector<std::string> tns;

    void parse_field(AmArg &arg, std::vector<std::string> &ident, bool array_is_required);
    void parse(AmArg &a, bool array_is_required = false);

    void serialize_field(AmArg &a, const std::vector<std::string> &field, bool use_array);
    void serialize(AmArg &a, bool use_array);
};

class AmIdentity {
  public:
    enum ident_attest { AT_A = 'A', AT_B = 'B', AT_C = 'C' };

    class PassportType {
      public:
        enum passport_type_id { ES256_PASSPORT_SHAKEN = 0, ES256_PASSPORT_DIV, ES256_PASSPORT_DIV_OPT };

      private:
        passport_type_id                ppt_id;
        static std::vector<std::string> names;
        // static const char *names[];

      public:
        PassportType(passport_type_id ppt_id = ES256_PASSPORT_SHAKEN);

        void               set(passport_type_id type_id);
        passport_type_id   get();
        const std::string &get_name();

        bool parse(const char *ppt_name);
    };

    AmIdentity();
    ~AmIdentity();

    bool verify_attestation(Botan::Public_Key *key, unsigned int expire, const IdentData &orig, const IdentData &dest);

    bool verify(const Botan::Public_Key *key, unsigned int expire = 0);

    std::string generate(Botan::Private_Key *key, bool raw = false);

    std::string generate_firebase_assertion(Botan::Private_Key *key, unsigned int expire, const std::string &kid,
                                            const std::string &iss);

    bool parse(const std::string_view &value, bool raw = false);

    void                           set_passport_type(PassportType::passport_type_id type);
    PassportType::passport_type_id get_passport_type();

    void         set_x5u_url(const std::string &val);
    std::string &get_x5u_url();

    void         set_attestation(ident_attest val);
    ident_attest get_attestation();

    void         set_opt(const std::string &opt_claim);
    std::string &get_opt();

    void         set_orig_id(const std::string &val);
    std::string &get_orig_id();

    time_t get_created();

    void       add_orig_tn(const std::string &origtn);
    void       add_orig_url(const std::string &origurl);
    IdentData &get_orig();

    void       add_dest_tn(const std::string &desttn);
    void       add_dest_url(const std::string &desturl);
    IdentData &get_dest();

    void       add_div_tn(const std::string &desttn);
    void       add_div_url(const std::string &desturl);
    IdentData &get_div();

    int get_last_error(std::string &err);

    AmArg &get_header() { return header; }
    AmArg &get_payload() { return payload; }

    std::string &get_jwt_header() { return jwt_header; }
    std::string &get_jwt_payload() { return jwt_payload; }

  private:
    // header claims
    PassportType type;    // ppt
    std::string  x5u_url; // x5u

    // payload claims
    time_t       created;   // iat
    std::string  orig_id;   // orig_id
    IdentData    orig_data; // orig
    IdentData    dest_data; // dest
    IdentData    div_data;  // div (div, div-o only)
    ident_attest at;        // attest (shaken only)
    std::string  opt;       // opt (div-o only)

    // ES256 signature
    std::string signature;

    std::string jwt_header;
    AmArg       header;

    std::string jwt_payload;
    AmArg       payload;

    int         last_errcode;
    std::string last_errstr;
};
