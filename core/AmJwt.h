#pragma once

#include <botan/pk_keys.h>
#include <string>
using std::string;
using std::string_view;

#include "AmArg.h"

#define ERR_EXPIRE_TIMEOUT 1
#define ERR_VERIFICATION   2
#define ERR_COMPACT_FORM   3
#define ERR_JWT_VALUE      5
#define ERR_UNSUPPORTED    7

class AmJwt {
  public:
    AmJwt();

    static bool is_supported_alg(const char *alg);

    bool parse(const string_view &token);

    bool verify(const Botan::Public_Key *key, unsigned int expire = 0);
    bool verify(const string &secret, unsigned int expire = 0);

    string generate(Botan::Private_Key *key);
    string generate(const string &secret);

    string generate_firebase_assertion(Botan::Private_Key *key, unsigned int expire, const string &kid,
                                       const string &iss);

    AmArg &get_header() { return header; }
    AmArg &get_payload() { return payload; }

    string &get_jwt_header() { return jwt_header; }
    string &get_jwt_payload() { return jwt_payload; }

    time_t get_iat() const;

    int get_last_error(string &err);

  private:
    string jwt_header;
    AmArg  header;

    string jwt_payload;
    AmArg  payload;

    string signature;

    int    last_errcode;
    string last_errstr;
};
