#include "AmJwt.h"
#include "log.h"
#include "base64url.h"
#include "jsonArg.h"
#include "AmArgValidator.h"

#include <botan/system_rng.h>
#include <botan/mac.h>
#include <botan/pubkey.h>

static const char *jwt_hdr_claim_alg = "alg";
static const char *alg_value_es256   = "ES256";
static const char *alg_value_hs256   = "HS256";
static const char *alg_value_rs256   = "RS256";

static const char *jwt_payload_claim_iat = "iat";

static AmArgHashValidator JwtHeaderValidator({
    { jwt_hdr_claim_alg, true, { AmArg::CStr } }
});

AmJwt::AmJwt()
    : last_errcode(0)
{
}

bool AmJwt::is_supported_alg(const char *alg)
{
    return !strcmp(alg, alg_value_es256) || !strcmp(alg, alg_value_hs256) || !strcmp(alg, alg_value_rs256);
}

bool AmJwt::parse(const string_view &token)
{
    string validation_error;
    size_t end = 0;

    last_errcode = 0;
    last_errstr.clear();

    jwt_header.clear();
    jwt_payload.clear();
    signature.clear();

    if (token[0] == '.' && token[1] == '.') {
        last_errcode = ERR_COMPACT_FORM;
        last_errstr  = "Compact form is not supported";
        return false;
    }

    // Header.Payload.Signature
    string_view data_base64[3];
    for (int i = 0; i < 2; i++) {
        size_t pos = token.find('.', end);
        if (pos == string::npos) {
            last_errcode = ERR_JWT_VALUE;
            if (i < 1) {
                last_errstr = "Missed header/payload separator";
            } else {
                last_errstr = "Missed payload/signature separator";
            }
            return false;
        }
        data_base64[i] = token.substr(end, pos - end);
        end            = pos + 1;
    }

    data_base64[2] = token.substr(end);

    if (data_base64[0].empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Empty base64url header";
        return false;
    }
    if (data_base64[1].empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Empty base64url payload";
        return false;
    }
    if (data_base64[2].empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Empty base64url signature";
        return false;
    }

    if (!base64_url_decode(data_base64[0], jwt_header) || jwt_header.empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Failed to decode header as base64url";
        return false;
    }
    if (!base64_url_decode(data_base64[1], jwt_payload) || jwt_payload.empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Failed to decode payload as base64url";
        return false;
    }
    if (!base64_url_decode(data_base64[2], signature) || signature.empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Failed to decode signature as base64url";
        return false;
    }

    if (!json2arg(jwt_header, header)) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Failed to parse JWT header JSON";
        return false;
    }

    if (!json2arg(jwt_payload, payload)) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Failed to parse JWT payload JSON";
        return false;
    }

    if (!JwtHeaderValidator.validate(header, validation_error)) {
        ERROR("%s", validation_error.data());
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Unexpected JWT header layout";
        return false;
    }

    return true;
}

bool AmJwt::verify(const Botan::Public_Key *key, unsigned int expire)
{
    last_errcode = 0;
    last_errstr.clear();

    if (expire) {
        time_t iat = get_iat();
        time_t t   = time(0);
        if ((t - iat) > expire) {
            last_errcode = ERR_EXPIRE_TIMEOUT;
            last_errstr  = "Expired Timeout";
            return false;
        }
    }

    string alg;
    try {
        alg = header[jwt_hdr_claim_alg].asCStr();
    } catch (...) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Missing alg in header";
        return false;
    }

    string padding;
    if (alg == alg_value_es256) {
        padding = "SHA-256";
    } else if (alg == alg_value_rs256) {
        padding = "EMSA3(SHA-256)";
    } else {
        last_errcode = ERR_UNSUPPORTED;
        last_errstr  = "Unsupported alg for public key verification: '" + alg + "'";
        return false;
    }

    Botan::PK_Verifier verifier(*key, padding);

    string base64_header  = base64_url_encode(jwt_header);
    string base64_payload = base64_url_encode(jwt_payload);

    verifier.update((uint8_t *)base64_header.c_str(), base64_header.size());
    verifier.update((uint8_t *)".", 1);
    verifier.update((uint8_t *)base64_payload.c_str(), base64_payload.size());

    bool ret = verifier.check_signature((uint8_t *)signature.c_str(), signature.size());
    if (!ret) {
        last_errstr  = "Signature verification Failed";
        last_errcode = ERR_VERIFICATION;
    }
    return ret;
}

bool AmJwt::verify(const string &secret, unsigned int expire)
{
    last_errcode = 0;
    last_errstr.clear();

    if (expire) {
        time_t iat = get_iat();
        time_t t   = time(0);
        if ((t - iat) > expire) {
            last_errcode = ERR_EXPIRE_TIMEOUT;
            last_errstr  = "Expired Timeout";
            return false;
        }
    }

    string signing_input = base64_url_encode(jwt_header) + "." + base64_url_encode(jwt_payload);

    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    if (!mac) {
        last_errstr  = "Unsupported alg 'HS256'";
        last_errcode = ERR_UNSUPPORTED;
        return false;
    }

    mac->set_key(reinterpret_cast<const uint8_t *>(secret.data()), secret.size());
    mac->update(reinterpret_cast<const uint8_t *>(signing_input.data()), signing_input.size());

    bool ret = mac->verify_mac(reinterpret_cast<const uint8_t *>(signature.data()), signature.size());
    if (!ret) {
        last_errstr  = "Signature verification Failed";
        last_errcode = ERR_VERIFICATION;
    }
    return ret;
}

string AmJwt::generate(Botan::Private_Key *key)
{
    string alg;
    try {
        alg = header[jwt_hdr_claim_alg].asCStr();
    } catch (...) {
        throw Botan::Exception("missing 'alg' in JWT header");
    }

    string padding;
    if (alg == alg_value_es256) {
        if (key->algo_name() != "ECDSA")
            throw Botan::Exception("unexpected key type " + key->algo_name());
        padding = "SHA-256";
    } else if (alg == alg_value_rs256) {
        if (key->algo_name() != "RSA")
            throw Botan::Exception("unexpected key type " + key->algo_name());
        padding = "EMSA3(SHA-256)";
    } else {
        throw Botan::Exception("unsupported alg for key signing: '" + alg + "'");
    }

    auto &rng = Botan::system_rng();

    Botan::PK_Signer signer(*key, rng, padding);

    jwt_header  = arg2json(header);
    jwt_payload = arg2json(payload);

    string base64_header  = base64_url_encode(jwt_header);
    string base64_payload = base64_url_encode(jwt_payload);

    signer.update((uint8_t *)base64_header.c_str(), base64_header.size());
    signer.update((uint8_t *)".", 1);
    signer.update((uint8_t *)base64_payload.c_str(), base64_payload.size());

    std::vector<uint8_t> sign_ = signer.signature(rng);
    signature.assign(reinterpret_cast<const char *>(sign_.data()), sign_.size());

    return base64_header + "." + base64_payload + "." + base64_url_encode(signature);
}

string AmJwt::generate_firebase_assertion(Botan::Private_Key *key, unsigned int expire, const string &kid,
                                          const string &iss)
{
    int now = (int)time(0);

    header["typ"] = "JWT";
    header["alg"] = alg_value_rs256;
    header["kid"] = kid;

    payload["iat"]   = now;
    payload["exp"]   = now + expire;
    payload["iss"]   = iss;
    payload["aud"]   = "https://oauth2.googleapis.com/token";
    payload["scope"] = "https://www.googleapis.com/auth/firebase.messaging";

    return generate(key);
}

string AmJwt::generate(const string &secret)
{
    header[jwt_hdr_claim_alg] = alg_value_hs256;

    jwt_header  = arg2json(header);
    jwt_payload = arg2json(payload);

    string base64_header  = base64_url_encode(jwt_header);
    string base64_payload = base64_url_encode(jwt_payload);

    string signing_input = base64_header + "." + base64_payload;

    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    if (!mac)
        throw Botan::Exception("HMAC(SHA-256) not available");

    mac->set_key(reinterpret_cast<const uint8_t *>(secret.data()), secret.size());
    mac->update(reinterpret_cast<const uint8_t *>(signing_input.data()), signing_input.size());

    auto sig = mac->final();
    signature.assign(reinterpret_cast<const char *>(sig.data()), sig.size());

    return signing_input + "." + base64_url_encode(signature);
}

time_t AmJwt::get_iat() const
{
    if (payload.hasMember(jwt_payload_claim_iat) && isArgInt(payload[jwt_payload_claim_iat]))
        return payload[jwt_payload_claim_iat].asInt();
    return 0;
}

int AmJwt::get_last_error(string &err)
{
    err = last_errstr;
    return last_errcode;
}
