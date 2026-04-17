#include "AmIdentity.h"
#include "log.h"
#include "jsonArg.h"
#include "AmSession.h"
#include "AmArgValidator.h"
#include "format_helper.h"

#include <botan/uuid.h>
#include <botan/system_rng.h>

static const char *jwt_field_tn  = "tn";
static const char *jwt_field_uri = "uri";

static const char *jwt_hdr_claim_alg = "alg";
static const char *alg_value_es256   = "ES256";

static const char *jwt_hdr_claim_x5u = "x5u";

static const char *jwt_hdr_claim_typ  = "typ";
static const char *typ_value_passport = "passport";

static const char *jwt_hdr_claim_ppt = "ppt";
static const char *ppt_value_shaken  = "shaken";
static const char *ppt_value_div     = "div";
static const char *ppt_value_div_opt = "div-o";

static const char *jwt_payload_claim_origid = "origid";
static const char *jwt_payload_claim_attest = "attest";
static const char *jwt_payload_claim_dest   = "dest";
static const char *jwt_payload_claim_orig   = "orig";
static const char *jwt_payload_claim_iat    = "iat";
static const char *jwt_payload_claim_div    = "div";
static const char *jwt_payload_claim_opt    = "opt";

static const char *identity_hdr_param_info = "info";
static const char *identity_hdr_param_alg  = "alg";
static const char *identity_hdr_param_ppt  = "ppt";

static AmArgHashValidator IdentityHeaderValidator({
    { jwt_hdr_claim_alg, true, { AmArg::CStr } },
    { jwt_hdr_claim_x5u, true, { AmArg::CStr } },
    { jwt_hdr_claim_ppt, true, { AmArg::CStr } },
    { jwt_hdr_claim_typ, true, { AmArg::CStr } }
});

static AmArgHashValidator IdentityShakenPayloadValidator({
    {    jwt_payload_claim_iat, true,    { AmArg::Int } },
    {   jwt_payload_claim_orig, true, { AmArg::Struct } },
    {   jwt_payload_claim_dest, true, { AmArg::Struct } },
    { jwt_payload_claim_attest, true,   { AmArg::CStr } },
    { jwt_payload_claim_origid, true,   { AmArg::CStr } }
});

static AmArgHashValidator IdentityDivPayloadValidator({
    {  jwt_payload_claim_iat, true,    { AmArg::Int } },
    { jwt_payload_claim_orig, true, { AmArg::Struct } },
    {  jwt_payload_claim_div, true, { AmArg::Struct } }
});

static AmArgHashValidator IdentityDivOptPayloadValidator({
    {  jwt_payload_claim_iat, true,    { AmArg::Int } },
    { jwt_payload_claim_orig, true, { AmArg::Struct } },
    { jwt_payload_claim_dest, true, { AmArg::Struct } },
    {  jwt_payload_claim_div, true, { AmArg::Struct } },
    {  jwt_payload_claim_opt, true,   { AmArg::CStr } }
});

void IdentData::parse_field(AmArg &a, std::vector<std::string> &field, bool array_is_required)
{
    if (isArgCStr(a)) {
        if (array_is_required) {
            throw AmArg::TypeMismatchException();
        }
        field.push_back(a.asCStr());
    } else if (isArgArray(a)) {
        for (int i = 0; i < static_cast<int>(a.size()); i++) {
            AmArg &v = a[i];
            if (isArgCStr(v)) {
                field.push_back(a[i].asCStr());
            } else {
                throw AmArg::TypeMismatchException();
            }
        }
    } else {
        throw AmArg::TypeMismatchException();
    }
}

void IdentData::parse(AmArg &a, bool array_is_required)
{
    tns.clear();
    if (a.hasMember(jwt_field_tn))
        parse_field(a[jwt_field_tn], tns, array_is_required);

    uris.clear();
    if (a.hasMember(jwt_field_uri))
        parse_field(a[jwt_field_uri], uris, array_is_required);
}

void IdentData::serialize_field(AmArg &a, const std::vector<std::string> &field, bool use_array)
{
    if (use_array) {
        for (auto &tn_s : field) {
            a.push(AmArg(tn_s));
        }
    } else {
        if (field.size() != 1)
            ERROR("wrong orig claim size %zd. expected 1", field.size());

        if (field.size())
            a = field[0];
    }
}

void IdentData::serialize(AmArg &a, bool use_array)
{
    a.assertStruct();
    if (!uris.empty())
        serialize_field(a[jwt_field_uri], uris, use_array);
    if (!tns.empty())
        serialize_field(a[jwt_field_tn], tns, use_array);
}

std::vector<std::string> AmIdentity::PassportType::names = { ppt_value_shaken, ppt_value_div, ppt_value_div_opt };

AmIdentity::PassportType::PassportType(passport_type_id ppt_id)
    : ppt_id(ppt_id)
{
}

void AmIdentity::PassportType::set(passport_type_id type_id)
{
    ppt_id = type_id;
}

AmIdentity::PassportType::passport_type_id AmIdentity::PassportType::get()
{
    return ppt_id;
}

bool AmIdentity::PassportType::parse(const char *ppt_name)
{
    int i = ES256_PASSPORT_SHAKEN;
    for (const auto &n : names) {
        if (n == ppt_name) {
            set(static_cast<passport_type_id>(i));
            return true;
        }
        i++;
    }
    return false;
}

const string &AmIdentity::PassportType::get_name()
{
    if (ppt_id < 0 || ppt_id > ES256_PASSPORT_DIV_OPT) {
        static string unknown("unknown");
        return unknown;
    }

    return names[ppt_id];
}

AmIdentity::AmIdentity()
    : jwt_(std::make_unique<AmJwt>())
    , type(PassportType::ES256_PASSPORT_SHAKEN)
    , last_errcode(0)
{
}

AmIdentity::AmIdentity(std::unique_ptr<AmJwt> jwt)
    : jwt_(std::move(jwt))
    , type(PassportType::ES256_PASSPORT_SHAKEN)
    , last_errcode(0)
{
}

AmIdentity::~AmIdentity() {}

void AmIdentity::add_dest_tn(const std::string &desttn)
{
    dest_data.tns.push_back(desttn);
}

void AmIdentity::add_dest_url(const std::string &desturl)
{
    dest_data.uris.push_back(desturl);
}

IdentData &AmIdentity::get_dest()
{
    return dest_data;
}

void AmIdentity::add_orig_tn(const std::string &origtn)
{
    orig_data.tns.push_back(origtn);
}

void AmIdentity::add_orig_url(const std::string &origurl)
{
    orig_data.uris.push_back(origurl);
}

IdentData &AmIdentity::get_orig()
{
    return orig_data;
}

void AmIdentity::add_div_tn(const std::string &desttn)
{
    div_data.tns.push_back(desttn);
}

void AmIdentity::add_div_url(const std::string &desturl)
{
    div_data.uris.push_back(desturl);
}

IdentData &AmIdentity::get_div()
{
    return div_data;
}

void AmIdentity::set_passport_type(PassportType::passport_type_id type_id)
{
    type.set(type_id);
}

AmIdentity::PassportType::passport_type_id AmIdentity::get_passport_type()
{
    return type.get();
}

std::string &AmIdentity::get_x5u_url()
{
    return x5u_url;
}

void AmIdentity::set_x5u_url(const std::string &val)
{
    x5u_url = val;
}

void AmIdentity::set_attestation(AmIdentity::ident_attest val)
{
    at = val;
}

AmIdentity::ident_attest AmIdentity::get_attestation()
{
    return at;
}

void AmIdentity::set_opt(const std::string &opt_claim)
{
    opt = opt_claim;
}

std::string &AmIdentity::get_opt()
{
    return opt;
}

void AmIdentity::set_orig_id(const std::string &val)
{
    orig_id = val;
}

std::string &AmIdentity::get_orig_id()
{
    return orig_id;
}

time_t AmIdentity::get_created()
{
    return jwt_->get_iat();
}

std::string AmIdentity::generate(Botan::Private_Key *key)
{
    auto &header  = jwt_->get_header();
    auto &payload = jwt_->get_payload();

    header[jwt_hdr_claim_alg] = alg_value_es256;
    header[jwt_hdr_claim_x5u] = x5u_url;
    header[jwt_hdr_claim_ppt] = type.get_name();
    header[jwt_hdr_claim_typ] = typ_value_passport;

    payload[jwt_payload_claim_attest] = std::string(1, (char)at);
    payload[jwt_payload_claim_iat]    = (int)time(0);

    auto &rng = Botan::system_rng();
    if (orig_id.empty())
        orig_id = Botan::UUID(rng).to_string();
    payload[jwt_payload_claim_origid] = orig_id;

    dest_data.serialize(payload[jwt_payload_claim_dest], true);
    orig_data.serialize(payload[jwt_payload_claim_orig], false);

    if (type.get() > PassportType::ES256_PASSPORT_SHAKEN) {
        // ES256_PASSPORT_DIV and ES256_PASSPORT_DIV_OPT
        div_data.serialize(payload[jwt_payload_claim_div], false);
        if (type.get() == PassportType::ES256_PASSPORT_DIV_OPT)
            payload[jwt_payload_claim_opt] = opt;
    }

    std::string ret = jwt_->generate(key);

    ret.append(";info=<");
    ret.append(x5u_url);
    ret.append(">;alg=ES256;ppt=");
    ret.append(type.get_name());

    return ret;
}

bool AmIdentity::verify(const Botan::Public_Key *key, unsigned int expire)
{
    if (!jwt_->verify(key, expire)) {
        last_errcode = jwt_->get_last_error(last_errstr);
        return false;
    }
    return true;
}

bool AmIdentity::verify(const std::string &secret, unsigned int expire)
{
    if (!jwt_->verify(secret, expire)) {
        last_errcode = jwt_->get_last_error(last_errstr);
        return false;
    }
    return true;
}

bool AmIdentity::verify_attestation(Botan::Public_Key *key, unsigned int expire, const IdentData &, const IdentData &)
{
    if (!verify(key, expire))
        return false;

    // TODO: verify orig and dest identification data;

    return true;
}

bool AmIdentity::parse(const std::string_view &value)
{
    std::string_view jwt_token;
    std::string_view info;
    std::string      validation_error;

    last_errcode = 0;
    last_errstr.clear();

    size_t pos = value.find(';');
    if (pos == std::string::npos) {
        jwt_token = value;
    } else {
        jwt_token = value.substr(0, pos);
        info      = value.substr(pos + 1);
    }

    // parse JWT structure
    if (!jwt_->parse(jwt_token)) {
        last_errcode = jwt_->get_last_error(last_errstr);
        return false;
    }

    auto &header  = jwt_->get_header();
    auto &payload = jwt_->get_payload();

    // process identity header
    if (!IdentityHeaderValidator.validate(header, validation_error)) {
        ERROR("%s", validation_error.data());
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Unexpected JWT header layout";
        return false;
    }

    try {
        AmArg &alg_arg  = header[jwt_hdr_claim_alg];
        AmArg &x5u_arg  = header[jwt_hdr_claim_x5u];
        AmArg &ppt_arg  = header[jwt_hdr_claim_ppt];
        AmArg &type_arg = header[jwt_hdr_claim_typ];

        if (!AmJwt::is_supported_alg(alg_arg.asCStr())) {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr  = std::string("Unsupported JWT alg '") + alg_arg.asCStr() + "'";
            return false;
        }

        if (strcmp(type_arg.asCStr(), typ_value_passport)) {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr  = "Unsupported typ. 'passport' expected";
            return false;
        }

        if (!type.parse(ppt_arg.asCStr())) {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr  = "Unsupported ppt. 'shaken','div','div-o' expected";
            return false;
        }
        x5u_url = x5u_arg.asCStr();
    } catch (...) {
        last_errcode = ERR_HEADER_VALUE;
        last_errstr  = "Malformed JWT header layout";
        return false;
    }

    // process payload
    try {
        switch (type.get()) {
        case PassportType::ES256_PASSPORT_SHAKEN:
        {
            if (!IdentityShakenPayloadValidator.validate(payload, validation_error)) {
                ERROR("%s", validation_error.data());
                last_errcode = ERR_JWT_VALUE;
                last_errstr  = "Unexpected JWT shaken payload layout";
                return false;
            }

            AmArg &attest_arg = payload[jwt_payload_claim_attest];
            if (strlen(attest_arg.asCStr()) != 1 || attest_arg.asCStr()[0] < AT_A || attest_arg.asCStr()[0] > AT_C) {
                last_errcode = ERR_UNSUPPORTED;
                last_errstr  = "Unknown attestation level";
                return false;
            }
            at = (enum ident_attest)(attest_arg.asCStr()[0]);

        } break;
        case PassportType::ES256_PASSPORT_DIV:
            if (!IdentityDivPayloadValidator.validate(payload, validation_error)) {
                ERROR("%s", validation_error.data());
                last_errcode = ERR_JWT_VALUE;
                last_errstr  = "Unexpected JWT div payload layout";
                return false;
            }

            div_data.parse(payload[jwt_payload_claim_div]);

            break;
        case PassportType::ES256_PASSPORT_DIV_OPT:
            if (!IdentityDivOptPayloadValidator.validate(payload, validation_error)) {
                ERROR("%s", validation_error.data());
                last_errcode = ERR_JWT_VALUE;
                last_errstr  = "Unexpected JWT div-o payload layout";
                return false;
            }

            div_data.parse(payload[jwt_payload_claim_div]);
            opt = payload[jwt_payload_claim_opt].asCStr();

            break;
        }

        orig_data.parse(payload[jwt_payload_claim_orig]);
        dest_data.parse(payload[jwt_payload_claim_dest], true);

    } catch (AmArg::TypeMismatchException &exc) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr  = "Malformed JWT payload layout";
        return false;
    }

    // process SIP Identity info parameters
    size_t      end = 0;
    std::string x5u_info, alg_info, ppt_info;
    if (!info.empty()) {
        do {
            pos = info.find(';', end);
            std::string param;

            if (pos != std::string::npos)
                param.append(info.begin() + end, info.begin() + pos);
            else
                param.append(info.begin() + end, info.end());

            end = pos + 1;
            pos = param.find('=');
            if (pos == std::string::npos) {
                DBG("incorrect parameter: %s. header: %s", param.c_str(), value.data());
                continue;
            }

            std::string name(param.begin(), param.begin() + pos), value(param.begin() + pos + 1, param.end());
            if (name == identity_hdr_param_info) {
                if (value[0] != '<' || value.back() != '>') {
                    last_errcode = ERR_HEADER_VALUE;
                    last_errstr  = "Missed <> in info value";
                    DBG("incorrect info value: %s. header: %s", value.c_str(), value.data());
                    continue;
                }
                x5u_info = trim(value, "\"<>");
            } else if (name == identity_hdr_param_alg) {
                alg_info = trim(value, "\"");
            } else if (name == identity_hdr_param_ppt) {
                ppt_info = trim(value, "\"");
            }
        } while (end);
    }

    if (!alg_info.empty() && !AmJwt::is_supported_alg(alg_info.c_str())) {
        last_errcode = ERR_UNSUPPORTED;
        last_errstr  = "Unsupported identity header alg '" + alg_info + "'";
        return false;
    }

    if (!ppt_info.empty()) {
        PassportType info_type;
        if (!info_type.parse(ppt_info.data())) {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr  = "Unsupported identity header ppt. 'shaken','div','div-o' expected";
            return false;
        }
        if (info_type.get() != type.get()) {
            last_errcode = ERR_HEADER_VALUE;
            last_errstr  = "JWT header 'ppt' claim and identity header param 'ppt' does not match";
            return false;
        }
    }

    if (!x5u_info.empty() && x5u_info != x5u_url) {
        last_errcode = ERR_EQUAL_X5U;
        last_errstr  = "JWT header 'x5u' claim and identity header param 'info' does not match";
        return false;
    }

    return true;
}

int AmIdentity::get_last_error(std::string &err)
{
    err = last_errstr;
    return last_errcode;
}
