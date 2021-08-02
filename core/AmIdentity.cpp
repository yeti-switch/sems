#include "AmIdentity.h"
#include "log.h"
#include "base64url.h"
#include "jsonArg.h"
#include <botan/data_src.h>
#include <botan/auto_rng.h>
#include <botan/x509cert.h>
#include <botan/pk_ops.h>
#include "AmSession.h"
#include "AmArgValidator.h"

static const char *jwt_field_tn = "tn";
static const char *jwt_field_uri = "uri";

static const char *jwt_hdr_claim_alg = "alg";
static const char *alg_value_es256 = "ES256";

static const char *jwt_hdr_claim_x5u = "x5u";

static const char *jwt_hdr_claim_typ = "typ";
static const char *typ_value_passport = "passport";

static const char *jwt_hdr_claim_ppt = "ppt";
static const char *ppt_value_shaken = "shaken";
static const char *ppt_value_div = "div";
static const char *ppt_value_div_opt = "div-o";
enum passport_type {
    ES256_PASSPORT_SHAKEN = 0,
    ES256_PASSPORT_DIV,
    ES256_PASSPORT_DIV_OPT
};

static const char *jwt_payload_claim_origid = "origid";
static const char *jwt_payload_claim_attest = "attest";
static const char *jwt_payload_claim_dest = "dest";
static const char *jwt_payload_claim_orig = "orig";
static const char *jwt_payload_claim_iat = "iat";
static const char *jwt_payload_claim_div = "div";
static const char *jwt_payload_claim_opt = "opt";

static const char *identity_hdr_param_info = "info";
static const char *identity_hdr_param_alg = "alg";
static const char *identity_hdr_param_ppt = "ppt";

static AmArgHashValidator IdentityHeaderValidator({
    {jwt_hdr_claim_alg, true, {AmArg::CStr}},
    {jwt_hdr_claim_x5u, true, {AmArg::CStr}},
    {jwt_hdr_claim_ppt, true, {AmArg::CStr}},
    {jwt_hdr_claim_typ, true, {AmArg::CStr}}
});

static AmArgHashValidator IdentityShakenPayloadValidator({
    {jwt_payload_claim_iat, true, {AmArg::Int}},
    {jwt_payload_claim_orig, true, {AmArg::Struct}},
    {jwt_payload_claim_dest, true, {AmArg::Struct}},
    {jwt_payload_claim_attest, true, {AmArg::CStr}},
    {jwt_payload_claim_origid, true, {AmArg::CStr}}
});

static AmArgHashValidator IdentityDivPayloadValidator({
    {jwt_payload_claim_iat, true, {AmArg::Int}},
    {jwt_payload_claim_orig, true, {AmArg::Struct}},
    {jwt_payload_claim_dest, true, {AmArg::Struct}},
    {jwt_payload_claim_div, true, {AmArg::Struct}}
});

static AmArgHashValidator IdentityDivOptPayloadValidator({
    {jwt_payload_claim_iat, true, {AmArg::Int}},
    {jwt_payload_claim_orig, true, {AmArg::Struct}},
    {jwt_payload_claim_dest, true, {AmArg::Struct}},
    {jwt_payload_claim_div, true, {AmArg::Struct}},
    {jwt_payload_claim_opt, true, {AmArg::CStr}}
});

static void add_ident_data(AmArg &arg, std::vector<std::string> &ident, const char *name)
{
    if(!arg.hasMember(name))
        return;

    AmArg& a = arg[name];
    if(isArgCStr(a)) {
        ident.push_back(a.asCStr());
    } else if(isArgArray(a)) {
        for(int i = 0; i < static_cast<int>(a.size()); i++) {
            AmArg &v = a[i];
            if(isArgCStr(v)) {
                ident.push_back(a[i].asCStr());
            } else {
                throw AmArg::TypeMismatchException();
            }
        }
    } else {
        throw AmArg::TypeMismatchException();
    }
}

AmIdentity::AmIdentity()
: last_errcode(0)
{
}

AmIdentity::~AmIdentity()
{
}

void AmIdentity::add_dest_tn(const std::string& desttn)
{
    dest_data.tns.push_back(desttn);
}

void AmIdentity::add_dest_url(const std::string& desturl)
{
    dest_data.uris.push_back(desturl);
}

IdentData & AmIdentity::get_dest()
{
    return dest_data;
}

void AmIdentity::add_orig_tn(const std::string& origtn)
{
    orig_data.tns.push_back(origtn);
}

void AmIdentity::add_orig_url(const std::string& origurl)
{
    orig_data.uris.push_back(origurl);
}

IdentData & AmIdentity::get_orig()
{
    return orig_data;
}

std::string & AmIdentity::get_x5u_url()
{
    return x5u_url;
}

void AmIdentity::set_x5u_url(const std::string& val)
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

std::string & AmIdentity::get_orig_id()
{
    return orig_id;
}

time_t AmIdentity::get_created()
{
    return created;
}

std::string AmIdentity::generate(Botan::Private_Key* key)
{
    Botan::AutoSeeded_RNG rnd;
    std::unique_ptr<Botan::PK_Ops::Signature> ops = key->create_signature_op(rnd, "EMSA1(SHA-256)", "");

    header[jwt_hdr_claim_alg] = alg_value_es256;
    header[jwt_hdr_claim_x5u] = x5u_url;
    header[jwt_hdr_claim_ppt] = ppt_value_shaken;
    header[jwt_hdr_claim_typ] = typ_value_passport;
    jwt_header = arg2json(header);

    payload[jwt_payload_claim_attest] = std::string(1, (char)at);
    payload[jwt_payload_claim_iat] = (int)time(0);
    payload[jwt_payload_claim_origid] = orig_id = AmSession::getNewId();

    AmArg& dest_arg = payload[jwt_payload_claim_dest];
    dest_arg.assertStruct();
    if(dest_data.tns.size() == 1) {
        dest_arg[jwt_field_tn] = dest_data.tns[0];
    } else {
        for(auto& tn_s : dest_data.tns) {
            dest_arg[jwt_field_tn].push(AmArg(tn_s));
        }
    }
    if(dest_data.uris.size() == 1) {
        dest_arg[jwt_field_uri] = dest_data.uris[0];
    } else {
        for(auto& url : dest_data.uris) {
            dest_arg[jwt_field_uri].push(AmArg(url));
        }
    }

    AmArg& orig_arg = payload[jwt_payload_claim_orig];
    orig_arg.assertStruct();
    if(orig_data.tns.size() == 1) {
        orig_arg[jwt_field_tn] = orig_data.tns[0];
    } else {
        for(auto& tn_s : orig_data.tns) {
            orig_arg[jwt_field_tn].push(AmArg(tn_s));
        }
    }
    if(orig_data.uris.size() == 1) {
        orig_arg[jwt_field_uri] = orig_data.uris[0];
    } else {
        for(auto& url : orig_data.uris) {
            orig_arg[jwt_field_uri].push(AmArg(url));
        }
    }

    jwt_payload = arg2json(payload);

    std::string base64_header = base64_url_encode(jwt_header);
    std::string base64_payload= base64_url_encode(jwt_payload);
    ops->update((uint8_t*)base64_header.c_str(), base64_header.size());
    ops->update((uint8_t*)".", 1);
    ops->update((uint8_t*)base64_payload.c_str(), base64_payload.size());
    sign.resize(ops->signature_length());
    Botan::secure_vector<uint8_t> sign_ = ops->sign(rnd);
    memcpy((char*)sign.c_str(), sign_.data(), sign_.size());

    std::string ret = base64_url_encode(sign);
    ret.insert(0, ".");
    ret.insert(0, base64_payload);
    ret.insert(0, ".");
    ret.insert(0, base64_header);
    ret.append(";info=<");
    ret.append(x5u_url);
    ret.append(">;alg=ES256;ppt=shaken");

    return ret;
}

bool AmIdentity::verify(Botan::Public_Key* key, unsigned int expire)
{
    last_errcode = 0;
    last_errstr.clear();
    time_t t = time(0);
    if(t - created > expire) {
        last_errcode = ERR_EXPIRE_TIMEOUT;
        last_errstr = "Expired Timeout";
        return false;
    }

    std::unique_ptr<Botan::PK_Ops::Verification> ops = key->create_verification_op("EMSA1(SHA-256)", "");

    std::string base64_header = base64_url_encode(jwt_header);
    std::string base64_payload= base64_url_encode(jwt_payload);

    ops->update((uint8_t*)base64_header.c_str(), base64_header.size());
    ops->update((uint8_t*)".", 1);
    ops->update((uint8_t*)base64_payload.c_str(), base64_payload.size());

    bool ret = ops->is_valid_signature((uint8_t*)sign.c_str(), sign.size());
    if(!ret) {
        last_errstr = "Signature verification Failed";
        last_errcode = ERR_VERIFICATION;
    }
    return ret;
}

bool AmIdentity::verify_attestation(Botan::Public_Key* key, unsigned int expire, const IdentData& orig_, const IdentData& dest_)
{
    if(!verify(key, expire)) return false;

    //TODO: verify orig and dest identification data;

    return true;
}

bool AmIdentity::parse(const std::string& value)
{
    std::string value_base64;
    std::string info;
    size_t end = 0;
    passport_type ppt_id;

    last_errcode = 0;
    last_errstr.clear();

    if(value[0] == '.' && value[1] == '.') {
        last_errcode = ERR_COMPACT_FORM;
        last_errstr = "Compact form is not supported";
        return false;
    }

    size_t pos = value.find(';');
    if(pos == std::string::npos) {
        value_base64 = value;
    } else {
        value_base64.append(value.begin(), value.begin() + pos);
        info.append(value.begin() + pos+1, value.end());
    }

    //Header.Payload.Signature
    std::string data_base64[3];
    for(int i = 0; i < 2; i++) {
        pos = value_base64.find('.', end);
        if(pos == std::string::npos) {
            last_errcode = ERR_HEADER_VALUE;
            if(i < 1) {
                last_errstr = "Missed header/payload separator";
            } else {
                last_errstr = "Missed payload/signature separator";
            }
            return false;
        }
        data_base64[i].append(value_base64.begin() + end, value_base64.begin() + pos);
        end = pos + 1;
    }

    data_base64[2].append(value_base64.begin() + end, value_base64.end());

    if(data_base64[0].empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Empty base65url header";
        return false;
    }
    jwt_header = base64_url_decode(data_base64[0]);
    if(jwt_header.empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Empty header data after decoding. wrong base64url";
        return false;
    }

    if(data_base64[1].empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Empty base65url payload";
        return false;
    }
    jwt_payload = base64_url_decode(data_base64[1]);
    if(jwt_payload.empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Empty payload data after decoding. wrong base64url";
        return false;
    }

    if(data_base64[2].empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Empty base65url signature";
        return false;
    }
    sign = base64_url_decode(data_base64[2]);
    if(sign.empty()) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Empty signature data after decoding. wrong base64url";
    }

    if(!json2arg(jwt_header, header)) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Failed to parse JWT header JSON";
        return false;
    }

    if(!json2arg(jwt_payload, payload)) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Failed to parse JWT payload JSON";
        return false;
    }

    //process header
    if(!IdentityHeaderValidator.validate(header)) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Unexpected JWT header layout";
        return false;
    }

    try {
        AmArg &alg_arg = header[jwt_hdr_claim_alg],
              &x5u_arg = header[jwt_hdr_claim_x5u],
              &ppt_arg = header[jwt_hdr_claim_ppt],
              &type_arg = header[jwt_hdr_claim_typ];

        if(strcmp(alg_arg.asCStr(), alg_value_es256))
        {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr = "Unsupported alg. 'ES256' expected";
            return false;
        }

        if(strcmp(type_arg.asCStr(), typ_value_passport)) {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr = "Unsupported typ. 'passport' expected";
            return false;
        }

        if(0==strcmp(ppt_arg.asCStr(), ppt_value_shaken)) {
            ppt_id = ES256_PASSPORT_SHAKEN;
        } else if(0==strcmp(ppt_arg.asCStr(), ppt_value_div)) {
            ppt_id = ES256_PASSPORT_DIV;
        } else if(0==strcmp(ppt_arg.asCStr(), ppt_value_div_opt)) {
            ppt_id = ES256_PASSPORT_DIV_OPT;
        } else {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr = "Unsupported ppt. 'shaken' or 'div' expected";
            return false;
        }

        x5u_url = x5u_arg.asCStr();
    } catch(...) {
        last_errcode = ERR_HEADER_VALUE;
        last_errstr = "Malformed JWT header layout";
        return false;
    }

    //process payload
    switch(ppt_id) {
    case ES256_PASSPORT_SHAKEN:
        if(!IdentityShakenPayloadValidator.validate(payload)) {
            last_errcode = ERR_JWT_VALUE;
            last_errstr = "Unexpected JWT shaken payload layout";
            return false;
        }
        break;
    case ES256_PASSPORT_DIV:
        if(!IdentityDivPayloadValidator.validate(payload)) {
            last_errcode = ERR_JWT_VALUE;
            last_errstr = "Unexpected JWT div payload layout";
            return false;
        }
        break;
    case ES256_PASSPORT_DIV_OPT:
        if(!IdentityDivOptPayloadValidator.validate(payload)) {
            last_errcode = ERR_JWT_VALUE;
            last_errstr = "Unexpected JWT div-o payload layout";
            return false;
        }
        break;
    }

    try {

        if(ppt_id==ES256_PASSPORT_SHAKEN) {
            AmArg &attest_arg = payload[jwt_payload_claim_attest];
            if(strlen(attest_arg.asCStr()) != 1 ||
               attest_arg.asCStr()[0] < AT_A || attest_arg.asCStr()[0] > AT_C)
            {
                last_errcode = ERR_UNSUPPORTED;
                last_errstr = "Unknown attestation level";
                return false;
            }
            at = (enum ident_attest)(attest_arg.asCStr()[0]);
        }

        AmArg &dest_arg = payload[jwt_payload_claim_dest],
              &orig_arg = payload[jwt_payload_claim_orig],
              &iat_arg = payload[jwt_payload_claim_iat];

        created = iat_arg.asInt();

        add_ident_data(orig_arg, orig_data.tns, jwt_field_tn);
        add_ident_data(orig_arg, orig_data.uris, jwt_field_uri);
        add_ident_data(dest_arg, dest_data.tns, jwt_field_tn);
        add_ident_data(dest_arg, dest_data.uris, jwt_field_uri);

        //TODO: add field div_data and add tn/uri for it
    } catch(AmArg::TypeMismatchException& exc) {
        last_errcode = ERR_JWT_VALUE;
        last_errstr = "Malformed JWT payload layout";
        return false;
    }

    std::string x5u_info, alg_info, ppt_info;
    if(!info.empty()) {
        end = 0;
        do {
            pos = info.find(';', end);
            std::string param;

            if(pos != std::string::npos)
                param.append(info.begin() + end, info.begin() + pos);
            else
                param.append(info.begin() + end, info.end());

            end = pos + 1;
            pos = param.find('=');
            if(pos == std::string::npos) {
                DBG("incorrect parameter: %s. header: %s",
                      param.c_str(), value.data());
                continue;
            }

            std::string name(param.begin(), param.begin() + pos),
                        value(param.begin() + pos + 1, param.end());
            if(name == identity_hdr_param_info) {
                if(value[0] != '<' || value.back() != '>') {
                    last_errcode = ERR_HEADER_VALUE;
                    last_errstr = "Missed <> in info value";
                    DBG("incorrect info value: %s. header: %s",
                          value.c_str(), value.data());
                    continue;
                }
                x5u_info = trim(value, "\"<>");
            } else if(name == identity_hdr_param_alg) {
                alg_info = trim(value, "\"");
            } else if(name == identity_hdr_param_ppt) {
                ppt_info = trim(value, "\"");
            }
        } while(end);
    }

    if(!alg_info.empty() && alg_info != alg_value_es256) {
        last_errcode = ERR_UNSUPPORTED;
        last_errstr = "Unsupported identity header alg. 'ES256' expected";
        return false;
    }

    if(!ppt_info.empty()) {
        if(ppt_info == ppt_value_shaken) {
            if(ppt_id != ES256_PASSPORT_SHAKEN) {
                last_errcode = ERR_HEADER_VALUE;
                last_errstr = "JWT header 'ppt' claim and identity header param 'ppt' does not match";
                return false;
            }
        } else if(ppt_info == ppt_value_div) {
            if(ppt_id != ES256_PASSPORT_DIV) {
                last_errcode = ERR_HEADER_VALUE;
                last_errstr = "JWT header 'ppt' claim and identity header param 'ppt' does not match";
                return false;
            }
        } else if(ppt_info == ppt_value_div_opt) {
            if(ppt_id != ES256_PASSPORT_DIV_OPT) {
                last_errcode = ERR_HEADER_VALUE;
                last_errstr = "JWT header 'ppt' claim and identity header param 'ppt' does not match";
                return false;
            }
        } else {
            last_errcode = ERR_UNSUPPORTED;
            last_errstr = "Unsupported identity header ppt. 'shaken' or 'div' expected";
            return false;
        }
    }

    if(!x5u_info.empty() && x5u_info != x5u_url) {
        last_errcode = ERR_EQUAL_X5U;
        last_errstr = "JWT header 'x5u' claim and identity header param 'info' does not match";
        return false;
    }

    return true;
}

int AmIdentity::get_last_error(std::string& err)
{
    err = last_errstr;
    return last_errcode;
}
