#include "HashCalculation.h"
#include "UACAuth.h"
#include <botan/internal/sha2_32.h>
#include <botan/internal/md5.h>
#include <botan/hex.h>

string HashCalculation::algorithmName() const
{
    return name;
}

unsigned int HashCalculation::getHashLength() const
{
    return output_l;
}

unsigned int HashCalculation::getHashHexLength() const
{
    return getHashLength() * 2;
}

string HashCalculation::calcNonce(const string &nonce_secret) const
{
    string result;
    string hash;

    time_t now = time(nullptr);
    result     = int2hex(now, true);

    auto hash_func = createFunc();
    hash_func->clear();
    hash_func->update(result);
    hash_func->update(nonce_secret);
    auto RespHash = hash_func->final();
    hash          = Botan::hex_encode(RespHash.data(), RespHash.size(), false);

    return result + hash;
}

nonce_check_result_t HashCalculation::checkNonce(const string &nonce, const string &nonce_secret,
                                                 unsigned int nonce_expire) const
{
    string hash;

#define INT_HEX_LEN int(2 * sizeof(int))

    if (nonce.size() != INT_HEX_LEN + getHashHexLength()) {
        DBG("wrong nonce length (expected %u, got %zd)", INT_HEX_LEN + getHashHexLength(), nonce.size());
        return NCR_WRONG;
    }

    unsigned int nonce_time = 0;
    if (hex2int(std::string(nonce.c_str(), INT_HEX_LEN), nonce_time)) {
        DBG("wrong nonce value(error hex to int conversion)");
        return NCR_WRONG;
    }
    nonce_time += nonce_expire;
    time_t now = time(nullptr);
    if (nonce_time < now) {
        DBG("wrong nonce value(nonce expired)");
        return NCR_EXPIRED;
    }

    auto hash_func = createFunc();
    hash_func->clear();
    hash_func->update(nonce.substr(0, INT_HEX_LEN));
    hash_func->update(nonce_secret);
    auto RespHash = hash_func->final();
    hash          = Botan::hex_encode(RespHash.data(), RespHash.size(), false);

    return UACAuth::tc_isequal(hash.c_str(), &nonce[INT_HEX_LEN], getHashHexLength()) ? NCR_OK : NCR_WRONG;

#undef INT_HEX_LEN
}

/*
 * calculate H(A1)
 */
void HashCalculation::uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential,
                                   std::string cnonce, string &sess_key) const
{
    if (nullptr == _credential)
        return;

    auto hash_func = createFunc();
    hash_func->clear();
    hash_func->update(_credential->user);
    hash_func->update(':');
    hash_func->update(challenge.realm);
    hash_func->update(':');
    hash_func->update(_credential->pwd);
    auto HA1 = hash_func->final();

    // MD5sess ...not supported
    // 	if ( flags & AUTHENTICATE_MD5SESS )
    // 	  {
    // 		MD5Init(&Md5Ctx);
    // 		MD5Update(&Md5Ctx, HA1, HASHLEN);
    // 		MD5Update(&Md5Ctx, ":", 1);
    // 		MD5Update(&Md5Ctx, challenge.nonce.c_str(), challenge.nonce.length());
    // 		MD5Update(&Md5Ctx, ":", 1);
    // 		MD5Update(&Md5Ctx, cnonce.c_str(), cnonce.length());
    // 		MD5Final(HA1, &Md5Ctx);
    // 	  };
    sess_key = Botan::hex_encode(HA1.data(), HA1.size(), false);
}

/*
 * calculate H(A2)
 */
void HashCalculation::uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                                   string &HA2Hex) const
{
    auto hash_func = createFunc();
    hash_func->clear();
    hash_func->update(method);
    hash_func->update(':');
    hash_func->update(uri);

    if (!hentity.empty()) {
        hash_func->update(':');
        hash_func->update((unsigned char *)hentity.c_str(), getHashHexLength());
    }

    auto HA2 = hash_func->final();
    HA2Hex   = Botan::hex_encode(HA2.data(), HA2.size(), false);
}

/*
 * calculate H(body)
 */
void HashCalculation::uac_calc_hentity(const std::string &body, string &hentity) const
{
    auto hash_func = createFunc();
    hash_func->clear();
    hash_func->update(body);
    auto h  = hash_func->final();
    hentity = Botan::hex_encode(h.data(), h.size(), false);
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
void HashCalculation::uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                                        const std::string &cnonce, const string &qop_value,
                                        const std::string &nonce_count_str, string &response) const
{
    auto hash_func = createFunc();
    hash_func->clear();
    hash_func->update((unsigned char *)ha1.c_str(), getHashHexLength());
    hash_func->update(':');
    hash_func->update(challenge.nonce);
    hash_func->update(':');

    if (!qop_value.empty()) {
        hash_func->update(nonce_count_str);
        hash_func->update(':');
        hash_func->update(cnonce);
        hash_func->update(':');
        hash_func->update(qop_value);
        hash_func->update(':');
    }

    hash_func->update((unsigned char *)ha2.c_str(), getHashHexLength());
    auto RespHash = hash_func->final();
    response      = Botan::hex_encode(RespHash.data(), RespHash.size(), false);
}

MD5_Hash::MD5_Hash()
{
    Botan::MD5 md5;
    name     = md5.name();
    output_l = md5.output_length();
}

unique_ptr<Botan::HashFunction> MD5_Hash::createFunc() const
{
    return std::make_unique<Botan::MD5>();
}

SHA256_Hash::SHA256_Hash()
{
    Botan::SHA_256 sha256;
    name     = sha256.name();
    output_l = sha256.output_length();
}

unique_ptr<Botan::HashFunction> SHA256_Hash::createFunc() const
{
    return std::make_unique<Botan::SHA_256>();
}
