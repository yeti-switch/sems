#include "HashCalculation.h"
#include "UACAuth.h"
#include "md5.h"
#include "sha-256.h"

inline void w_MD5Update(MD5_CTX *ctx, const string &s)
{
    MD5Update(ctx, (const unsigned char *)s.data(), s.length());
}

#define MD5HASHHEXLEN 32
#define MD5HASHLEN    16

unsigned int MD5_Hash::getHashLength() const
{
    return MD5HASHLEN;
}

string MD5_Hash::algorithmName() const
{
    return "MD5";
}

/** calculate nonce: time-stamp H(time-stamp private-key) */
string MD5_Hash::calcNonce(const string &nonce_secret)
{
    string        result;
    string        hash;
    MD5_CTX       Md5Ctx;
    unsigned char RespHash[MD5HASHLEN];

    time_t now = time(nullptr);
    result     = int2hex(now, true);

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, result);
    w_MD5Update(&Md5Ctx, nonce_secret);
    MD5Final(RespHash, &Md5Ctx);
    cvt_hex(string_view((char *)RespHash, MD5HASHLEN), hash);

    return result + hash.c_str();
}

nonce_check_result_t MD5_Hash::checkNonce(const string &nonce, const string &nonce_secret,
                                          unsigned int nonce_expire) const
{
    string        hash;
    MD5_CTX       Md5Ctx;
    unsigned char RespHash[MD5HASHLEN];

#define INT_HEX_LEN int(2 * sizeof(int))

    if (nonce.size() != INT_HEX_LEN + MD5HASHHEXLEN) {
        DBG("wrong nonce length (expected %u, got %zd)", INT_HEX_LEN + MD5HASHHEXLEN, nonce.size());
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

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, nonce.substr(0, INT_HEX_LEN));
    w_MD5Update(&Md5Ctx, nonce_secret);
    MD5Final(RespHash, &Md5Ctx);
    cvt_hex(string_view((char *)RespHash, MD5HASHLEN), hash);

    return UACAuth::tc_isequal(hash.c_str(), &nonce[INT_HEX_LEN], MD5HASHHEXLEN) ? NCR_OK : NCR_WRONG;

#undef INT_HEX_LEN
}

/*
 * calculate H(A1)
 */
void MD5_Hash::uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential, std::string cnonce,
                            string &sess_key) const
{
    if (nullptr == _credential)
        return;

    MD5_CTX       Md5Ctx;
    unsigned char HA1[MD5HASHLEN];

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, _credential->user);
    w_MD5Update(&Md5Ctx, ":");
    // use realm from challenge
    w_MD5Update(&Md5Ctx, challenge.realm);
    w_MD5Update(&Md5Ctx, ":");
    w_MD5Update(&Md5Ctx, _credential->pwd);
    MD5Final(HA1, &Md5Ctx);

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
    cvt_hex(string_view((char *)HA1, MD5HASHLEN), sess_key);
}

/*
 * calculate H(A2)
 */
void MD5_Hash::uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                            string &HA2Hex) const
{
    static unsigned char hc[1] = { ':' };
    MD5_CTX              Md5Ctx;
    unsigned char        HA2[MD5HASHLEN];

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, method);
    MD5Update(&Md5Ctx, hc, 1);
    w_MD5Update(&Md5Ctx, uri);

    if (!hentity.empty()) {
        MD5Update(&Md5Ctx, hc, 1);
        MD5Update(&Md5Ctx, (unsigned char *)hentity.c_str(), MD5HASHHEXLEN);
    }

    MD5Final(HA2, &Md5Ctx);
    cvt_hex(string_view((char *)HA2, MD5HASHLEN), HA2Hex);
}

/*
 * calculate H(body)
 */
void MD5_Hash::uac_calc_hentity(const std::string &body, string &hentity) const
{
    MD5_CTX       Md5Ctx;
    unsigned char h[MD5HASHLEN];

    MD5Init(&Md5Ctx);
    w_MD5Update(&Md5Ctx, body);
    MD5Final(h, &Md5Ctx);
    cvt_hex(string_view((char *)h, MD5HASHLEN), hentity);
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
void MD5_Hash::uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                                 const std::string &cnonce, const string &qop_value, const std::string &nonce_count_str,
                                 string &response) const
{
    static unsigned char hc[1] = { ':' };
    MD5_CTX              Md5Ctx;
    unsigned char        RespHash[MD5HASHLEN];

    MD5Init(&Md5Ctx);
    MD5Update(&Md5Ctx, (unsigned char *)ha1.c_str(), MD5HASHHEXLEN);
    MD5Update(&Md5Ctx, hc, 1);
    w_MD5Update(&Md5Ctx, challenge.nonce);
    MD5Update(&Md5Ctx, hc, 1);


    if (!qop_value.empty()) {
        w_MD5Update(&Md5Ctx, nonce_count_str);
        MD5Update(&Md5Ctx, hc, 1);
        w_MD5Update(&Md5Ctx, cnonce);
        MD5Update(&Md5Ctx, hc, 1);
        w_MD5Update(&Md5Ctx, qop_value);
        MD5Update(&Md5Ctx, hc, 1);
    }

    MD5Update(&Md5Ctx, (unsigned char *)ha2.c_str(), MD5HASHHEXLEN);
    MD5Final(RespHash, &Md5Ctx);
    cvt_hex(string_view((char *)RespHash, MD5HASHLEN), response);
}

inline void w_SHA256Update(SHA256_CTX *ctx, const string &s)
{
    SHA256_Update(ctx, (const unsigned char *)s.data(), s.length());
}

#define SHA256HASHHEXLEN 64
#define SHA256HASHLEN    32

unsigned int SHA256_Hash::getHashLength() const
{
    return SHA256HASHLEN;
}

string SHA256_Hash::algorithmName() const
{
    return "SHA-256";
}

/** calculate nonce: time-stamp H(time-stamp private-key) */
string SHA256_Hash::calcNonce(const string &nonce_secret)
{
    string        result;
    string        hash;
    SHA256_CTX    Sha256Ctx;
    unsigned char RespHash[SHA256HASHLEN];

    time_t now = time(nullptr);
    result     = int2hex(now, true);

    SHA256_Init(&Sha256Ctx);
    w_SHA256Update(&Sha256Ctx, result);
    w_SHA256Update(&Sha256Ctx, nonce_secret);
    SHA256_Final(&Sha256Ctx, RespHash);
    cvt_hex(string_view((char *)RespHash, SHA256HASHLEN), hash);

    return result + hash;
}

nonce_check_result_t SHA256_Hash::checkNonce(const string &nonce, const string &nonce_secret,
                                             unsigned int nonce_expire) const
{
    string        hash;
    SHA256_CTX    Sha256Ctx;
    unsigned char RespHash[SHA256HASHLEN];

#define INT_HEX_LEN int(2 * sizeof(int))

    if (nonce.size() != INT_HEX_LEN + SHA256HASHHEXLEN) {
        DBG("wrong nonce length (expected %u, got %zd)", INT_HEX_LEN + SHA256HASHHEXLEN, nonce.size());
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

    SHA256_Init(&Sha256Ctx);
    w_SHA256Update(&Sha256Ctx, nonce.substr(0, INT_HEX_LEN));
    w_SHA256Update(&Sha256Ctx, nonce_secret);
    SHA256_Final(&Sha256Ctx, RespHash);
    cvt_hex(string_view((char *)RespHash, SHA256HASHLEN), hash);

    return UACAuth::tc_isequal(hash.c_str(), &nonce[INT_HEX_LEN], SHA256HASHHEXLEN) ? NCR_OK : NCR_WRONG;

#undef INT_HEX_LEN
}

/*
 * calculate H(A1)
 */
void SHA256_Hash::uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential,
                               std::string cnonce, string &sess_key) const
{
    if (nullptr == _credential)
        return;

    SHA256_CTX    Sha256Ctx;
    unsigned char HA1[SHA256HASHLEN];

    SHA256_Init(&Sha256Ctx);
    w_SHA256Update(&Sha256Ctx, _credential->user);
    w_SHA256Update(&Sha256Ctx, ":");
    // use realm from challenge
    w_SHA256Update(&Sha256Ctx, challenge.realm);
    w_SHA256Update(&Sha256Ctx, ":");
    w_SHA256Update(&Sha256Ctx, _credential->pwd);
    SHA256_Final(&Sha256Ctx, HA1);

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
    cvt_hex(string_view((char *)HA1, SHA256HASHLEN), sess_key);
}

/*
 * calculate H(A2)
 */
void SHA256_Hash::uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                               string &HA2Hex) const
{
    static unsigned char hc[1] = { ':' };
    SHA256_CTX           Sha256Ctx;
    unsigned char        HA2[SHA256HASHLEN];

    SHA256_Init(&Sha256Ctx);
    w_SHA256Update(&Sha256Ctx, method);
    SHA256_Update(&Sha256Ctx, hc, 1);
    w_SHA256Update(&Sha256Ctx, uri);

    if (!hentity.empty()) {
        SHA256_Update(&Sha256Ctx, hc, 1);
        SHA256_Update(&Sha256Ctx, (unsigned char *)hentity.c_str(), SHA256HASHLEN);
    }

    SHA256_Final(&Sha256Ctx, HA2);
    cvt_hex(string_view((char *)HA2, SHA256HASHLEN), HA2Hex);
}

/*
 * calculate H(body)
 */
void SHA256_Hash::uac_calc_hentity(const std::string &body, string &hentity) const
{
    SHA256_CTX    Sha256Ctx;
    unsigned char h[SHA256HASHLEN];

    SHA256_Init(&Sha256Ctx);
    w_SHA256Update(&Sha256Ctx, body);
    SHA256_Final(&Sha256Ctx, h);
    cvt_hex(string_view((char *)h, SHA256HASHLEN), hentity);
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
void SHA256_Hash::uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                                    const std::string &cnonce, const string &qop_value,
                                    const std::string &nonce_count_str, string &response) const
{
    static unsigned char hc[1] = { ':' };
    SHA256_CTX           Sha256Ctx;
    unsigned char        RespHash[SHA256HASHLEN];

    SHA256_Init(&Sha256Ctx);
    SHA256_Update(&Sha256Ctx, (unsigned char *)ha1.c_str(), SHA256HASHHEXLEN);
    SHA256_Update(&Sha256Ctx, hc, 1);
    w_SHA256Update(&Sha256Ctx, challenge.nonce);
    SHA256_Update(&Sha256Ctx, hc, 1);


    if (!qop_value.empty()) {
        w_SHA256Update(&Sha256Ctx, nonce_count_str);
        SHA256_Update(&Sha256Ctx, hc, 1);
        w_SHA256Update(&Sha256Ctx, cnonce);
        SHA256_Update(&Sha256Ctx, hc, 1);
        w_SHA256Update(&Sha256Ctx, qop_value);
        SHA256_Update(&Sha256Ctx, hc, 1);
    }

    SHA256_Update(&Sha256Ctx, (unsigned char *)ha2.c_str(), MD5HASHHEXLEN);
    SHA256_Final(&Sha256Ctx, RespHash);
    cvt_hex(string_view((char *)RespHash, SHA256HASHLEN), response);
}
