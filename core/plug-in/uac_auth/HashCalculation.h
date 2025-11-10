#ifndef HASH_CALCULATION_H
#define HASH_CALCULATION_H

#include <string>
#include <memory>
using std::string;
using std::unique_ptr;

#include <botan/hash.h>

class UACAuthCred;
struct UACAuthDigestChallenge;

enum nonce_check_result_t { NCR_EXPIRED, NCR_WRONG, NCR_OK };

class HashCalculation {
  protected:
    // std::map<int, std::unique_ptr<Botan::HashFunction>> hashes;
    string       name;
    unsigned int output_l;

    HashCalculation()                                   = default;
    HashCalculation(const HashCalculation &)            = delete;
    HashCalculation(HashCalculation &&)                 = delete;
    HashCalculation &operator=(const HashCalculation &) = delete;
    HashCalculation &operator=(HashCalculation &&)      = delete;

  public:
    virtual ~HashCalculation() {}

    unsigned int getHashLength() const;
    unsigned int getHashHexLength() const;
    string       algorithmName() const;

    string               calcNonce(const string &nonce_secret) const;
    nonce_check_result_t checkNonce(const string &nonce, const string &nonce_secret, unsigned int nonce_expire) const;

    void uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential, std::string cnonce,
                      string &sess_key) const;
    void uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity, string &HA2Hex) const;
    void uac_calc_hentity(const std::string &body, string &hentity) const;
    void uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                           const std::string &cnonce, const string &qop_value, const std::string &nonce_count_str,
                           string &response) const;

    virtual unique_ptr<Botan::HashFunction> createFunc() const = 0;
};

class MD5_Hash : public HashCalculation {
  public:
    MD5_Hash();
    unique_ptr<Botan::HashFunction> createFunc() const override;
};

class SHA256_Hash : public HashCalculation {
  public:
    SHA256_Hash();
    unique_ptr<Botan::HashFunction> createFunc() const override;
};

#endif /*HASH_CALCULATION_H*/
