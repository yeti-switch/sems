#ifndef HASH_CALCULATION_H
#define HASH_CALCULATION_H

#include <string>
using std::string;

class UACAuthCred;
struct UACAuthDigestChallenge;

enum nonce_check_result_t { NCR_EXPIRED, NCR_WRONG, NCR_OK };

struct HashCalculation {
    HashCalculation()                                   = default;
    HashCalculation(const HashCalculation &)            = delete;
    HashCalculation(HashCalculation &&)                 = delete;
    HashCalculation &operator=(const HashCalculation &) = delete;
    HashCalculation &operator=(HashCalculation &&)      = delete;

    virtual ~HashCalculation() {}
    virtual unsigned int         getHashLength() const                                    = 0;
    virtual string               algorithmName() const                                    = 0;
    virtual string               calcNonce(const string &nonce_secret)                    = 0;
    virtual nonce_check_result_t checkNonce(const string &nonce, const string &nonce_secret,
                                            unsigned int nonce_expire) const              = 0;
    virtual void                 uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential,
                                              std::string cnonce, string &sess_key) const = 0;

    virtual void uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                              string &HA2Hex) const = 0;

    virtual void uac_calc_hentity(const std::string &body, string &hentity) const = 0;

    virtual void uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                                   const std::string &cnonce, const string &qop_value,
                                   const std::string &nonce_count_str, string &response) const = 0;
};

class MD5_Hash : public HashCalculation {
  public:
    unsigned int         getHashLength() const override;
    string               algorithmName() const override;
    string               calcNonce(const string &nonce_secret) override;
    nonce_check_result_t checkNonce(const string &nonce, const string &nonce_secret,
                                    unsigned int nonce_expire) const override;
    void uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential, std::string cnonce,
                      string &sess_key) const override;

    void uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                      string &HA2Hex) const override;

    void uac_calc_hentity(const std::string &body, string &hentity) const override;

    void uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                           const std::string &cnonce, const string &qop_value, const std::string &nonce_count_str,
                           string &response) const override;
};

class SHA256_Hash : public HashCalculation {
  public:
    unsigned int         getHashLength() const override;
    string               algorithmName() const override;
    string               calcNonce(const string &nonce_secret) override;
    nonce_check_result_t checkNonce(const string &nonce, const string &nonce_secret,
                                    unsigned int nonce_expire) const override;
    void uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential, std::string cnonce,
                      string &sess_key) const override;

    void uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                      string &HA2Hex) const override;

    void uac_calc_hentity(const std::string &body, string &hentity) const override;

    void uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                           const std::string &cnonce, const string &qop_value, const std::string &nonce_count_str,
                           string &response) const override;
};

#endif /*HASH_CALCULATION_H*/
