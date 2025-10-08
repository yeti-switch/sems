#ifndef HASH_CALCULATION_H
#define HASH_CALCULATION_H

#include <string>
using std::string;

class UACAuthCred;
struct UACAuthDigestChallenge;

enum nonce_check_result_t { NCR_EXPIRED, NCR_WRONG, NCR_OK };

struct HashCalculation {
    virtual ~HashCalculation() {}
    virtual unsigned int         getHashLength()                                    = 0;
    virtual string               algorithmName()                                    = 0;
    virtual string               calcNonce(const string &nonce_secret)              = 0;
    virtual nonce_check_result_t checkNonce(const string &nonce, const string &nonce_secret,
                                            unsigned int nonce_expire)              = 0;
    virtual void                 uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential,
                                              std::string cnonce, string &sess_key) = 0;

    virtual void uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                              string &HA2Hex) = 0;

    virtual void uac_calc_hentity(const std::string &body, string &hentity) = 0;

    virtual void uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                                   const std::string &cnonce, const string &qop_value,
                                   const std::string &nonce_count_str, string &response) = 0;
};

class MD5_Hash : public HashCalculation {
  public:
    unsigned int         getHashLength() override;
    string               algorithmName() override;
    string               calcNonce(const string &nonce_secret) override;
    nonce_check_result_t checkNonce(const string &nonce, const string &nonce_secret,
                                    unsigned int nonce_expire) override;
    void uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential, std::string cnonce,
                      string &sess_key) override;

    void uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                      string &HA2Hex) override;

    void uac_calc_hentity(const std::string &body, string &hentity) override;

    void uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                           const std::string &cnonce, const string &qop_value, const std::string &nonce_count_str,
                           string &response) override;
};

class SHA256_Hash : public HashCalculation {
  public:
    unsigned int         getHashLength() override;
    string               algorithmName() override;
    string               calcNonce(const string &nonce_secret) override;
    nonce_check_result_t checkNonce(const string &nonce, const string &nonce_secret,
                                    unsigned int nonce_expire) override;
    void uac_calc_HA1(const UACAuthDigestChallenge &challenge, const UACAuthCred *_credential, std::string cnonce,
                      string &sess_key) override;

    void uac_calc_HA2(const std::string &method, const std::string &uri, const string &hentity,
                      string &HA2Hex) override;

    void uac_calc_hentity(const std::string &body, string &hentity) override;

    void uac_calc_response(const string &ha1, const string &ha2, const UACAuthDigestChallenge &challenge,
                           const std::string &cnonce, const string &qop_value, const std::string &nonce_count_str,
                           string &response) override;
};

#endif /*HASH_CALCULATION_H*/
