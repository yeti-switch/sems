#ifndef AM_IDENTITY_H
#define AM_IDENTITY_H

#include <string>
#include <vector>
#include <botan/pk_keys.h>

/*
 * for generation private key and certificate
 * openssl genpkey -out test.key.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
 * openssl req -new -x509 -key test.key.pem -out test.pem -days 730 -subj "/C=UA/O=root/CN=sjwttest"
 */


struct IdentData
{
    std::vector<std::string> uries;
    std::vector<std::string> tns;
};

class AmIdentity
{
public:
    AmIdentity();
    ~AmIdentity();

    enum ident_attest {
        AT_A = 'A',
        AT_B = 'B',
        AT_C = 'C'
    };

    bool verify_attestation(Botan::Public_Key* key, unsigned int expire,
               const IdentData& orig, const IdentData& dest);

    bool verify(Botan::Public_Key* key, unsigned int expire);

    std::string generate(Botan::Private_Key* key);

    bool parse(const std::string& value);

    void set_x5url(const std::string& val);
    std::string& get_x5url();

    void set_attestation(ident_attest val);
    ident_attest get_attestation();

    std::string& get_origid();
    time_t get_created();

    void add_origtn(const std::string& origtn);
    void add_origurl(const std::string& origurl);
    IdentData& get_origtn();

    void add_desttn(const std::string& desttn);
    void add_desturl(const std::string& desturl);
    IdentData& get_dest();
private:
    std::string sign;
    std::string x5url;
    IdentData orig_data;
    IdentData dest_data;
    ident_attest at;
    time_t created;
    std::string orig_id;

    std::string orig_header;
    std::string orig_payload;
};

#endif/*AM_IDENTITY_H*/
