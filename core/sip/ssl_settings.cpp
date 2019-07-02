#include "ssl_settings.h"
#include "sip/tls_trsp.h"
#include <botan/pkcs8.h>

settings::~settings()
{}

bool settings::checkCertificateAndKey(
    const char *interface_name,
    const char* interface_type,
    const char *role_name)
{
    try {
        if(!certificate_key.empty()) {
            DBG("checking %s interface %s %s %s certificate_key: %s",
                interface_type, interface_name,
                getProtocolName(),role_name,
                certificate_key.c_str());
            std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(certificate_key, *rand_generator_tls::instance()));
        }

        for(auto& cert : ca_list) {
                DBG("checking %s interface %s %s %s ca_list: %s",
                    interface_type, interface_name,
                    getProtocolName(),role_name,
                    cert.c_str());
                Botan::X509_Certificate cert_(cert);
        }

        if(!certificate.empty()) {
            DBG("checking %s interface %s %s %s certificate: %s",
                interface_type, interface_name,
                getProtocolName(),role_name,
                certificate.c_str());
            Botan::X509_Certificate certificate_(certificate);
        }

    } catch(const Botan::Exception& exc) {
        ERROR("Botan Error: invalid secure options %s", exc.what());
        return false;
    }
    return true;
}

const char *tls_settings::getProtocolName()
{
    return "tls";
}

const char *dtls_settings::getProtocolName()
{
    return "dtls";
}
