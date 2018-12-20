#include "ssl_settings.h"
#include "sip/tls_trsp.h"
#include <botan/pkcs8.h>

bool settings::checkCertificateAndKey()
{
    try {
        DBG("checking certificate and key of %s, settings", getProtocolSettings().c_str());
        std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(certificate_key, *rand_generator_tls::instance()));
        for(auto& cert : ca_list) {
            Botan::X509_Certificate cert_(cert);
        }
        Botan::X509_Certificate certificate_(certificate);
    } catch(const Botan::Exception& exc) {
        ERROR("Botan Error: invalid secure options %s", exc.what());
        return false;
    }
    return true;
}
