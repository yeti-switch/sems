#include "ssl_settings.h"
#include "sip/tls_trsp.h"
#include <botan/data_src.h>
#include <fstream>

settings::settings() {}

AtomicCounter &settings::initNotAfterCounter()
{
    certificate_not_after_counter = &stat_group(Gauge, "core", "certificate_not_after_timestamp").addAtomicCounter();
    return *certificate_not_after_counter;
}

void settings::load_certificates()
{
    std::vector<Botan::X509_Certificate> certs;
    Botan::DataSource_Stream             in(certificate_path);
    while (true) {
        try {
            certs.push_back(Botan::X509_Certificate(in));
        } catch (const Botan::Exception &) {
            break;
        }
    }

    if (certificate_not_after_counter)
        certificate_not_after_counter->set(certs[0].not_after().time_since_epoch());

    Botan::DataSource_Stream             stream(certificate_key_path);
    std::unique_ptr<Botan::Private_Key>  cert_key = Botan::PKCS8::load_key(stream);
    std::vector<Botan::X509_Certificate> calist;
    for (auto &ca : ca_path_list) {
        calist.emplace_back(ca);
    }

    AmLock l(mutex);
    certificates.swap(certs);
    certificate_key = Botan::PKCS8::copy_key(*cert_key.get());
    ca_list.swap(calist);
}

bool settings::checkCertificateAndKey(const char *interface_name, const char *interface_type, const char *role_name)
{
    try {
        if (!certificate_key_path.empty()) {
            DBG3("checking %s interface %s %s %s certificate_key: %s", interface_type, interface_name,
                 getProtocolName(), role_name, certificate_key_path.c_str());
            Botan::DataSource_Stream            stream(certificate_key_path);
            std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(stream));
        }

        for (auto &cert : ca_path_list) {
            DBG3("checking %s interface %s %s %s ca_list: %s", interface_type, interface_name, getProtocolName(),
                 role_name, cert.c_str());
            Botan::X509_Certificate cert_(cert);
        }

        if (!certificate_path.empty()) {
            DBG3("checking %s interface %s %s %s certificate: %s", interface_type, interface_name, getProtocolName(),
                 role_name, certificate_path.c_str());
            std::vector<Botan::X509_Certificate> certs;
            Botan::DataSource_Stream             in(certificate_path);
            while (true) {
                try {
                    certs.push_back(Botan::X509_Certificate(in));
                    auto &t = certs.back().not_after();
                    if (t.cmp(Botan::X509_Time(std::chrono::_V2::system_clock::now())) < 0)
                        throw Botan::Exception("certificate expired");
                } catch (const Botan::Exception &ex) {
                    if (certs.empty())
                        throw Botan::Exception("certificates is absent");
                    break;
                }
            }
        }

    } catch (const Botan::Exception &exc) {
        ERROR("Botan Error: invalid secure options %s", exc.what());
        return false;
    }
    return true;
}

std::vector<Botan::X509_Certificate> settings::getCertificateCopy()
{
    AmLock l(mutex);
    return certificates;
}

std::string settings::getCertificateFingerprint(const string &hash_name)
{
    AmLock l(mutex);
    if (certificates.empty()) {
        return "";
    }
    return certificates[0].fingerprint(hash_name);
}

std::unique_ptr<Botan::Private_Key> settings::getCertificateKeyCopy()
{
    AmLock l(mutex);
    return Botan::PKCS8::copy_key(*certificate_key.get());
}

vector<Botan::Certificate_Store *> settings::getCertificateAuthorityCopy()
{
    AmLock                             l(mutex);
    vector<Botan::Certificate_Store *> ca;
    for (auto &cert : ca_list) {
        ca.push_back(new Botan::Certificate_Store_In_Memory(cert));
    }
    return ca;
}

#define getSupportedProtocols(class_setting)                                                                           \
    std::vector<std::string> class_setting::getSupportedProtocols()                                                    \
    {                                                                                                                  \
        std::vector<std::string> supp_proto;                                                                           \
        for (auto &proto : protocols) {                                                                                \
            supp_proto.push_back(protocolToStr(proto));                                                                \
        }                                                                                                              \
        return supp_proto;                                                                                             \
    }

getSupportedProtocols(tls_settings);
getSupportedProtocols(dtls_settings);

#undef getSupportedProtocols

const char *tls_settings::getProtocolName()
{
    return "tls";
}

const char *dtls_settings::getProtocolName()
{
    return "dtls";
}
