#include "ssl_settings.h"
#include "sip/tls_trsp.h"
#include <botan/data_src.h>
#include <fstream>

template<>
Botan::Private_Key* binary_data<Botan::Private_Key>::get()
{
    AmLock lock(mutex);
    return Botan::PKCS8::copy_key(*data).release();
}

template<>
uint64_t binary_data<Botan::X509_Certificate>::not_after()
{
    AmLock lock(mutex);
    return data->not_after().time_since_epoch();
}

void settings::load_certificates()
{
    certificate.set(new Botan::X509_Certificate(certificate_path));
    Botan::DataSource_Stream stream(certificate_key_path);
    certificate_key.set(Botan::PKCS8::load_key(stream).release());
    {
        AmLock lock(ca_list);
        ca_list.clear();
        for(auto& ca : ca_path_list) {
            std::vector<Botan::X509_Certificate>& list = ca_list;
            list.push_back(Botan::X509_Certificate(ca));
        }
    }

    crt_not_after->set(certificate.not_after());
}

bool settings::checkCertificateAndKey(
    const char *interface_name,
    const char* interface_type,
    const char *role_name)
{
    try {
        if(!certificate_key_path.empty()) {
            DBG("checking %s interface %s %s %s certificate_key: %s",
                interface_type, interface_name,
                getProtocolName(),role_name,
                certificate_key_path.c_str());
            Botan::DataSource_Stream stream(certificate_key_path);
            std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(stream));
        }

        for(auto& cert : ca_path_list) {
                DBG("checking %s interface %s %s %s ca_list: %s",
                    interface_type, interface_name,
                    getProtocolName(),role_name,
                    cert.c_str());
                Botan::X509_Certificate cert_(cert);
        }

        if(!certificate_path.empty()) {
            DBG("checking %s interface %s %s %s certificate: %s",
                interface_type, interface_name,
                getProtocolName(),role_name,
                certificate_path.c_str());
            Botan::X509_Certificate certificate_(certificate_path);
        }

    } catch(const Botan::Exception& exc) {
        ERROR("Botan Error: invalid secure options %s", exc.what());
        return false;
    }
    return true;
}

void settings::dump(const std::string& prefix)
{
    std::string ca_list("{");
    for(auto& ca : ca_path_list) {
        ca_list.append(ca);
        ca_list.push_back(',');
    }
    ca_list.pop_back();
    ca_list.push_back('}');

    std::string protocols;
    auto supp_proto = getSupportedProtocols();
    for(auto& protocol : supp_proto) {
        protocols.append(protocol);
        protocols.push_back(',');
    }
    protocols.pop_back();
    protocols.push_back('}');
    INFO("\t\tclient: certificate='%s'"
        ";key='%s';ca='%s'"
        ";supported_protocols='%s'",
        certificate_path.c_str(),
        certificate_key_path.c_str(),
        ca_list.c_str(), protocols.c_str());
}

#define getSupportedProtocols(class_setting) \
std::vector<std::string> class_setting::getSupportedProtocols() \
{ \
    std::vector<std::string> supp_proto; \
    for(auto& proto : protocols) { \
        supp_proto.push_back(protocolToStr(proto)); \
    } \
    return supp_proto; \
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
