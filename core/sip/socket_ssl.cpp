#include "socket_ssl.h"

std::string toString(sockaddr_ssl::sig_method sig)
{
    switch(sig)
    {
    case sockaddr_ssl::SIG_UNDEFINED:
        return "";
    case sockaddr_ssl::SIG_RSA:
        return "RSA";
    case sockaddr_ssl::SIG_DH:
        return "DH";
    case sockaddr_ssl::SIG_ECDH:
        return "ECDH";
    case sockaddr_ssl::SIG_CECPQ1:
        return "CECPQ1";
    case sockaddr_ssl::SIG_PSK:
        return "PSK";
    case sockaddr_ssl::SIG_DHE_PSK:
        return "DHE_PSK";
    case sockaddr_ssl::SIG_ECDHE_PSK:
        return "ECDHE_PS";
    case sockaddr_ssl::SIG_SHA:
        return "SHA";
    };
    return "";
}

std::string toString(sockaddr_ssl::cipher_method cipher)
{
    switch(cipher)
    {
    case sockaddr_ssl::CIPHER_UNDEFINED:
        return "";
    case sockaddr_ssl::CIPHER_AES256_OCB12:
        return "AES-256/OCB(12)";
    case sockaddr_ssl::CIPHER_AES128_OCB12:
        return "AES-128/OCB(12)";
    case sockaddr_ssl::CIPHER_ChaCha20Poly1305:
        return "ChaCha20Poly1305";
    case sockaddr_ssl::CIPHER_AES256_GCM:
        return "AES-256/GCM";
    case sockaddr_ssl::CIPHER_AES128_GCM:
        return "AES-128/GCM";
    case sockaddr_ssl::CIPHER_AES256_CCM:
        return "AES-256/CCM";
    case sockaddr_ssl::CIPHER_AES128_CCM:
        return "AES-128/CCM";
    case sockaddr_ssl::CIPHER_AES256_CCM8:
        return "AES-256/CCM(8)";
    case sockaddr_ssl::CIPHER_AES128_CCM8:
        return "AES-128/CCM(8)";
    case sockaddr_ssl::CIPHER_Camellia256_GCM:
        return "Camellia-256/GCM";
    case sockaddr_ssl::CIPHER_Camellia128_GCM:
        return "Camellia-128/GCM";
    case sockaddr_ssl::CIPHER_ARIA256_GCM:
        return "ARIA-256/GCM";
    case sockaddr_ssl::CIPHER_ARIA128_GCM:
        return "ARIA-128/GCM";
    case sockaddr_ssl::CIPHER_AES256:
        return "AES-256";
    case sockaddr_ssl::CIPHER_AES128:
        return "AES-128";
    case sockaddr_ssl::CIPHER_Camellia256:
        return "Camellia-256";
    case sockaddr_ssl::CIPHER_Camellia128:
        return "Camellia-128";
    case sockaddr_ssl::CIPHER_SEED:
        return "SEED";
    case sockaddr_ssl::CIPHER_3DES:
        return "3DES";
    };
    return "";
}

std::string toString(sockaddr_ssl::mac_method mac)
{
    switch(mac)
    {
    case sockaddr_ssl::MAC_UNDEFINED:
        return "";
    case sockaddr_ssl:: MAC_AEAD:
        return "AEAD";
    case sockaddr_ssl:: MAC_SHA256:
        return "SHA-256";
    case sockaddr_ssl:: MAC_SHA384:
        return "SHA-384";
    case sockaddr_ssl:: MAC_SHA1:
        return "SHA-1";
    };
    return "";
}
