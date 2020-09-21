#include <netinet/in.h>
#include <string>
#include "transport.h"

struct sockaddr_ssl
{
    union {
        sockaddr_in in;
        sockaddr_in6 in6;
    } addr;
    trsp_socket::socket_transport trsp;
    bool ssl_marker;
    enum sig_method {
        SIG_UNDEFINED = 0,
        SIG_SHA,
        SIG_ECDHE_PSK,
        SIG_DHE_PSK,
        SIG_PSK,
        SIG_CECPQ1,
        SIG_ECDH,
        SIG_DH,
        SIG_RSA
    } sig;
    enum cipher_method {
        CIPHER_UNDEFINED = 0,
        CIPHER_AES256_OCB12,
        CIPHER_AES128_OCB12,
        CIPHER_ChaCha20Poly1305,
        CIPHER_AES256_GCM,
        CIPHER_AES128_GCM,
        CIPHER_AES256_CCM,
        CIPHER_AES128_CCM,
        CIPHER_AES256_CCM8,
        CIPHER_AES128_CCM8,
        CIPHER_Camellia256_GCM,
        CIPHER_Camellia128_GCM,
        CIPHER_ARIA256_GCM,
        CIPHER_ARIA128_GCM,
        CIPHER_AES256,
        CIPHER_AES128,
        CIPHER_Camellia256,
        CIPHER_Camellia128,
        CIPHER_SEED,
        CIPHER_3DES
    } cipher;
    enum mac_method {
        MAC_UNDEFINED = 0,
        MAC_AEAD,
        MAC_SHA256,
        MAC_SHA384,
        MAC_SHA1
    } mac;
};

std::string toString(sockaddr_ssl::sig_method sig);
std::string toString(sockaddr_ssl::cipher_method cipher);
std::string toString(sockaddr_ssl::mac_method mac);
