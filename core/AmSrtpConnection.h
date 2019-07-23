#ifndef AM_SRTP_CONNECTION_H
#define AM_SRTP_CONNECTION_H

#include "sip/ssl_settings.h"
#include "singleton.h"

#include <AmDtlsConnection.h>
#include <netinet/in.h>

#include <srtp.h>

#include <memory>
using std::auto_ptr;

class AmRtpStream;
class msg_logger;

#define SRTP_KEY_SIZE 30

#define SRTP_PACKET_PARSE_ERROR -1
#define SRTP_PACKET_PARSE_OK 0
#define SRTP_PACKET_PARSE_RTP 1

class srtp_master_key_p
{
public:
    srtp_master_key_p(srtp_master_key_t key)
        : master_key(key){}
    ~srtp_master_key_p();

    operator srtp_master_key_t*()
    {
        return &master_key;
    }

    srtp_master_key_t master_key;
};

class AmSrtpConnection : public Botan::TLS::Callbacks
{
public:
    enum RTP_mode
    {
        RTP_DEFAULT,
        DTLS_SRTP_SERVER,
        DTLS_SRTP_CLIENT,
        SRTP_EXTERNAL_KEY
    };
private:
    typedef std::vector<srtp_master_key_p> srtp_master_keys;
    RTP_mode       rtp_mode;
    unsigned char  c_key_s[SRTP_KEY_SIZE];
    unsigned char  c_key_r[SRTP_KEY_SIZE];
    bool b_init[2];
    srtp_profile_t srtp_profile;
    srtp_fingerprint_p fingerprint;
    srtp_t srtp_s_session;
    srtp_t srtp_r_session;

    Botan::TLS::Channel* dtls_channel;
    AmRtpStream* rtp_stream;
    auto_ptr<dtls_conf> dtls_settings;
    bool b_srtcp;
    struct sockaddr_storage l_saddr;
protected:
    bool isRtpPacket(uint8_t* data, unsigned int size);
public:
    AmSrtpConnection(AmRtpStream* stream, bool srtcp);
    ~AmSrtpConnection();

    void setLocalAddr(struct sockaddr_storage& saddr);

    RTP_mode get_rtp_mode() { return rtp_mode; }
    void create_dtls();
    void use_dtls(dtls_client_settings* settings, const srtp_fingerprint_p& fingerprint);
    void use_dtls(dtls_server_settings* settings, const srtp_fingerprint_p& fingerprint);
    void use_key(srtp_profile_t profile, unsigned char* key_s, unsigned int key_s_len, unsigned char* key_r, unsigned int key_r_len);

    static void base64_key(const std::string& key, unsigned char* key_s, unsigned int& key_s_len);
    static std::string gen_base64_key(srtp_profile_t profile);
    static std::string gen_base64(unsigned int key_s_len);
    static srtp_fingerprint_p gen_fingerprint(class dtls_settings* settings);

    int on_data_recv(uint8_t* data, unsigned int* size, bool rtcp);
    bool on_data_send(uint8_t* data, unsigned int* size, bool rtcp);

    void tls_emit_data(const uint8_t data[], size_t size);
    void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size);
    void tls_alert(Botan::TLS::Alert alert);
    bool tls_session_established(const Botan::TLS::Session& session);
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
                                const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                Botan::Usage_Type usage,
                                const std::string& hostname,
                                const Botan::TLS::Policy& policy);
    virtual void tls_session_activated();

    void logReceivedPacket(msg_logger* logger, uint8_t* data, unsigned int size, struct sockaddr_storage* addr);
};

#endif/*AM_SRTP_CONNECTION_H*/
