#ifndef AM_SRTP_CONNECTION_H
#define AM_SRTP_CONNECTION_H

#include "singleton.h"
#include "AmRtpConnection.h"

#include <netinet/in.h>
#include <srtp.h>
#include <memory>

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

class AmSrtpConnection : public AmStreamConnection
{
private:
    typedef std::vector<srtp_master_key_p> srtp_master_keys;
    unsigned char  c_key_s[SRTP_KEY_SIZE];
    unsigned char  c_key_r[SRTP_KEY_SIZE];
    bool b_init[2];
    srtp_profile_t srtp_profile;
    srtp_t srtp_s_session;
    srtp_t srtp_r_session;

    AmStreamConnection* s_stream;
public:
    AmSrtpConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port, AmStreamConnection::ConnectionType conn_type);
    ~AmSrtpConnection();

    void use_key(srtp_profile_t profile, unsigned char* key_s, unsigned int key_s_len, unsigned char* key_r, unsigned int key_r_len);

    static void base64_key(const std::string& key, unsigned char* key_s, unsigned int& key_s_len);
    static std::string gen_base64_key(srtp_profile_t profile);
    static std::string gen_base64(unsigned int key_s_len);

    void handleConnection(uint8_t * data, unsigned int size, struct sockaddr_storage * recv_addr, struct timeval recv_time) override;
};

#endif/*AM_SRTP_CONNECTION_H*/
