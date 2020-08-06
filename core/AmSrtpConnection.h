#ifndef AM_SRTP_CONNECTION_H
#define AM_SRTP_CONNECTION_H

#include "singleton.h"
#include "AmRtpConnection.h"

#include <netinet/in.h>
#include <srtp.h>
#include <memory>

#define SRTP_KEY_SIZE 46

#define SRTP_PACKET_PARSE_ERROR -1
#define SRTP_PACKET_PARSE_OK 0
#define SRTP_PACKET_PARSE_RTP 1

class srtp_master_key_p
{
public:
    srtp_master_key_p(srtp_master_key_t key)
        : master_key(key){}
    ~srtp_master_key_p(){}

    operator srtp_master_key_t*()
    {
        return &master_key;
    }

    srtp_master_key_t master_key;
};

namespace srtp {
    int profile_get_master_key_length(srtp_profile_t profile);
    int profile_get_master_salt_length(srtp_profile_t profile);
#define crypto_policy_set_from_profile_for_rtcp crypto_policy_set_from_profile_for_rtp
    void crypto_policy_set_from_profile_for_rtp(srtp_crypto_policy_t* policy, srtp_profile_t profile);
}

class AmSrtpConnection : public AmStreamConnection
{
private:
    typedef std::vector<srtp_master_key_p> srtp_master_keys;
    unsigned char  c_key_tx[SRTP_KEY_SIZE];
    unsigned char  c_key_rx[SRTP_KEY_SIZE];

    bool rx_context_initialized;
    bool tx_context_initialized;
    bool connection_invalidated;
    uint32_t last_rx_ssrc_net_order;
    unsigned int rx_ssrc_changes_count;
    srtp_policy_t rx_policy;

    srtp_profile_t srtp_profile;
    srtp_t srtp_tx_session;
    srtp_t srtp_rx_session;

    AmStreamConnection* s_stream;

    int ensure_rx_stream_context(uint32_t ssrc_net_order);

public:
    AmSrtpConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, AmStreamConnection::ConnectionType conn_type);
    ~AmSrtpConnection();

    void use_key(srtp_profile_t profile,
                 const unsigned char* key_tx, size_t key_tx_len,
                 const unsigned char* key_rx, size_t key_rx_len);

    static void base64_key(const std::string& key,
                           unsigned char* key_s, unsigned int& key_s_len);

    static std::string gen_base64_key(srtp_profile_t profile);
    static std::string gen_base64(unsigned int key_s_len);

    void handleConnection(uint8_t * data, unsigned int size, struct sockaddr_storage * recv_addr, struct timeval recv_time) override;
    ssize_t send(AmRtpPacket * packet) override;
    void setPassiveMode(bool p) override;
};

#endif/*AM_SRTP_CONNECTION_H*/
