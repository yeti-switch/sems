#pragma once

#include "AmRtpConnection.h"

#include <netinet/in.h>
#include <srtp/srtp.h>

#include <list>

#define SRTP_KEY_SIZE 46

#define SRTP_PACKET_PARSE_ERROR -1
#define SRTP_PACKET_PARSE_OK 0
#define SRTP_PACKET_PARSE_RTP 1

class srtp_master_keys
{
  private:
    vector<srtp_master_key_t *> srtp_data_ptrs;

  public:
    struct strp_mater_key_container
      : srtp_master_key_t
    {
        string key_data;
        uint32_t mki_id_data;

        strp_mater_key_container() = delete;
        strp_mater_key_container(const string &key_, uint32_t mki_id_, uint32_t mki_size_);
        bool operator==(const strp_mater_key_container& other) const;
    };

    using data_container = std::list<strp_mater_key_container>;

  private:
    data_container data;

  public:
    srtp_master_keys() = default;
    srtp_master_keys(const string& key, uint32_t mki_id = 0, uint32_t mki_size = 0);
    srtp_master_keys(srtp_master_keys &&) = delete;
    srtp_master_keys(srtp_master_keys const &) = delete;

    void operator=(srtp_master_keys const & other);
    void add(const string& key, uint32_t mki_id = 0, uint32_t mki_size = 0);

    srtp_master_key_t **get_ptrs() { return srtp_data_ptrs.data(); }
    const data_container& get_data() const { return data; }

    bool has_mki() const { return data.front().mki_size != 0; }
    string &get_first_key() { return data.front().key_data; }
    size_t size() const { return srtp_data_ptrs.size(); }

    bool operator==(const srtp_master_keys& other) const { return data == other.get_data(); }
};

namespace srtp {
    int profile_get_master_key_length(srtp_profile_t profile);
    int profile_get_master_salt_length(srtp_profile_t profile);
#define crypto_policy_set_from_profile_for_rtcp crypto_policy_set_from_profile_for_rtp
    void crypto_policy_set_from_profile_for_rtp(srtp_crypto_policy_t* policy, srtp_profile_t profile);
}

class AmSrtpConnection : public AmStreamConnection
{
    string c_tx_key;
    srtp_master_keys c_rx_keys;
    bool use_mki;

    bool rx_context_initialized;
    bool tx_context_initialized;
    bool connection_invalidated;
    uint32_t last_rx_ssrc_net_order;
    unsigned int rx_ssrc_changes_count;
    srtp_policy_t rx_policy;

    srtp_profile_t srtp_profile;
    srtp_t srtp_tx_session;
    AmMutex session_tx_mutex;
    srtp_t srtp_rx_session;
    AmMutex session_rx_mutex;

    AmStreamConnection* s_stream;

    void apply_rx_policy_keys();
    int ensure_rx_stream_context(uint32_t ssrc_net_order);
    int is_valid_keys(srtp_profile_t profile,
                      const string &tx_key,
                      const srtp_master_keys& rx_keys);

  public:
    AmSrtpConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, AmStreamConnection::ConnectionType conn_type);
    virtual ~AmSrtpConnection();

    void use_keys(srtp_profile_t profile,
                  const string &tx_key,
                  const srtp_master_keys& rx_keys);

    void update_keys(srtp_profile_t profile,
                    const string &tx_key,
                    const srtp_master_keys& rx_keys);

    static void base64_key(const std::string& key,
                           unsigned char* key_s, unsigned int& key_s_len);

    static std::string gen_base64_key(srtp_profile_t profile);
    static std::string gen_base64(unsigned int key_s_len);

    void handleConnection(uint8_t * data, unsigned int size, struct sockaddr_storage * recv_addr, struct timeval recv_time) override;
    void setRAddr(const string& addr, unsigned short port) override;
    ssize_t send(AmRtpPacket * packet) override;
    void setPassiveMode(bool p) override;
};
